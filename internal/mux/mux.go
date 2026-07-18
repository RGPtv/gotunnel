// Package mux provides a lightweight, pure-stdlib bidirectional stream
// multiplexer over a single net.Conn.
//
// Wire format
// ───────────
// Every frame has a 12-byte header followed by an optional payload:
//
//	 0       1       2       3
//	 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|    Version    |     Type      |            Flags              |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                           StreamID                            |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                            Length                             |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                    Payload (Length bytes)                     |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// Types: 0=Data  1=WindowUpdate  2=Ping  3=GoAway
// Flags: SYN=0x1  ACK=0x2  FIN=0x4  RST=0x8
//
// Flow control
// ────────────
// Each stream starts with a send window of initialWindow bytes.  The sender
// decrements the window before each DATA frame.  The receiver sends a
// WindowUpdate(delta) after consuming delta bytes in Read(), incrementing the
// remote send window.  Write blocks when the window reaches zero.
//
// Stream IDs
// ──────────
// The Client() side uses odd IDs (1, 3, 5 …); the Server() side uses even
// IDs (2, 4, 6 …).  In gotunnel the gateway calls Client / OpenStream and the
// agent calls Server / AcceptStream, matching the original yamux semantics.
package mux

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// ── Constants ─────────────────────────────────────────────────────────────────

const (
	protoVersion = 1
	headerLen    = 12

	typeData         byte = 0
	typeWindowUpdate byte = 1
	typePing         byte = 2
	typeGoAway       byte = 3

	flagSYN uint16 = 1 << 0
	flagACK uint16 = 1 << 1
	flagFIN uint16 = 1 << 2
	flagRST uint16 = 1 << 3

	// initialWindow is the per-stream send/receive window in bytes.
	initialWindow = 256 * 1024
	// maxFramePayload caps a single DATA frame to prevent monopolising the wire.
	maxFramePayload = 32 * 1024
	// maxSendWin caps the accumulated send window so a peer cannot grant
	// unbounded credit (flow-control bypass) or cause int64 overflow.
	maxSendWin = initialWindow * 64 // 16 MiB
	// defaultAcceptBacklog is the number of unaccepted streams buffered before
	// new SYNs are rejected with RST.
	defaultAcceptBacklog = 256
)

// ── Errors ────────────────────────────────────────────────────────────────────

var (
	ErrSessionClosed = errors.New("mux: session closed")
	ErrStreamClosed  = errors.New("mux: stream closed")
	ErrStreamReset   = errors.New("mux: stream reset by remote")
)

// ── Config ────────────────────────────────────────────────────────────────────

// Config holds tunable parameters.  nil is treated as DefaultConfig().
type Config struct {
	// KeepAliveInterval is how often a ping is sent on an idle session.
	// 0 disables keepalive.
	KeepAliveInterval time.Duration
	// KeepAliveTimeout is how long to wait for a pong before declaring
	// the session dead.
	KeepAliveTimeout time.Duration
	// AcceptBacklog is the maximum number of unaccepted inbound streams
	// queued before the remote receives RST.
	AcceptBacklog int
}

// DefaultConfig returns production-ready defaults.
func DefaultConfig() *Config {
	return &Config{
		KeepAliveInterval: 30 * time.Second,
		KeepAliveTimeout:  10 * time.Second,
		AcceptBacklog:     defaultAcceptBacklog,
	}
}

func applyDefaults(cfg *Config) *Config {
	if cfg == nil {
		return DefaultConfig()
	}
	out := *cfg
	if out.KeepAliveTimeout == 0 {
		out.KeepAliveTimeout = 10 * time.Second
	}
	if out.AcceptBacklog <= 0 {
		out.AcceptBacklog = defaultAcceptBacklog
	}
	return &out
}

// ── Frame helpers ─────────────────────────────────────────────────────────────

// writeFrameLocked writes a complete frame (header + optional payload) to w.
// The caller must hold the session writeMu.
func writeFrameLocked(w io.Writer, typ byte, flags uint16, streamID, length uint32, payload []byte) error {
	var hdr [headerLen]byte
	hdr[0] = protoVersion
	hdr[1] = typ
	binary.BigEndian.PutUint16(hdr[2:], flags)
	binary.BigEndian.PutUint32(hdr[4:], streamID)
	binary.BigEndian.PutUint32(hdr[8:], length)
	if err := writeAll(w, hdr[:]); err != nil {
		return err
	}
	if len(payload) > 0 {
		return writeAll(w, payload)
	}
	return nil
}

// writeAll handles writers that make partial progress without returning an
// error. Frame boundaries must never be truncated on the wire.
func writeAll(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if n > 0 {
			p = p[n:]
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

// ── Session ───────────────────────────────────────────────────────────────────

// Session multiplexes many logical Streams over one net.Conn.
type Session struct {
	conn     net.Conn
	isClient bool // true → odd stream IDs; false → even stream IDs

	// streams holds all live streams keyed by stream ID.
	streamsMu sync.RWMutex
	streams   map[uint32]*Stream

	// nextID is the next stream ID to use (increments by 2).
	nextID atomic.Uint32

	// writeMu serialises all frame writes to conn so goroutines do not
	// interleave partial frames.
	writeMu sync.Mutex

	// acceptCh queues inbound SYN streams for AcceptStream().
	acceptCh chan *Stream

	// closedCh is closed when the session terminates.
	closedCh  chan struct{}
	closeOnce sync.Once
	closeErr  atomic.Value // stores error

	numStreams atomic.Int32

	cfg *Config

	// keepalive
	pingSeq atomic.Uint32
	pongCh  chan uint32
}

// Client creates a session whose OpenStream calls use odd stream IDs.
// Equivalent to yamux.Client.
func Client(conn net.Conn, cfg *Config) (*Session, error) {
	return newSession(conn, true, cfg), nil
}

// Server creates a session that accepts streams opened by the remote Client.
// Equivalent to yamux.Server.
func Server(conn net.Conn, cfg *Config) (*Session, error) {
	return newSession(conn, false, cfg), nil
}

func newSession(conn net.Conn, isClient bool, cfg *Config) *Session {
	cfg = applyDefaults(cfg)
	s := &Session{
		conn:     conn,
		isClient: isClient,
		streams:  make(map[uint32]*Stream),
		acceptCh: make(chan *Stream, cfg.AcceptBacklog),
		closedCh: make(chan struct{}),
		cfg:      cfg,
		pongCh:   make(chan uint32, 8),
	}
	if isClient {
		s.nextID.Store(1) // odd IDs: 1, 3, 5, …
	} else {
		s.nextID.Store(2) // even IDs: 2, 4, 6, …
	}
	go s.readLoop()
	if cfg.KeepAliveInterval > 0 {
		go s.keepAliveLoop()
	}
	return s
}

// IsClosed reports whether the session has been closed.
func (s *Session) IsClosed() bool {
	select {
	case <-s.closedCh:
		return true
	default:
		return false
	}
}

// NumStreams returns the number of currently active streams.
func (s *Session) NumStreams() int { return int(s.numStreams.Load()) }

// Close terminates the session, sending GoAway and RST-ing all streams.
func (s *Session) Close() error { return s.closeWithError(ErrSessionClosed) }

func (s *Session) closeWithError(err error) error {
	s.closeOnce.Do(func() {
		if err == nil {
			err = ErrSessionClosed
		}
		s.closeErr.Store(err)
		close(s.closedCh)

		// RST every live stream while holding the lock only briefly.
		s.streamsMu.Lock()
		streams := make([]*Stream, 0, len(s.streams))
		for _, st := range s.streams {
			streams = append(streams, st)
		}
		s.streams = nil
		s.streamsMu.Unlock()

		for _, st := range streams {
			st.forceClose(err)
		}

		// Close the transport immediately. Waiting for writeMu here can
		// deadlock shutdown when another goroutine is blocked in a network
		// Write.
		_ = s.conn.Close()
	})
	return nil
}

func (s *Session) sessionErr() error {
	if v := s.closeErr.Load(); v != nil {
		return v.(error)
	}
	return ErrSessionClosed
}

// ── OpenStream ────────────────────────────────────────────────────────────────

// OpenStream opens a new logical stream.  It blocks until the remote
// acknowledges the SYN or the session closes.
func (s *Session) OpenStream() (net.Conn, error) {
	if s.IsClosed() {
		return nil, ErrSessionClosed
	}

	// Allocate a unique stream ID (stays odd or even depending on isClient).
	id := s.nextID.Add(2) - 2

	st := s.newStream(id)
	st.synAckCh = make(chan struct{})

	s.streamsMu.Lock()
	if s.streams == nil {
		s.streamsMu.Unlock()
		return nil, ErrSessionClosed
	}
	s.streams[id] = st
	s.streamsMu.Unlock()
	s.numStreams.Add(1)

	// Send SYN.
	if err := s.sendCtrl(id, typeData, flagSYN, 0); err != nil {
		s.removeStream(id)
		return nil, err
	}

	// Wait for ACK from the remote's readLoop.
	select {
	case <-st.synAckCh:
		// synAckCh is also closed by forceClose (RST path). Distinguish
		// a true ACK from a RST so callers get an error immediately.
		if st.rst.Load() {
			s.removeStream(id)
			return nil, st.streamErr()
		}
		return st, nil
	case <-s.closedCh:
		s.removeStream(id)
		return nil, s.sessionErr()
	}
}

// AcceptStream blocks until an inbound stream arrives or the session closes.
func (s *Session) AcceptStream() (net.Conn, error) {
	select {
	case st := <-s.acceptCh:
		return st, nil
	case <-s.closedCh:
		return nil, s.sessionErr()
	}
}

// ── Stream lifecycle helpers ──────────────────────────────────────────────────

func (s *Session) newStream(id uint32) *Stream {
	return &Stream{
		id:         id,
		sess:       s,
		recvNotify: make(chan struct{}, 1),
		sendNotify: make(chan struct{}, 1),
		localAddr:  s.conn.LocalAddr(),
		remoteAddr: s.conn.RemoteAddr(),
		sendWin:    initialWindow,
		recvWin:    initialWindow,
	}
}

func (s *Session) removeStream(id uint32) {
	s.streamsMu.Lock()
	_, had := s.streams[id]
	if s.streams != nil {
		delete(s.streams, id)
	}
	s.streamsMu.Unlock()
	if had {
		s.numStreams.Add(-1)
	}
}

// ── Write helpers (all acquire writeMu) ───────────────────────────────────────

func (s *Session) sendCtrl(streamID uint32, typ byte, flags uint16, length uint32) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return writeFrameLocked(s.conn, typ, flags, streamID, length, nil)
}

func (s *Session) sendData(streamID uint32, flags uint16, payload []byte) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return writeFrameLocked(s.conn, typeData, flags, streamID, uint32(len(payload)), payload)
}

func (s *Session) sendWindowUpdate(streamID uint32, delta uint32) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return writeFrameLocked(s.conn, typeWindowUpdate, 0, streamID, delta, nil)
}

// ── Read loop ─────────────────────────────────────────────────────────────────

func (s *Session) readLoop() {
	hdr := make([]byte, headerLen)
	for {
		if _, err := io.ReadFull(s.conn, hdr); err != nil {
			s.closeWithError(err)
			return
		}

		if hdr[0] != protoVersion {
			s.closeWithError(errors.New("mux: protocol version mismatch"))
			return
		}

		typ := hdr[1]
		flags := binary.BigEndian.Uint16(hdr[2:])
		streamID := binary.BigEndian.Uint32(hdr[4:])
		length := binary.BigEndian.Uint32(hdr[8:])

		// Only DATA frames carry payload bytes; WindowUpdate/Ping/GoAway
		// encode their value in the length field without a payload body.
		var payload []byte
		if typ == typeData && length > 0 {
			if length > maxFramePayload {
				s.closeWithError(errors.New("mux: oversized DATA frame"))
				return
			}
			payload = make([]byte, length)
			if _, err := io.ReadFull(s.conn, payload); err != nil {
				s.closeWithError(err)
				return
			}
		}

		if err := s.dispatch(typ, flags, streamID, length, payload); err != nil {
			s.closeWithError(err)
			return
		}
	}
}

func (s *Session) dispatch(typ byte, flags uint16, streamID uint32, length uint32, payload []byte) error {
	switch typ {
	case typePing:
		return s.handlePing(flags, length)
	case typeGoAway:
		s.closeWithError(ErrSessionClosed)
		return nil
	case typeData:
		return s.handleData(flags, streamID, payload)
	case typeWindowUpdate:
		return s.handleWindowUpdate(streamID, length)
	}
	return nil // unknown frame types are silently ignored
}

func (s *Session) handlePing(flags uint16, seq uint32) error {
	if flags&flagACK != 0 {
		// Pong received.
		select {
		case s.pongCh <- seq:
		default:
		}
		return nil
	}
	// Ping received – echo back immediately.
	return s.sendCtrl(0, typePing, flagACK, seq)
}

func (s *Session) handleData(flags uint16, streamID uint32, payload []byte) error {
	// ── SYN: new inbound stream ───────────────────────────────────────────────
	if flags&flagSYN != 0 {
		// A peer may only open streams using its own parity. Rejecting a
		// duplicate ID also prevents a malformed peer from replacing a live
		// stream in the session map.
		peerUsesOddIDs := !s.isClient
		if streamID == 0 || (streamID&1 == 1) != peerUsesOddIDs {
			return errors.New("mux: invalid inbound stream ID")
		}
		st := s.newStream(streamID)

		s.streamsMu.Lock()
		if s.streams == nil {
			s.streamsMu.Unlock()
			return s.sendCtrl(streamID, typeData, flagRST, 0)
		}
		if _, exists := s.streams[streamID]; exists {
			s.streamsMu.Unlock()
			return s.sendCtrl(streamID, typeData, flagRST, 0)
		}
		s.streams[streamID] = st
		s.streamsMu.Unlock()
		s.numStreams.Add(1)

		// Try to enqueue the stream before ACKing. If the backlog is full
		// we RST without ever ACKing, so OpenStream on the remote side
		// never unblocks with a "live" stream that is immediately torn down.
		select {
		case s.acceptCh <- st:
			// Backlog had room — now ACK the SYN.
			if err := s.sendCtrl(streamID, typeData, flagACK, 0); err != nil {
				// Network is broken; the stream is already in acceptCh.
				// forceClose it so AcceptStream callers get an error.
				st.forceClose(err)
				s.removeStream(streamID)
				return err
			}
		default:
			// Backlog full — RST without ACKing. The remote OpenStream
			// will see the RST close synAckCh and return an error.
			s.removeStream(streamID)
			return s.sendCtrl(streamID, typeData, flagRST, 0)
		}

		// A SYN frame may also carry payload (rare, but legal). Fall through.
		if len(payload) == 0 && flags&flagFIN == 0 {
			return nil
		}
	}

	// ── ACK: OpenStream() SYN was acknowledged ────────────────────────────────
	if flags&flagACK != 0 {
		s.streamsMu.RLock()
		st, ok := s.streams[streamID]
		s.streamsMu.RUnlock()
		if ok && st.synAckCh != nil {
			// synAckOnce ensures close(synAckCh) is called exactly once,
			// even if forceClose races this ACK handler from another goroutine.
			st.synAckOnce.Do(func() { close(st.synAckCh) })
		}
		if len(payload) == 0 && flags&flagFIN == 0 {
			return nil
		}
	}

	// ── Lookup stream for RST / FIN / data ───────────────────────────────────
	s.streamsMu.RLock()
	st, ok := s.streams[streamID]
	s.streamsMu.RUnlock()

	if !ok {
		// Stream unknown (already removed or never seen). Send RST once unless
		// this frame is itself a RST or FIN (avoid RST storms).
		if flags&(flagRST|flagFIN) == 0 {
			return s.sendCtrl(streamID, typeData, flagRST, 0)
		}
		return nil
	}

	// ── RST ──────────────────────────────────────────────────────────────────
	if flags&flagRST != 0 {
		st.forceClose(ErrStreamReset)
		s.removeStream(streamID)
		return nil
	}

	// ── Deliver data ─────────────────────────────────────────────────────────
	if len(payload) > 0 {
		// Enforce receive-side flow control: the peer must not send more
		// bytes than the window we have granted.  If it does, the stream
		// is in protocol violation — RST it.
		st.recvMu.Lock()
		if int64(len(payload)) > st.recvWin {
			st.recvMu.Unlock()
			st.forceClose(ErrStreamReset)
			s.removeStream(streamID)
			return s.sendCtrl(streamID, typeData, flagRST, 0)
		}
		st.recvWin -= int64(len(payload))
		st.recvBuf = append(st.recvBuf, payload...)
		st.recvMu.Unlock()
		select {
		case st.recvNotify <- struct{}{}:
		default:
		}
	}

	// ── FIN: remote half-closed ───────────────────────────────────────────────
	if flags&flagFIN != 0 {
		st.remoteFin.Store(true)
		// Wake any blocked Read so it can drain the buffer then return io.EOF.
		select {
		case st.recvNotify <- struct{}{}:
		default:
		}
		// If we also already closed our side, the stream is fully done.
		if st.localFin.Load() {
			s.removeStream(streamID)
		}
	}

	return nil
}

func (s *Session) handleWindowUpdate(streamID uint32, delta uint32) error {
	s.streamsMu.RLock()
	st, ok := s.streams[streamID]
	s.streamsMu.RUnlock()
	if !ok {
		return nil
	}
	st.sendWinMu.Lock()
	st.sendWin += int64(delta)
	if st.sendWin > maxSendWin {
		st.sendWin = maxSendWin
	}
	st.sendWinMu.Unlock()
	// Wake any Write blocked waiting for window space.
	select {
	case st.sendNotify <- struct{}{}:
	default:
	}
	return nil
}

// ── Keepalive ─────────────────────────────────────────────────────────────────

func (s *Session) keepAliveLoop() {
	ticker := time.NewTicker(s.cfg.KeepAliveInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
		case <-s.closedCh:
			return
		}

		seq := s.pingSeq.Add(1)
		if err := s.sendCtrl(0, typePing, 0, seq); err != nil {
			s.closeWithError(err)
			return
		}

		timer := time.NewTimer(s.cfg.KeepAliveTimeout)
		gotPong := false
		for !gotPong {
			select {
			case id := <-s.pongCh:
				if id == seq {
					gotPong = true
				}
				// else: stale pong from a previous ping — drain and retry
			case <-timer.C:
				s.closeWithError(errors.New("mux: keepalive timeout"))
				return
			case <-s.closedCh:
				timer.Stop()
				return
			}
		}
		timer.Stop()
	}
}

// ── Stream ────────────────────────────────────────────────────────────────────

// Stream is a logical bidirectional channel over a Session.  It implements
// net.Conn.
type Stream struct {
	id   uint32
	sess *Session

	// synAckCh is closed by the readLoop when ACK arrives for this stream's SYN.
	// Non-nil only for streams created by OpenStream().
	synAckCh   chan struct{}
	synAckOnce sync.Once // guards the single close(synAckCh)

	// Receive side.
	recvMu     sync.Mutex
	recvBuf    []byte
	recvWin    int64         // remaining receive window; protected by recvMu
	recvNotify chan struct{} // capacity-1; pinged when data appended

	// Send flow-control window.
	sendWinMu  sync.Mutex
	sendWin    int64         // protected by sendWinMu
	sendNotify chan struct{} // capacity-1; pinged when window grows

	// Half-close state.
	localFin  atomic.Bool
	remoteFin atomic.Bool

	// RST state.
	rst    atomic.Bool
	rstErr atomic.Value // stores error

	// Deadline state.
	deadlineMu    sync.Mutex
	readDeadline  time.Time
	writeDeadline time.Time

	closeOnce sync.Once

	localAddr  net.Addr
	remoteAddr net.Addr
}

// forceClose is called on RST or session shutdown.  It unblocks all pending
// Read and Write calls with err, and prevents future I/O.
func (st *Stream) forceClose(err error) {
	st.closeOnce.Do(func() {
		st.rst.Store(true)
		if err != nil {
			st.rstErr.Store(err)
		}
		st.localFin.Store(true)
		st.remoteFin.Store(true)
		select {
		case st.recvNotify <- struct{}{}:
		default:
		}
		select {
		case st.sendNotify <- struct{}{}:
		default:
		}
		// Unblock any OpenStream waiting for ACK.
		if st.synAckCh != nil {
			st.synAckOnce.Do(func() { close(st.synAckCh) })
		}
	})
}

// ── net.Conn implementation ───────────────────────────────────────────────────

// Read reads data from the stream, blocking if the buffer is empty.
func (st *Stream) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	for {
		// RST is checked first; it overrides everything.
		if st.rst.Load() {
			return 0, st.streamErr()
		}

		st.recvMu.Lock()
		if len(st.recvBuf) > 0 {
			n := copy(b, st.recvBuf)
			// Shift the buffer.  For large or streaming payloads, avoid
			// O(n) copy by reslicing; reset to nil when drained.
			if n == len(st.recvBuf) {
				st.recvBuf = nil
			} else {
				remaining := st.recvBuf[n:]
				// Compact the backing array when the remainder is small
				// relative to the capacity — prevents retaining a large
				// backing array for the life of the stream.
				const compactThreshold = 4 * 1024
				if cap(st.recvBuf) > compactThreshold && len(remaining) <= compactThreshold/4 {
					fresh := make([]byte, len(remaining))
					copy(fresh, remaining)
					st.recvBuf = fresh
				} else {
					st.recvBuf = remaining
				}
			}
			// Replenish the receive window before releasing the lock so
			// that the readLoop's recvWin check sees the updated value.
			st.recvWin += int64(n)
			st.recvMu.Unlock()
			// Notify the remote that it may send more bytes.
			if err := st.sess.sendWindowUpdate(st.id, uint32(n)); err != nil {
				// Non-fatal – the session will close on its own.
				_ = err
			}
			return n, nil
		}
		st.recvMu.Unlock()

		// Buffer empty.
		if st.remoteFin.Load() {
			return 0, io.EOF
		}

		// Block until data, deadline, or session closure.
		if err := st.waitRecv(); err != nil {
			return 0, err
		}
	}
}

// waitRecv blocks until recvNotify fires, a deadline expires, or the session
// closes.
func (st *Stream) waitRecv() error {
	st.deadlineMu.Lock()
	dl := st.readDeadline
	st.deadlineMu.Unlock()

	var timerCh <-chan time.Time
	var timer *time.Timer
	if !dl.IsZero() {
		d := time.Until(dl)
		if d <= 0 {
			return &timeoutErr{}
		}
		timer = time.NewTimer(d)
		timerCh = timer.C
	}

	select {
	case <-st.recvNotify:
		if timer != nil {
			timer.Stop()
		}
		return nil
	case <-timerCh:
		return &timeoutErr{}
	case <-st.sess.closedCh:
		if timer != nil {
			timer.Stop()
		}
		return st.sess.sessionErr()
	}
}

// Write sends b to the remote side, respecting flow-control windows.
// Large buffers are split into maxFramePayload-sized DATA frames.
func (st *Stream) Write(b []byte) (int, error) {
	if st.rst.Load() {
		return 0, st.streamErr()
	}
	if st.localFin.Load() {
		return 0, ErrStreamClosed
	}
	if st.sess.IsClosed() {
		return 0, ErrSessionClosed
	}

	sent := 0
	for sent < len(b) {
		// Block until the send window has space.
		if err := st.waitSendWindow(); err != nil {
			return sent, err
		}

		// Compute chunk size and decrement the window atomically so that
		// concurrent Write calls cannot both observe the same positive window
		// and both over-commit (TOCTOU).
		st.sendWinMu.Lock()
		avail := st.sendWin
		if avail <= 0 {
			// Another concurrent Write drained the window between
			// waitSendWindow returning and now; loop back and wait again.
			st.sendWinMu.Unlock()
			continue
		}
		chunk := b[sent:]
		if int64(len(chunk)) > avail {
			chunk = chunk[:avail]
		}
		if len(chunk) > maxFramePayload {
			chunk = chunk[:maxFramePayload]
		}
		st.sendWin -= int64(len(chunk))
		st.sendWinMu.Unlock()

		if err := st.sess.sendData(st.id, 0, chunk); err != nil {
			return sent, err
		}
		sent += len(chunk)
	}
	return sent, nil
}

// waitSendWindow blocks until the send window is non-zero, a deadline fires,
// or the session/stream is closed.
func (st *Stream) waitSendWindow() error {
	for {
		if st.rst.Load() {
			return st.streamErr()
		}
		if st.sess.IsClosed() {
			return st.sess.sessionErr()
		}

		st.sendWinMu.Lock()
		win := st.sendWin
		st.sendWinMu.Unlock()
		if win > 0 {
			return nil
		}

		// Window exhausted – wait.
		st.deadlineMu.Lock()
		dl := st.writeDeadline
		st.deadlineMu.Unlock()

		var timerCh <-chan time.Time
		var timer *time.Timer
		if !dl.IsZero() {
			d := time.Until(dl)
			if d <= 0 {
				return &timeoutErr{}
			}
			timer = time.NewTimer(d)
			timerCh = timer.C
		}

		select {
		case <-st.sendNotify:
			if timer != nil {
				timer.Stop()
			}
		case <-timerCh:
			return &timeoutErr{}
		case <-st.sess.closedCh:
			if timer != nil {
				timer.Stop()
			}
			return st.sess.sessionErr()
		}
	}
}

// Close performs a graceful half-close by sending FIN.  The stream remains
// readable until the remote also sends FIN.
func (st *Stream) Close() error {
	if !st.localFin.CompareAndSwap(false, true) {
		return nil // already closed
	}
	err := st.sess.sendCtrl(st.id, typeData, flagFIN, 0)
	// If the remote half is also closed, the stream is fully done.
	if st.remoteFin.Load() {
		st.sess.removeStream(st.id)
	}
	return err
}

func (st *Stream) LocalAddr() net.Addr  { return st.localAddr }
func (st *Stream) RemoteAddr() net.Addr { return st.remoteAddr }

func (st *Stream) SetDeadline(t time.Time) error {
	st.deadlineMu.Lock()
	st.readDeadline = t
	st.writeDeadline = t
	st.deadlineMu.Unlock()
	select {
	case st.recvNotify <- struct{}{}:
	default:
	}
	select {
	case st.sendNotify <- struct{}{}:
	default:
	}
	return nil
}

func (st *Stream) SetReadDeadline(t time.Time) error {
	st.deadlineMu.Lock()
	st.readDeadline = t
	st.deadlineMu.Unlock()
	select {
	case st.recvNotify <- struct{}{}:
	default:
	}
	return nil
}

func (st *Stream) SetWriteDeadline(t time.Time) error {
	st.deadlineMu.Lock()
	st.writeDeadline = t
	st.deadlineMu.Unlock()
	select {
	case st.sendNotify <- struct{}{}:
	default:
	}
	return nil
}

func (st *Stream) streamErr() error {
	if v := st.rstErr.Load(); v != nil {
		return v.(error)
	}
	return ErrStreamClosed
}

// ── net.Error (timeout) ───────────────────────────────────────────────────────

type timeoutErr struct{}

func (*timeoutErr) Error() string   { return "mux: i/o timeout" }
func (*timeoutErr) Timeout() bool   { return true }
func (*timeoutErr) Temporary() bool { return true }
