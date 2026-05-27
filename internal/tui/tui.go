// Package tui provides a terminal user interface for the gotunnel server.
// It uses only the Go standard library (syscall + os) — no external deps.
package tui

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// ── ANSI helpers ──────────────────────────────────────────────────────────────

const (
	esc   = "\x1b["
	reset = "\x1b[0m"

	bold      = "\x1b[1m"
	dim       = "\x1b[2m"
	underline = "\x1b[4m"

	black   = "\x1b[30m"
	red     = "\x1b[31m"
	green   = "\x1b[32m"
	yellow  = "\x1b[33m"
	blue    = "\x1b[34m"
	magenta = "\x1b[35m"
	cyan    = "\x1b[36m"
	white   = "\x1b[37m"

	bgBlack = "\x1b[40m"
	bgBlue  = "\x1b[44m"

	brightBlack  = "\x1b[90m"
	brightRed    = "\x1b[91m"
	brightGreen  = "\x1b[92m"
	brightYellow = "\x1b[93m"
	brightBlue   = "\x1b[94m"
	brightCyan   = "\x1b[96m"
	brightWhite  = "\x1b[97m"
)

func clearScreen()              { fmt.Fprint(os.Stdout, esc+"2J"+esc+"H") }
func hideCursor()               { fmt.Fprint(os.Stdout, esc+"?25l") }
func showCursor()               { fmt.Fprint(os.Stdout, esc+"?25h") }
func moveTo(row, col int)       { fmt.Fprintf(os.Stdout, esc+"%d;%dH", row, col) }
func clearLine()                { fmt.Fprint(os.Stdout, esc+"2K") }
func clearToEnd()               { fmt.Fprint(os.Stdout, esc+"J") }
func altScreen()                { fmt.Fprint(os.Stdout, esc+"?1049h") }
func mainScreen()               { fmt.Fprint(os.Stdout, esc+"?1049l") }

func termSize() (w, h int) {
	type winsize struct {
		Row    uint16
		Col    uint16
		Xpixel uint16
		Ypixel uint16
	}
	var ws winsize
	//nolint:errcheck
	syscall.Syscall(syscall.SYS_IOCTL,
		uintptr(syscall.Stdout),
		syscall.TIOCGWINSZ,
		uintptr(unsafe.Pointer(&ws)),
	)
	if ws.Col < 40 {
		ws.Col = 120
	}
	if ws.Row < 10 {
		ws.Row = 30
	}
	return int(ws.Col), int(ws.Row)
}

func pad(s string, n int) string {
	r := []rune(s)
	if len(r) >= n {
		if n <= 3 {
			return string(r[:n])
		}
		return string(r[:n-1]) + "…"
	}
	return s + strings.Repeat(" ", n-len(r))
}

func rpad(s string, n int) string {
	r := []rune(s)
	if len(r) >= n {
		return string(r[:n])
	}
	return strings.Repeat(" ", n-len(r)) + s
}

func hline(w int, ch string) string { return strings.Repeat(ch, w) }

// ── Event log ─────────────────────────────────────────────────────────────────

// LogLevel classifies a log event.
type LogLevel int

const (
	LevelInfo LogLevel = iota
	LevelWarn
	LevelError
	LevelSuccess
)

// LogEntry is a single event line shown in the log pane.
type LogEntry struct {
	Time    time.Time
	Level   LogLevel
	Message string
}

// ── TunnelInfo mirrors server state for display ───────────────────────────────

// TunnelInfo holds a snapshot of one active tunnel.
type TunnelInfo struct {
	Endpoint    string
	Type        string // "http" | "tcp"
	Connections int
	ClientIP    string
	ProxyURL    string
}

// Stats holds server-level counters.
type Stats struct {
	ActiveConns int64
	TotalReqs   int64
	Uptime      time.Duration
}

// ── TUI ───────────────────────────────────────────────────────────────────────

const maxLogLines = 200

// TUI is the live terminal dashboard.
type TUI struct {
	mu sync.Mutex

	// config (set once at Init)
	token       string
	httpAddr    string
	httpsAddr   string
	tunAddr     string
	inspectAddr string
	dashUser    string
	dashPass    string

	// live state (updated via Update*)
	stats   Stats
	tunnels []TunnelInfo
	logs    []LogEntry

	startTime time.Time
	quit      chan struct{}
}

// New creates a TUI. Call Start() to begin rendering.
func New() *TUI {
	return &TUI{
		startTime: time.Now(),
		quit:      make(chan struct{}),
	}
}

// SetConfig stores one-time server config for the header pane.
func (t *TUI) SetConfig(token, httpAddr, httpsAddr, tunAddr, inspectAddr, dashUser, dashPass string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.token = token
	t.httpAddr = httpAddr
	t.httpsAddr = httpsAddr
	t.tunAddr = tunAddr
	t.inspectAddr = inspectAddr
	t.dashUser = dashUser
	t.dashPass = dashPass
}

// UpdateStats replaces the live stats snapshot.
func (t *TUI) UpdateStats(s Stats) {
	t.mu.Lock()
	t.stats = s
	t.mu.Unlock()
}

// UpdateTunnels replaces the live tunnel list.
func (t *TUI) UpdateTunnels(tunnels []TunnelInfo) {
	t.mu.Lock()
	t.tunnels = tunnels
	t.mu.Unlock()
}

// Log appends a line to the event log.
func (t *TUI) Log(level LogLevel, msg string) {
	t.mu.Lock()
	t.logs = append(t.logs, LogEntry{Time: time.Now(), Level: level, Message: msg})
	if len(t.logs) > maxLogLines {
		t.logs = t.logs[len(t.logs)-maxLogLines:]
	}
	t.mu.Unlock()
}

// Logf is a convenience wrapper around Log.
func (t *TUI) Logf(level LogLevel, format string, args ...any) {
	t.Log(level, fmt.Sprintf(format, args...))
}

// Start enters the alternate screen and begins the render loop.
func (t *TUI) Start() {
	altScreen()
	hideCursor()
	clearScreen()
	go t.loop()
}

// Stop exits cleanly.
func (t *TUI) Stop() {
	close(t.quit)
	showCursor()
	mainScreen()
}

func (t *TUI) loop() {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-t.quit:
			return
		case <-ticker.C:
			t.render()
		}
	}
}

// render draws the entire TUI to stdout in one pass.
func (t *TUI) render() {
	t.mu.Lock()
	defer t.mu.Unlock()

	w, h := termSize()
	var b strings.Builder

	// ── header bar ───────────────────────────────────────────────────────────
	b.WriteString(esc + "H") // cursor home, no clear (avoids flicker)

	title := "  gotunnel server "
	uptime := fmt.Sprintf("  uptime %s  ", fmtDuration(time.Since(t.startTime)))
	header := bold + brightWhite + bgBlack + " " + title
	header += strings.Repeat(" ", max(0, w-len([]rune(title))-len([]rune(uptime))-2))
	header += dim + uptime + reset
	writeLine(&b, header, w)

	b.WriteString(brightBlack + hline(w, "─") + reset + "\n")

	// ── info pane (2 columns) ─────────────────────────────────────────────────
	col := w / 2

	row1 := infoCell("HTTP  ", t.httpAddr, col) + infoCell("Tunnel", t.tunAddr, w-col)
	row2 := infoCell("HTTPS ", orDash(t.httpsAddr), col) + infoCell("Dashb.", t.inspectURL(), w-col)
	row3 := infoCell("Token ", maskSecret(t.token), col) + infoCell("Login ", t.dashUser+"/"+maskSecret(t.dashPass), w-col)

	connsStr := fmt.Sprintf("%d", t.stats.ActiveConns)
	reqsStr := fmt.Sprintf("%d", t.stats.TotalReqs)
	row4 := infoCell("Conns ", brightGreen+connsStr+reset, col) + infoCell("Reqs  ", brightCyan+reqsStr+reset, w-col)

	writeLine(&b, row1, w)
	writeLine(&b, row2, w)
	writeLine(&b, row3, w)
	writeLine(&b, row4, w)

	b.WriteString(brightBlack + hline(w, "─") + reset + "\n")

	// ── tunnels pane ─────────────────────────────────────────────────────────
	tunnelHeaderH := 9 // lines used above
	logLines := 8      // lines reserved for log at bottom
	separators := 3    // separator lines

	tunnelH := h - tunnelHeaderH - logLines - separators
	if tunnelH < 3 {
		tunnelH = 3
	}

	// Header row
	th := dim + brightWhite +
		" " + pad("ENDPOINT", 28) +
		pad("TYPE", 6) +
		rpad("CONNS", 7) + "  " +
		pad("CLIENT IP", 22) +
		pad("PROXY URL", w-28-6-7-2-22-1) +
		reset
	writeLine(&b, th, w)
	b.WriteString(brightBlack + hline(w, "·") + reset + "\n")

	shown := t.tunnels
	if len(shown) > tunnelH-2 {
		shown = shown[:tunnelH-2]
	}
	for _, tun := range shown {
		typeColor := cyan
		if tun.Type == "tcp" {
			typeColor = magenta
		}
		line := " " +
			brightWhite + pad(tun.Endpoint, 28) + reset +
			typeColor + pad(tun.Type, 6) + reset +
			brightGreen + rpad(fmt.Sprintf("%d", tun.Connections), 7) + reset + "  " +
			dim + pad(orDash(stripPort(tun.ClientIP)), 22) + reset +
			dim + pad(orDash(tun.ProxyURL), w-28-6-7-2-22-1) + reset
		writeLine(&b, line, w)
	}
	// fill empty tunnel rows
	for i := len(shown); i < tunnelH-2; i++ {
		writeLine(&b, "", w)
	}

	b.WriteString(brightBlack + hline(w, "─") + reset + "\n")

	// ── log pane ─────────────────────────────────────────────────────────────
	b.WriteString(dim + " event log" + reset + "\n")

	last := t.logs
	if len(last) > logLines-1 {
		last = last[len(last)-(logLines-1):]
	}
	for _, e := range last {
		col, sym := logStyle(e.Level)
		ts := e.Time.Format("15:04:05")
		line := fmt.Sprintf(" %s%s%s %s%s%s %s",
			brightBlack, ts, reset,
			col, sym, reset,
			e.Message)
		writeLine(&b, line, w)
	}
	for i := len(last); i < logLines-1; i++ {
		writeLine(&b, "", w)
	}

	// clear anything below (handles terminal resize)
	b.WriteString(esc + "J")

	// flush everything at once
	fmt.Fprint(os.Stdout, b.String())
}

// ── helpers ───────────────────────────────────────────────────────────────────

func writeLine(b *strings.Builder, s string, w int) {
	b.WriteString(s)
	// move to start of next line (avoids needing to track visual width exactly)
	b.WriteString(esc + "0K\n")
	_ = w
}

func infoCell(label, value string, width int) string {
	lbl := dim + brightWhite + " " + label + reset + " "
	val := brightCyan + value + reset
	// visual padding (approximate — ANSI codes are invisible)
	visLen := 1 + len(label) + 1 + len(value)
	pad := strings.Repeat(" ", max(0, width-visLen-1))
	return lbl + val + pad
}

func logStyle(l LogLevel) (color, sym string) {
	switch l {
	case LevelSuccess:
		return brightGreen, "✓"
	case LevelWarn:
		return brightYellow, "!"
	case LevelError:
		return brightRed, "✗"
	default:
		return brightBlue, "·"
	}
}

func fmtDuration(d time.Duration) string {
	d = d.Round(time.Second)
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	s := int(d.Seconds()) % 60
	if h > 0 {
		return fmt.Sprintf("%dh%02dm%02ds", h, m, s)
	}
	return fmt.Sprintf("%dm%02ds", m, s)
}

func maskSecret(s string) string {
	if len(s) <= 8 {
		return "••••••••"
	}
	return s[:6] + "••••••"
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

func stripPort(s string) string {
	// strip trailing :port and surrounding brackets from IPv6
	if i := strings.LastIndex(s, ":"); i > 0 {
		// only strip if what follows looks like a port number
		rest := s[i+1:]
		allDigits := len(rest) > 0
		for _, c := range rest {
			if c < '0' || c > '9' {
				allDigits = false
				break
			}
		}
		if allDigits {
			s = s[:i]
		}
	}
	return strings.Trim(s, "[]")
}

func (t *TUI) inspectURL() string {
	if t.inspectAddr == "" {
		return "—"
	}
	addr := t.inspectAddr
	if strings.HasPrefix(addr, ":") {
		addr = "localhost" + addr
	}
	return "http://" + addr
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
