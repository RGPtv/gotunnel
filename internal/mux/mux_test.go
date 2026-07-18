package mux

import (
	"bytes"
	"net"
	"testing"
	"time"
)

type shortWriter struct {
	bytes.Buffer
}

func (w *shortWriter) Write(p []byte) (int, error) {
	if len(p) > 2 {
		p = p[:2]
	}
	return w.Buffer.Write(p)
}

func TestWriteFrameHandlesPartialWrites(t *testing.T) {
	var w shortWriter
	payload := []byte("payload")
	if err := writeFrameLocked(&w, typeData, 0, 1, uint32(len(payload)), payload); err != nil {
		t.Fatalf("writeFrameLocked: %v", err)
	}
	if got, want := w.Len(), headerLen+len(payload); got != want {
		t.Fatalf("frame length = %d, want %d", got, want)
	}
}

func TestCloseDoesNotWaitForBlockedWrite(t *testing.T) {
	local, remote := net.Pipe()
	defer remote.Close()

	s, err := Client(local, &Config{KeepAliveInterval: -1})
	if err != nil {
		t.Fatal(err)
	}
	go s.OpenStream() // Its SYN write blocks because remote does not read.

	time.Sleep(10 * time.Millisecond)
	done := make(chan struct{})
	go func() {
		_ = s.Close()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Close blocked behind an in-flight write")
	}
}

func TestInvalidInboundStreamParityClosesSession(t *testing.T) {
	local, remote := net.Pipe()
	defer remote.Close()

	s, err := Client(local, &Config{KeepAliveInterval: -1})
	if err != nil {
		t.Fatal(err)
	}
	// Client sessions open odd IDs, so an inbound SYN must be even.
	var frame bytes.Buffer
	if err := writeFrameLocked(&frame, typeData, flagSYN, 1, 0, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := remote.Write(frame.Bytes()); err != nil {
		t.Fatal(err)
	}

	select {
	case <-s.closedCh:
	case <-time.After(time.Second):
		t.Fatal("invalid stream ID did not close the session")
	}
}
