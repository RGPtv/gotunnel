package tunnel

import (
	"io"
	"net"
	"sync"
	"time"
)

const bidirectionalCloseWait = 5 * time.Second

func proxyBidirectional(left net.Conn, leftReader io.Reader, right net.Conn, rightReader io.Reader) {
	var once sync.Once
	closeBoth := func() {
		once.Do(func() {
			left.Close()
			right.Close()
		})
	}

	done := make(chan struct{}, 2)
	cp := func(dst net.Conn, src io.Reader) {
		defer func() {
			closeBoth()
			done <- struct{}{}
		}()
		_, _ = io.Copy(dst, src)
	}

	go cp(left, rightReader)
	go cp(right, leftReader)

	<-done
	select {
	case <-done:
	case <-time.After(bidirectionalCloseWait):
	}
}
