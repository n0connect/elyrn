//go:build test
// +build test

package testutil

import (
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// StallingProxy forwards TCP connections to PostgreSQL and can stop delivering in both
// directions without closing anything: what a paused or overloaded database looks like from
// the server (the kernel still accepts the bytes, nobody answers them). It can also slow down
// instead (Slow): every chunk is delivered, each one late, what an overloaded database or a
// congested link looks like: each statement answers within its own deadline, several together
// do not. The sessions behind it
// (and any lock they hold) and PostgreSQL itself stay real. Point DB_HOST/DB_PORT at
// 127.0.0.1:Port() before a connection is opened through it.
type StallingProxy struct {
	listener net.Listener
	target   string
	gate     sync.RWMutex // held for writing while stalled
	mu       sync.Mutex
	stalled  bool
	conns    []net.Conn
	delay    atomic.Int64 // nanoseconds every chunk waits before it is delivered (Slow)
}

// StartStallingProxy forwards to target (host:port) until the test ends.
func StartStallingProxy(t *testing.T, target string) *StallingProxy {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	p := &StallingProxy{listener: listener, target: target}
	go p.serve()
	t.Cleanup(p.close)
	return p
}

// Port is the proxy's port on 127.0.0.1.
func (p *StallingProxy) Port() string {
	return strconv.Itoa(p.listener.Addr().(*net.TCPAddr).Port)
}

func (p *StallingProxy) serve() {
	for {
		client, err := p.listener.Accept()
		if err != nil {
			return
		}
		server, err := net.Dial("tcp", p.target)
		if err != nil {
			_ = client.Close()
			continue
		}
		p.mu.Lock()
		p.conns = append(p.conns, client, server)
		p.mu.Unlock()
		go p.pipe(client, server)
		go p.pipe(server, client)
	}
}

// pipe copies src to dst chunk by chunk; while stalled, a chunk read is held, not delivered.
func (p *StallingProxy) pipe(src, dst net.Conn) {
	defer func() { _ = src.Close(); _ = dst.Close() }()
	buf := make([]byte, 32<<10)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if delay := time.Duration(p.delay.Load()); delay > 0 {
				time.Sleep(delay)
			}
			p.gate.RLock()
			_, werr := dst.Write(buf[:n])
			p.gate.RUnlock()
			if werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// Stall holds every byte from now on, in both directions, without closing anything.
func (p *StallingProxy) Stall() {
	p.gate.Lock()
	p.mu.Lock()
	p.stalled = true
	p.mu.Unlock()
}

// Slow delays every chunk from now on by delay, in both directions (0: deliver at once again).
func (p *StallingProxy) Slow(delay time.Duration) {
	p.delay.Store(int64(delay))
}

// Resume delivers the held bytes and everything after them.
func (p *StallingProxy) Resume() {
	p.mu.Lock()
	stalled := p.stalled
	p.stalled = false
	p.mu.Unlock()
	if stalled {
		p.gate.Unlock()
	}
}

func (p *StallingProxy) close() {
	p.Slow(0)
	p.Resume()
	_ = p.listener.Close()
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, c := range p.conns {
		_ = c.Close()
	}
}
