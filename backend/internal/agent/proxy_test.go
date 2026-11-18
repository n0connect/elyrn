package agent_test

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"elyrn/internal/agent"
)

// F1 (agent-proxy/onion-origin-accepts-non-tor-proxy-http-proxy-precedes-all-proxy): an onion
// server is reached through the socks5h:// proxy of ALL_PROXY only. The proxies below are real
// local listeners: an HTTP forward proxy that records what reaches it, and a TCP listener that
// records the first byte a client sends (0x05 opens a SOCKS5 greeting). No elyrn server exists:
// every exchange fails at the proxy, which is all these tests need to see.

const (
	onionServer     = "http://" + "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx" + ".onion"
	socksVersion5   = 0x05
	proxyWaitBudget = 5 * time.Second
)

// proxyEnvironment is every variable that could name a proxy, cleared for one test.
var proxyEnvironment = []string{"ALL_PROXY", "all_proxy", "HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "NO_PROXY", "no_proxy"}

func clearProxies(t *testing.T) {
	t.Helper()
	for _, name := range proxyEnvironment {
		t.Setenv(name, "")
	}
}

// forwardProxy is an HTTP forward proxy that only counts the requests it is handed.
func forwardProxy(t *testing.T) (string, *atomic.Int64) {
	t.Helper()
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusBadGateway)
	}))
	t.Cleanup(srv.Close)
	return srv.URL, &hits
}

// socksListener accepts connections and reports the first byte of each, then closes it.
func socksListener(t *testing.T) (string, <-chan byte) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() }) // closing ends the accept loop; nothing to report
	first := make(chan byte, 8)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			buf := make([]byte, 1)
			_ = conn.SetReadDeadline(time.Now().Add(proxyWaitBudget)) // a silent client only shortens the test
			if n, _ := conn.Read(buf); n == 1 {
				select {
				case first <- buf[0]:
				default:
				}
			}
			_ = conn.Close() // the client sees the proxy hang up, as intended
		}
	}()
	return ln.Addr().String(), first
}

func onionAgent(t *testing.T) (*agent.Agent, error) {
	t.Helper()
	return open(t, identityAt(t, map[string]string{"server": onionServer}), false)
}

// An inherited ordinary forward proxy (HTTP_PROXY) beside the Tor proxy must never see a request
// for the onion server: the old chooser handed it every http request, the login body included.
func TestOnionServer_GoesThroughTheSOCKSProxyOnly(t *testing.T) {
	clearProxies(t)
	forward, hits := forwardProxy(t)
	socks, first := socksListener(t)
	t.Setenv("HTTP_PROXY", forward)
	t.Setenv("HTTPS_PROXY", forward)
	t.Setenv("ALL_PROXY", "socks5h://"+socks)
	robot, err := onionAgent(t)
	if err != nil {
		t.Fatalf("New with ALL_PROXY=socks5h:// beside HTTP_PROXY: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), proxyWaitBudget)
	defer cancel()
	if _, err := robot.Identity(ctx); err == nil {
		t.Fatal("a login through a proxy that hangs up succeeded")
	}
	select {
	case b := <-first:
		if b != socksVersion5 {
			t.Fatalf("the SOCKS proxy received %#x first, not a SOCKS5 greeting", b)
		}
	case <-time.After(proxyWaitBudget):
		t.Fatal("the SOCKS proxy was never contacted")
	}
	if hits.Load() != 0 {
		t.Fatalf("the HTTP forward proxy received %d requests for the onion server", hits.Load())
	}
}

// Without ALL_PROXY, or with one of another scheme, the agent refuses to start: HTTP_PROXY alone
// used to pass the start-up check, and so did ALL_PROXY=http://.
func TestOnionServer_RefusesEveryOtherProxy(t *testing.T) {
	forward, hits := forwardProxy(t)
	host := strings.TrimPrefix(forward, "http://")
	for name, env := range map[string]map[string]string{
		"no proxy at all":                 {},
		"HTTP_PROXY only":                 {"HTTP_PROXY": forward},
		"HTTPS_PROXY only":                {"HTTPS_PROXY": forward},
		"lowercase http_proxy only":       {"http_proxy": forward},
		"ALL_PROXY over http":             {"ALL_PROXY": "http://" + host},
		"ALL_PROXY over https":            {"ALL_PROXY": "https://" + host},
		"ALL_PROXY over socks5":           {"ALL_PROXY": "socks5://" + host},
		"ALL_PROXY without a host":        {"ALL_PROXY": "socks5h://"},
		"ALL_PROXY with a path":           {"ALL_PROXY": "socks5h://" + host + "/tor"},
		"ALL_PROXY not a URL":             {"ALL_PROXY": "127.0.0.1:9050"},
		"ALL_PROXY empty, all_proxy http": {"all_proxy": "http://" + host},
	} {
		t.Run(name, func(t *testing.T) {
			clearProxies(t)
			for k, v := range env {
				t.Setenv(k, v)
			}
			_, err := onionAgent(t)
			wantCode(t, err, agent.CodeOnionProxy, name)
		})
	}
	if hits.Load() != 0 {
		t.Fatalf("the forward proxy received %d requests", hits.Load())
	}
}

// The lowercase all_proxy is read when ALL_PROXY is unset, as curl does.
func TestOnionServer_TakesTheLowercaseAllProxy(t *testing.T) {
	clearProxies(t)
	socks, _ := socksListener(t)
	t.Setenv("all_proxy", "socks5h://"+socks)
	if _, err := onionAgent(t); err != nil {
		t.Fatalf("New with all_proxy=socks5h://: %v", err)
	}
}

// A clearnet server keeps today's rules: an http ALL_PROXY is still accepted for it.
func TestClearnetServer_KeepsItsProxyRules(t *testing.T) {
	clearProxies(t)
	forward, _ := forwardProxy(t)
	t.Setenv("ALL_PROXY", forward)
	if _, err := open(t, identityAt(t, nil), false); err != nil {
		t.Fatalf("New for %s with ALL_PROXY=http://: %v", testServer, err)
	}
	t.Setenv("ALL_PROXY", "ftp://"+strings.TrimPrefix(forward, "http://"))
	if _, err := open(t, identityAt(t, nil), false); agent.CodeOf(err) != agent.CodeProxy {
		t.Fatalf("a malformed clearnet ALL_PROXY: %v, want %s", err, agent.CodeProxy)
	}
}
