package handlers

import (
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"elyrn/internal/apperr"
	"elyrn/internal/contract"
	"elyrn/internal/models"
	"elyrn/tests/testutil"
)

// Run with: go test -tags test -run '^$' -fuzz '^FuzzHealthLoopback$' -fuzztime 60s ./internal/handlers

// realLoopback is the oracle, written with net/netip: the peer is a loopback address, IPv4-mapped
// or not, without a zone. Anything that does not parse is not loopback.
func realLoopback(remote string) bool {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = remote
	}
	addr, err := netip.ParseAddr(host)
	return err == nil && addr.Zone() == "" && addr.Unmap().IsLoopback()
}

// FuzzHealthLoopback runs the healthcheck (through the gate, as routed) for arbitrary peer
// addresses: only a real loopback peer is answered (no database in a fuzz run, so 503
// E_HEALTH_UNAVAILABLE); every other peer is told the path does not exist (E_ROUTE_NOT_FOUND),
// and a canonical loopback address is never refused.
func FuzzHealthLoopback(f *testing.F) {
	for _, seed := range []string{"127.0.0.1:4000", "127.255.255.254:1", "[::1]:4000", "::1", "127.0.0.1",
		"[::ffff:127.0.0.1]:4000", "[::1%lo]:4000", "[fe80::1%lo0]:1", "0.0.0.0:80", "[::]:80", "128.0.0.1:1",
		"localhost:80", "127.0.0.1:80:90", "0127.0.0.1:1", "", "\x00"} {
		f.Add(seed)
	}
	health := contract.Gate(HealthHandler)
	f.Fuzz(func(t *testing.T, remote string) {
		r := httptest.NewRequest(http.MethodGet, models.PathHealth, nil)
		r.RemoteAddr = remote
		rec := httptest.NewRecorder()
		health(rec, r)
		answered := testutil.IsAnswer(rec, apperr.HealthUnavailable)
		if !answered && !testutil.IsAnswer(rec, apperr.RouteNotFound) {
			t.Fatalf("peer %q: answered %d %q", remote, rec.Code, rec.Body.String())
		}
		if answered && !realLoopback(remote) {
			t.Fatalf("the non-loopback peer %q was answered", remote)
		}
		if addrPort, err := netip.ParseAddrPort(remote); err == nil && addrPort.Addr().Zone() == "" &&
			addrPort.Addr().Unmap().IsLoopback() && addrPort.String() == remote && !answered {
			t.Fatalf("the loopback peer %q was refused", remote)
		}
	})
}
