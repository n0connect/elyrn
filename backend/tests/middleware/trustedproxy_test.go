package middleware

import (
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strconv"
	"testing"

	"elyrn/internal/middleware"
	"elyrn/internal/utils"
	"elyrn/tests/testutil"
)

func TestClientIP_UntrustedProxy_IgnoresForwardedHeaders(t *testing.T) {
	testutil.SetupTestEnv(t)
	defer testutil.TeardownTestEnv(t)

	middleware.ResetTrustedProxiesForTesting()

	req := httptest.NewRequest("GET", "/api/v2/conversations", nil)
	req.RemoteAddr = "203.0.113.10:12345"
	req.Header.Set("X-Forwarded-For", "198.51.100.20")
	req.Header.Set("X-Real-IP", "198.51.100.30")

	ip := middleware.ClientIP(req)
	if ip != "203.0.113.10" {
		t.Errorf("ClientIP() = %q, want %q", ip, "203.0.113.10")
	}
}

func TestClientIP_TrustedProxy_UsesForwardedHeaders(t *testing.T) {
	testutil.SetupTestEnv(t)
	defer testutil.TeardownTestEnv(t)

	t.Setenv("TRUSTED_PROXIES", "203.0.113.0/24")
	middleware.ResetTrustedProxiesForTesting()

	req := httptest.NewRequest("GET", "/api/v2/conversations", nil)
	req.RemoteAddr = "203.0.113.10:12345"
	req.Header.Set("X-Forwarded-For", "198.51.100.20, 203.0.113.10")

	ip := middleware.ClientIP(req)
	if ip != "198.51.100.20" {
		t.Errorf("ClientIP() = %q, want %q", ip, "198.51.100.20")
	}
}

// X-Forwarded-For is read from the right: each trusted proxy appends the address it saw,
// so the first untrusted hop from the right is the only entry the chain vouches for.
// Everything left of it is whatever the client chose to send.
func TestClientIP_TrustedProxy_TakesRightmostUntrustedHop(t *testing.T) {
	testutil.SetupTestEnv(t)
	defer testutil.TeardownTestEnv(t)
	t.Setenv("TRUSTED_PROXIES", "203.0.113.0/24")
	middleware.ResetTrustedProxiesForTesting()
	t.Cleanup(middleware.ResetTrustedProxiesForTesting)

	cases := map[string]string{
		"1.2.3.4, 198.51.100.20":                    "198.51.100.20", // spoofed entry first, real client appended
		"198.51.100.20, 203.0.113.7":                "198.51.100.20", // two trusted proxies in a row
		"garbage, 198.51.100.20":                    "198.51.100.20",
		"198.51.100.99, 198.51.100.20, 203.0.113.7": "198.51.100.20",
		"203.0.113.7":                               "203.0.113.10", // nothing untrusted: the direct peer
	}
	for xff, want := range cases {
		req := httptest.NewRequest("GET", "/api/v2/me", nil)
		req.RemoteAddr = "203.0.113.10:12345"
		req.Header.Set("X-Forwarded-For", xff)
		if got := middleware.ClientIP(req); got != want {
			t.Errorf("XFF %q: ClientIP() = %q, want %q", xff, got, want)
		}
	}
}

// One IPv6 subscriber holds a whole /64; keying limits on the full address would let it
// rotate through 2^64 addresses. IPv4-mapped IPv6 is the same client as plain IPv4.
func TestClientKey_GroupsIPv6ByPrefix(t *testing.T) {
	testutil.SetupTestEnv(t)
	defer testutil.TeardownTestEnv(t)
	middleware.ResetTrustedProxiesForTesting()

	key := func(remote string) string {
		req := httptest.NewRequest("GET", "/api/v2/me", nil)
		req.RemoteAddr = remote
		return clientKey(t, req)
	}
	if key("[2001:db8:1:2::1]:443") != key("[2001:db8:1:2:ffff:ffff:ffff:9]:443") {
		t.Error("two addresses in one IPv6 /64 got different rate-limit keys")
	}
	if key("[2001:db8:1:2::1]:443") == key("[2001:db8:1:3::1]:443") {
		t.Error("different IPv6 /64 prefixes share a rate-limit key")
	}
	if key("198.51.100.7:1") == key("198.51.100.8:1") {
		t.Error("different IPv4 addresses share a rate-limit key")
	}
	if key("[::ffff:198.51.100.7]:1") != key("198.51.100.7:1") {
		t.Error("IPv4-mapped IPv6 and IPv4 for the same client got different keys")
	}
}

// Behind the onion service every client arrives from tor, which gives each circuit its own
// address inside fc00:dead:beef:4dad::/64 (HiddenServiceExportCircuitID haproxy). Grouping
// that /64 like one subscriber's prefix would put every Tor user in a single bucket.
func TestClientKey_SeparatesTorCircuits(t *testing.T) {
	testutil.SetupTestEnv(t)
	defer testutil.TeardownTestEnv(t)
	t.Setenv("TRUSTED_PROXIES", "203.0.113.0/24")
	middleware.ResetTrustedProxiesForTesting()
	t.Cleanup(middleware.ResetTrustedProxiesForTesting)

	viaProxy := func(client string) string {
		req := httptest.NewRequest("GET", "/api/v2/me", nil)
		req.RemoteAddr = "203.0.113.10:12345"
		req.Header.Set("X-Forwarded-For", client)
		return clientKey(t, req)
	}
	circuit := viaProxy("fc00:dead:beef:4dad::1:2c3d")
	if circuit == viaProxy("fc00:dead:beef:4dad::1:2c3e") {
		t.Error("two Tor circuits share a rate-limit key")
	}
	if again := viaProxy("fc00:dead:beef:4dad::1:2c3d"); again != circuit {
		t.Error("one Tor circuit got two rate-limit keys")
	}
	// Only tor's own prefix is per-address; the neighbouring /64 is still one subscriber
	if viaProxy("fc00:dead:beef:4dae::1") != viaProxy("fc00:dead:beef:4dae::2") {
		t.Error("an ordinary IPv6 /64 is no longer grouped")
	}
}

// clientKey is middleware.ClientKey for tests: a key the server could not compute fails the test.
func clientKey(t *testing.T, r *http.Request) string {
	t.Helper()
	key, err := middleware.ClientKey(r)
	if err != nil {
		t.Fatalf("ClientKey: %v", err)
	}
	return key
}

// A trusted range wider than /8 (IPv4) or /16 (IPv6) lets addresses no operator runs proxies in
// name any client: a /0 lets the whole internet choose its rate-limit bucket. Such a list is
// malformed, so the backend trusts no proxy (fail closed) and startup refuses it; a range at the
// bound, and every single address, is kept. An IPv6 range over IPv4-mapped addresses matches
// plain IPv4 clients and is held to the IPv4 bound after its 96 mapping bits.
func TestTrustedProxies_RefuseRangesWiderThanTheFamilyBound(t *testing.T) {
	for _, wide := range []string{"0.0.0.0/0", "10.0.0.0/7", "128.0.0.0/1", "::/0", "2001:db8::/15", "fd00::/8",
		"::ffff:0:0/96", "::ffff:0.0.0.0/103", "192.0.2.1, 0.0.0.0/0"} {
		if _, _, err := utils.ParseProxyList(wide); err == nil {
			t.Errorf("TRUSTED_PROXIES=%q accepted", wide)
		}
	}
	for _, narrow := range []string{"10.0.0.0/8", "2001:db8::/16", "::ffff:10.0.0.0/104", "203.0.113.0/24",
		"172.29.73.10", "2001:db8::/128"} {
		if _, _, err := utils.ParseProxyList(narrow); err != nil {
			t.Errorf("TRUSTED_PROXIES=%q refused: %v", narrow, err)
		}
	}

	testutil.SetupTestEnv(t)
	defer testutil.TeardownTestEnv(t)
	t.Cleanup(middleware.ResetTrustedProxiesForTesting)
	for _, wide := range []string{"0.0.0.0/0", "::ffff:0:0/96"} {
		t.Setenv("TRUSTED_PROXIES", wide)
		middleware.ResetTrustedProxiesForTesting()
		req := httptest.NewRequest("GET", "/api/v2/me", nil)
		req.RemoteAddr = "203.0.113.10:12345"
		req.Header.Set("X-Forwarded-For", "198.51.100.20")
		if got := middleware.ClientIP(req); got != "203.0.113.10" {
			t.Errorf("TRUSTED_PROXIES=%s: a forwarded address was believed (ClientIP %q)", wide, got)
		}
	}
}

// edgeProxiesScript is nginx's renderer of EDGE_TRUSTED_PROXIES, from this package's directory
// (docker-compose.test.yaml mounts it at the same relative place for the containerized suite).
const edgeProxiesScript = "../../../nginx-edge-proxies.sh"

// nginx's EDGE_TRUSTED_PROXIES and the backend's TRUSTED_PROXIES refuse the same ranges: the
// script's minimum prefixes are the backend's (one rule, two readers).
func TestTrustedProxies_BoundsEqualNginxEdgeProxies(t *testing.T) {
	script, err := os.ReadFile(edgeProxiesScript)
	if err != nil {
		t.Fatalf("read %s: %v", edgeProxiesScript, err)
	}
	for name, want := range map[string]int{"IPV4_MIN_PREFIX": utils.MinProxyPrefixIPv4, "IPV6_MIN_PREFIX": utils.MinProxyPrefixIPv6} {
		found := regexp.MustCompile(`(?m)^`+name+`=(\d+)$`).FindAllSubmatch(script, -1)
		if len(found) != 1 {
			t.Errorf("nginx-edge-proxies.sh must set %s exactly once", name)
			continue
		}
		if got, _ := strconv.Atoi(string(found[0][1])); got != want {
			t.Errorf("nginx-edge-proxies.sh %s=%d, the backend's bound is %d", name, got, want)
		}
	}
}
