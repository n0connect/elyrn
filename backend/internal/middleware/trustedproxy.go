package middleware

import (
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"elyrn/internal/config"
	"elyrn/internal/cryptoengine"
	"elyrn/internal/utils"
)

var (
	trustedProxyLogger = utils.NewLogger("TRUSTED_PROXY")
	trustedProxyOnce   sync.Once
	trustedProxyNets   []*net.IPNet
	trustedProxyIPs    []net.IP
)

// loadTrustedProxies parses TRUSTED_PROXIES once. Startup validation refuses a malformed list
// (E_CONFIG_INVALID); should one get here anyway, no proxy is trusted (fail closed) and the
// entry is never echoed.
func loadTrustedProxies() {
	trustedProxyOnce.Do(func() {
		ips, nets, err := utils.ParseProxyList(config.GetTrustedProxies())
		if err != nil {
			trustedProxyLogger.Error("TRUSTED_PROXIES is malformed (%v): no proxy is trusted", err)
			return
		}
		trustedProxyIPs, trustedProxyNets = ips, nets
		trustedProxyLogger.Info("Trusted proxies loaded: ips=%d cidrs=%d", len(trustedProxyIPs), len(trustedProxyNets))
	})
}

// LoadTrustedProxies parses TRUSTED_PROXIES now (at startup) instead of at the first request.
func LoadTrustedProxies() { loadTrustedProxies() }

// IsLoopbackPeer reports whether the request's direct TCP peer is a loopback address (the
// container's own healthcheck); forwarded headers are never consulted.
func IsLoopbackPeer(r *http.Request) bool {
	ip := parseRemoteIP(r.RemoteAddr)
	return ip != nil && ip.IsLoopback()
}

func isTrustedProxy(ip net.IP) bool {
	if ip == nil {
		return false
	}

	loadTrustedProxies()

	for _, trustedIP := range trustedProxyIPs {
		if trustedIP.Equal(ip) {
			return true
		}
	}
	for _, cidr := range trustedProxyNets {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

func parseRemoteIP(remoteAddr string) net.IP {
	if remoteAddr == "" {
		return nil
	}
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return net.ParseIP(remoteAddr)
	}
	return net.ParseIP(host)
}

// clientFromXFF walks X-Forwarded-For from the right. Each trusted proxy appends the peer it
// saw, so the first entry from the right that is not itself a trusted proxy is the client;
// anything further left was supplied by the client and is never believed.
func clientFromXFF(xff string) net.IP {
	if xff == "" {
		return nil
	}
	parts := strings.Split(xff, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		ip := net.ParseIP(strings.TrimSpace(parts[i]))
		if ip == nil || isTrustedProxy(ip) {
			continue
		}
		return ip
	}
	return nil
}

// ClientIP returns the real client IP based on trusted proxy configuration.
// Forwarded headers are only trusted when the direct peer is a trusted proxy.
func ClientIP(r *http.Request) string {
	if r == nil {
		return ""
	}

	remoteIP := parseRemoteIP(r.RemoteAddr)
	if isTrustedProxy(remoteIP) {
		if ip := clientFromXFF(r.Header.Get("X-Forwarded-For")); ip != nil {
			return ip.String()
		}
		if ip := net.ParseIP(strings.TrimSpace(r.Header.Get("X-Real-IP"))); ip != nil && !isTrustedProxy(ip) {
			return ip.String()
		}
	}

	if remoteIP != nil {
		return remoteIP.String()
	}
	return ""
}

const (
	// ipv6SubscriberBits is the prefix one IPv6 subscriber controls (RFC 6177 assigns at least a /64)
	ipv6SubscriberBits = 64
	// ipv6AddressBits is the full length of an IPv6 address
	ipv6AddressBits = 8 * net.IPv6len
	// torCircuitPrefixBits: tor's circuit addresses share one /64 and differ in the low bits
	torCircuitPrefixBits = 64
	// unknownNetwork groups every address that does not parse into one bucket
	unknownNetwork = "unknown"
	// clientKeySecretBytes keys HMAC-SHA256 with a full digest's worth of entropy
	clientKeySecretBytes = cryptoengine.SHA256Size
	// clientKeyBytes truncates the HMAC to 128 bits: collision-free for any realistic bucket count
	clientKeyBytes = 16
)

// ipv6SubscriberSuffix marks a reduced IPv6 address as the subscriber prefix ("/64")
var ipv6SubscriberSuffix = "/" + strconv.Itoa(ipv6SubscriberBits)

// torCircuitPrefix holds the addresses tor gives onion-service clients
// (HiddenServiceExportCircuitID haproxy): one per circuit, the circuit ID in the low 32 bits.
// They reach us only through nginx's onion listener, which accepts the tor container alone.
var torCircuitPrefix = &net.IPNet{IP: net.ParseIP("fc00:dead:beef:4dad::"), Mask: net.CIDRMask(torCircuitPrefixBits, ipv6AddressBits)}

// clientNetwork reduces an address to what one client controls: the IPv4 address itself,
// the IPv6 /64, or a single Tor circuit. Rate limits keyed on full IPv6 addresses are
// bypassed by rotation; grouping Tor's /64 would put every onion user in one bucket.
func clientNetwork(raw string) string {
	ip := net.ParseIP(raw)
	if ip == nil {
		return unknownNetwork
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	if torCircuitPrefix.Contains(ip) {
		return ip.String()
	}
	return ip.Mask(net.CIDRMask(ipv6SubscriberBits, ipv6AddressBits)).String() + ipv6SubscriberSuffix
}

// IsRequestHTTPS returns true if the request is HTTPS, considering trusted proxy headers.
func IsRequestHTTPS(r *http.Request) bool {
	if r == nil {
		return false
	}
	if r.TLS != nil {
		return true
	}
	remoteIP := parseRemoteIP(r.RemoteAddr)
	if !isTrustedProxy(remoteIP) {
		return false
	}
	proto := strings.TrimSpace(r.Header.Get("X-Forwarded-Proto"))
	return strings.EqualFold(proto, "https")
}

// clientKeySecret is generated per process and never persisted, so rate-limit buckets
// hold HMAC(ip) values that cannot be reversed even from a memory dump.
var (
	clientKeyOnce   sync.Once
	clientKeySecret []byte
	clientKeyErr    error
)

// ClientKey returns an opaque, per-boot pseudonym for the client's network (IPv4 address or
// IPv6 /64). Rate limiters key on this instead of the raw IP. A CSPRNG or HMAC failure is
// returned so the caller answers 500: a panic inside a request is recovered by net/http, so it
// would not abort the process (RULES.md §1.3) and would only drop the connection. A failed
// secret draw is remembered, so no key is ever computed without a secret.
func ClientKey(r *http.Request) (string, error) {
	clientKeyOnce.Do(func() {
		clientKeySecret, clientKeyErr = cryptoengine.RandomBytes(clientKeySecretBytes)
	})
	if clientKeyErr != nil {
		return "", fmt.Errorf("client key secret: %w", clientKeyErr)
	}
	mac, err := cryptoengine.HMACSHA256(clientKeySecret, []byte(clientNetwork(ClientIP(r))))
	if err != nil {
		return "", fmt.Errorf("client key: %w", err)
	}
	return hex.EncodeToString(mac[:clientKeyBytes]), nil
}
