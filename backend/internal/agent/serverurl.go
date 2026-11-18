package agent

import (
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
)

// URLKind is how a server address may be reached; anything else is refused.
type URLKind int

const (
	URLRefused URLKind = iota
	URLHTTPS
	URLLoopbackHTTP // plain http to this machine only
	URLOnionHTTP    // plain http to an onion service: Tor encrypts and authenticates it
)

const (
	schemeHTTPS        = "https"
	schemeHTTP         = "http"
	onionSuffix        = ".onion"
	portSeparator      = ":"
	maxServerURLChars  = 256
	maxHostLabelChars  = 63
	maxPort            = 65535
	envAllProxy        = "ALL_PROXY"
	envAllProxyLower   = "all_proxy"
	envHTTPSProxy      = "HTTPS_PROXY"
	envHTTPSProxyLower = "https_proxy"
	envHTTPProxy       = "HTTP_PROXY"
	envHTTPProxyLower  = "http_proxy"
	proxySchemeSOCKS5  = "socks5"
	proxySchemeSOCKS5H = "socks5h"
)

var (
	loopbackHosts = map[string]struct{}{"localhost": {}, "127.0.0.1": {}, "::1": {}}
	proxySchemes  = map[string]struct{}{proxySchemeSOCKS5: {}, proxySchemeSOCKS5H: {}, schemeHTTP: {}, schemeHTTPS: {}}
)

// ClassifyServerURL whitelists a server address: scheme, host and optional port only. It
// returns the canonical origin (lowercase, no trailing slash) and how it may be reached.
func ClassifyServerURL(raw string) (string, URLKind) {
	if len(raw) == 0 || len(raw) > maxServerURLChars {
		return "", URLRefused
	}
	u, err := url.Parse(raw)
	if err != nil || u.Opaque != "" || u.User != nil || u.RawQuery != "" || u.ForceQuery ||
		u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return "", URLRefused
	}
	host := strings.ToLower(u.Hostname())
	if !validHost(host) || !validPort(u.Port()) {
		return "", URLRefused
	}
	// An empty port ("host:") names the scheme's default one: it is dropped, so both spellings
	// give one origin (the identity file's server is compared with --server by that origin)
	origin := strings.ToLower(u.Scheme) + "://" + strings.TrimSuffix(strings.ToLower(u.Host), portSeparator)
	switch strings.ToLower(u.Scheme) {
	case schemeHTTPS:
		return origin, URLHTTPS
	case schemeHTTP:
		if _, ok := loopbackHosts[host]; ok {
			return origin, URLLoopbackHTTP
		}
		if strings.HasSuffix(host, onionSuffix) {
			return origin, URLOnionHTTP
		}
	}
	return "", URLRefused
}

// validHost accepts an IP literal or dot-separated labels of [a-z0-9-].
func validHost(host string) bool {
	if host == "" {
		return false
	}
	if net.ParseIP(host) != nil {
		return true
	}
	labels := strings.Split(host, ".")
	for _, label := range labels {
		if len(label) == 0 || len(label) > maxHostLabelChars || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
				return false
			}
		}
	}
	return true
}

func validPort(port string) bool {
	if port == "" {
		return true
	}
	if len(port) > len(strconv.Itoa(maxPort)) {
		return false
	}
	n, err := strconv.Atoi(port)
	return err == nil && n >= 1 && n <= maxPort && strconv.Itoa(n) == port
}

// isOnionHost reports whether origin's host is an onion service.
func isOnionHost(origin string) bool {
	u, err := url.Parse(origin)
	return err == nil && strings.HasSuffix(strings.ToLower(u.Hostname()), onionSuffix)
}

// proxyFor picks the proxy chooser for origin: an onion origin is reached through Tor only
// (onionProxy), every other origin (or none yet) by clearnetProxy's rules.
func proxyFor(origin string) (func(*http.Request) (*url.URL, error), error) {
	if origin != "" && isOnionHost(origin) {
		return onionProxy()
	}
	return clearnetProxy()
}

// onionProxy is the one route to an onion service: the socks5h:// proxy that ALL_PROXY (or
// all_proxy) names, for every request, whatever HTTP_PROXY, HTTPS_PROXY or NO_PROXY say: those are
// not read at all. net/http's ProxyFromEnvironment would hand a plain-http .onion request, the
// login body included, to an ordinary forward proxy (its vendored httpproxy returns HTTP_PROXY for
// any http URL that NO_PROXY does not match, before ALL_PROXY is ever consulted). socks5h, not
// socks5 or http: the name must reach Tor unresolved, and only Tor carries an onion address.
// Missing, malformed or of any other scheme, the agent refuses to start (E_AGENT_ONION_PROXY).
func onionProxy() (func(*http.Request) (*url.URL, error), error) {
	raw := allProxyValue()
	u, err := url.Parse(raw)
	if raw == "" || err != nil || len(raw) > maxServerURLChars || u.Scheme != proxySchemeSOCKS5H || u.Host == "" ||
		u.Opaque != "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return nil, fail(CodeOnionProxy, err)
	}
	return http.ProxyURL(u), nil
}

// clearnetProxy picks the proxy of each request as curl does, with one documented difference.
//   - HTTPS_PROXY (https requests) or HTTP_PROXY (http requests), upper or lower case, when set:
//     http.ProxyFromEnvironment decides, NO_PROXY and its matching included.
//   - Otherwise ALL_PROXY (curl's variable, which net/http does not read). NO_PROXY does NOT
//     apply to it: its matching lives in golang.org/x/net/http/httpproxy, a dependency this
//     program does not take and whose rules it will not copy. Only localhost, 127.0.0.1 and ::1
//     bypass ALL_PROXY.
//
// An onion origin never comes here (proxyFor). The environment is read once, as net/http itself
// caches it.
func clearnetProxy() (func(*http.Request) (*url.URL, error), error) {
	all, err := allProxy()
	if err != nil {
		return nil, err
	}
	schemeProxySet := map[string]bool{
		schemeHTTPS: envSet(envHTTPSProxy, envHTTPSProxyLower),
		schemeHTTP:  envSet(envHTTPProxy, envHTTPProxyLower),
	}
	return func(req *http.Request) (*url.URL, error) {
		if all == nil || schemeProxySet[strings.ToLower(req.URL.Scheme)] {
			return http.ProxyFromEnvironment(req)
		}
		if _, loopback := loopbackHosts[strings.ToLower(req.URL.Hostname())]; loopback {
			return nil, nil
		}
		return all, nil
	}, nil
}

// envSet reports whether any of the named environment variables is non-empty.
func envSet(names ...string) bool {
	for _, name := range names {
		if os.Getenv(name) != "" {
			return true
		}
	}
	return false
}

// allProxyValue is ALL_PROXY, or all_proxy when the first is unset or empty (curl's order).
func allProxyValue() string {
	if raw := os.Getenv(envAllProxy); raw != "" {
		return raw
	}
	return os.Getenv(envAllProxyLower)
}

// allProxy parses ALL_PROXY (or all_proxy) for a clearnet origin; unset is no proxy, malformed is
// refused.
func allProxy() (*url.URL, error) {
	raw := allProxyValue()
	if raw == "" {
		return nil, nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || len(raw) > maxServerURLChars {
		return nil, fail(CodeProxy, err)
	}
	if _, ok := proxySchemes[strings.ToLower(u.Scheme)]; !ok {
		return nil, fail(CodeProxy, nil)
	}
	return u, nil
}
