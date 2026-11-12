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
	maxServerURLChars  = 256
	maxHostLabelChars  = 63
	maxPort            = 65535
	envAllProxy        = "ALL_PROXY"
	envAllProxyLower   = "all_proxy"
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
	origin := strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host)
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

// proxyFunc honours HTTPS_PROXY / HTTP_PROXY / NO_PROXY (http.ProxyFromEnvironment) and, when
// those name no proxy, ALL_PROXY (curl's variable, which net/http does not read): so
// ALL_PROXY=socks5h://127.0.0.1:9050 reaches an onion service. Loopback is never proxied.
func proxyFunc() (func(*http.Request) (*url.URL, error), error) {
	all, err := allProxy()
	if err != nil {
		return nil, err
	}
	return func(req *http.Request) (*url.URL, error) {
		proxy, err := http.ProxyFromEnvironment(req)
		if err != nil || proxy != nil {
			return proxy, err
		}
		if _, loopback := loopbackHosts[strings.ToLower(req.URL.Hostname())]; loopback {
			return nil, nil
		}
		return all, nil
	}, nil
}

// allProxy parses ALL_PROXY (or all_proxy); unset is no proxy, malformed is refused.
func allProxy() (*url.URL, error) {
	raw := os.Getenv(envAllProxy)
	if raw == "" {
		raw = os.Getenv(envAllProxyLower)
	}
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

// requireProxyForOnion refuses an onion server that no configured proxy would reach.
func requireProxyForOnion(origin string, proxy func(*http.Request) (*url.URL, error)) error {
	if !isOnionHost(origin) {
		return nil
	}
	req, err := http.NewRequest(http.MethodGet, origin+pathMe, nil)
	if err != nil {
		return fail(CodeServerURL, err)
	}
	via, err := proxy(req)
	if err != nil {
		return fail(CodeProxy, err)
	}
	if via == nil {
		return fail(CodeOnionProxy, nil)
	}
	return nil
}
