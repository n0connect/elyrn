package utils

import (
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// listSeparator separates the entries of TRUSTED_PROXIES and ALLOWED_ORIGINS
const listSeparator = ","

// ErrListEntry reports a malformed list entry by its position only (1-based): the entry's text
// is never echoed, so a log line cannot carry what an operator mistyped (a secret pasted into
// the wrong variable).
type ErrListEntry struct{ Position int }

func (e ErrListEntry) Error() string {
	return "entry " + strconv.Itoa(e.Position) + " is malformed"
}

// ErrEmptyList: the list holds no entry at all
var ErrEmptyList = errors.New("no entry")

// entries splits a comma-separated list, trimmed; empty entries are skipped but still counted,
// so a reported position matches what the operator sees.
func entries(raw string, each func(position int, entry string) error) error {
	for i, entry := range strings.Split(raw, listSeparator) {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if err := each(i+1, entry); err != nil {
			return err
		}
	}
	return nil
}

// ParseProxyList parses TRUSTED_PROXIES: single addresses and CIDR ranges. Any malformed entry
// is an error: a silently dropped proxy would put every user behind it in one rate-limit bucket.
func ParseProxyList(raw string) (ips []net.IP, nets []*net.IPNet, err error) {
	err = entries(raw, func(position int, entry string) error {
		if ip := net.ParseIP(entry); ip != nil {
			ips = append(ips, ip)
			return nil
		}
		if _, cidr, cidrErr := net.ParseCIDR(entry); cidrErr == nil {
			nets = append(nets, cidr)
			return nil
		}
		return ErrListEntry{Position: position}
	})
	return ips, nets, err
}

// originSchemes are the schemes a browser origin may carry here (http for localhost and onion)
var originSchemes = map[string]struct{}{"http": {}, "https": {}}

// ParseOrigins parses ALLOWED_ORIGINS into the exact set of origins it lists. Each entry must
// be a bare origin, scheme://host[:port], exactly as a browser sends it in the Origin header:
// no wildcard, path, query, fragment or credentials.
func ParseOrigins(raw string) (map[string]struct{}, error) {
	origins := make(map[string]struct{})
	err := entries(raw, func(position int, entry string) error {
		u, parseErr := url.Parse(entry)
		if parseErr != nil {
			return ErrListEntry{Position: position}
		}
		_, schemeOK := originSchemes[u.Scheme]
		if !schemeOK || u.Host == "" || u.User != nil || u.Path != "" ||
			u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || strings.Contains(entry, "*") ||
			u.Scheme+"://"+u.Host != entry {
			return ErrListEntry{Position: position}
		}
		origins[entry] = struct{}{}
		return nil
	})
	if err == nil && len(origins) == 0 {
		err = ErrEmptyList
	}
	return origins, err
}
