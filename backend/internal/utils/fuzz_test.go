package utils

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"elyrn/internal/config"
	"elyrn/internal/cryptoengine"
)

// Fuzz targets for the parsers, scrubbers and bounds of this package. Run one with:
// go test -tags test -run '^$' -fuzz '^FuzzScrubPeerAddresses$' -fuzztime 60s ./internal/utils

const (
	// maxFuzzLine bounds one fuzzed log line: the oracle parses every substring up to maxIPLiteral
	maxFuzzLine = 256
	// maxIPLiteral is longer than any textual IP address with a short zone id
	maxIPLiteral = 64
	// throttleOpBytes: key (2 bytes, big-endian) and clock step (1 signed byte) per operation
	throttleOpBytes = 3
	// throttleStep scales one signed clock-step byte, so a few steps cross LogWindow either way
	throttleStep = 7 * time.Second
	// maxDecodeSize bounds the size DecodeExact is asked for
	maxDecodeSize = 512
)

// throttleStart is the fuzzed throttle clock's origin (any fixed instant)
var throttleStart = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// nastySeeds are the hostile shapes every string target starts from (written as escapes: ST1018).
var nastySeeds = []string{"", "\x00", "\xff\xfe\xfd", "\u202e\u200b\ufeff", strings.Repeat("A", 4096), " , ,", ",,,", "\r\n"}

func addSeeds(f *testing.F, seeds ...string) {
	for _, seed := range append(seeds, nastySeeds...) {
		f.Add(seed)
	}
}

// ipLiteralIn is the scrubber's oracle, written without its regular expression: the first
// substring of s that net/netip parses as an address (any spelling, any zone).
func ipLiteralIn(s string) (string, bool) {
	for i := 0; i < len(s); i++ {
		if !isHexOrColon(s[i]) {
			continue // every textual address starts with a hex digit or a colon
		}
		for j := i + 1; j <= len(s) && j-i <= maxIPLiteral; j++ {
			if _, err := netip.ParseAddr(s[i:j]); err == nil {
				return s[i:j], true
			}
		}
	}
	return "", false
}

func isHexOrColon(b byte) bool {
	return b == ':' || (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')
}

// FuzzScrubPeerAddresses: no IP address of any spelling survives in a library line the
// logger writes (zero identifiers), whatever surrounds it.
func FuzzScrubPeerAddresses(f *testing.F) {
	addSeeds(f,
		"http: TLS handshake error from 192.0.2.7:4000: EOF",
		"http: TLS handshake error from [2001:db8::7]:4000: EOF",
		"accept tcp [::]:8080: use of closed network connection",
		"x192.0.2.1y", "fe80::1%eth0 failed", "[fe80::1%eth0]:443", "::ffff:192.0.2.1",
		"1:2:3:4:5:6:7:8::1", "::1.2.3.4.5", "2001:db8::1:443", "12345::1", "1.2.3.4::1", "10.0.0.1:65536:1")
	f.Fuzz(func(t *testing.T, line string) {
		if len(line) > maxFuzzLine {
			return
		}
		out := scrubPeerAddresses(line)
		if address, found := ipLiteralIn(out); found {
			t.Fatalf("address %q survived scrubbing %q: %q", address, line, out)
		}
	})
}

// resetThrottles empties the process-wide throttle table (one fuzz iteration's state).
func resetThrottles() {
	throttleMu.Lock()
	defer throttleMu.Unlock()
	throttles = make(map[string]*throttleWindow)
}

// throttleModel is the documented flood bound, per key: LogBurst lines per window, a window
// restarted by LogWindow passing or by the clock going back, drops reported once.
type throttleModel struct {
	start               time.Time
	written, suppressed int
}

// FuzzAdmitLine drives the flood bound with arbitrary keys and clock steps (forward and back):
// at most LogBurst lines per key per window, every dropped line reported exactly once, and a
// table that never grows past maxThrottleKeys.
func FuzzAdmitLine(f *testing.F) {
	f.Add([]byte{0, 1, 0})
	f.Add([]byte{0, 1, 0, 0, 1, 0, 0, 1, 9, 0, 1, 0x80})
	f.Add(make([]byte, throttleOpBytes*(LogBurst+5)))
	f.Fuzz(func(t *testing.T, program []byte) {
		resetThrottles()
		defer resetThrottles()
		model := make(map[string]*throttleModel)
		now := throttleStart
		for op := 0; op+throttleOpBytes <= len(program); op += throttleOpBytes {
			key := "fuzz/" + strconv.Itoa(int(binary.BigEndian.Uint16(program[op:]))%(2*maxThrottleKeys))
			now = now.Add(time.Duration(int8(program[op+2])) * throttleStep)
			ok, dropped := admitLine(key, now)

			m, known := model[key]
			if !known {
				if len(model) >= maxThrottleKeys {
					if ok || dropped != 0 {
						t.Fatalf("key beyond the table bound admitted (ok=%v dropped=%d)", ok, dropped)
					}
					continue
				}
				m = &throttleModel{start: now}
				model[key] = m
			}
			wantDropped := 0
			if now.Sub(m.start) >= LogWindow || now.Before(m.start) {
				wantDropped = m.suppressed
				*m = throttleModel{start: now}
			}
			wantOK := m.written < LogBurst
			if wantOK {
				m.written++
			} else {
				m.suppressed++
			}
			if ok != wantOK || dropped != wantDropped || m.written > LogBurst {
				t.Fatalf("op %d key %s: ok=%v dropped=%d, want ok=%v dropped=%d", op/throttleOpBytes, key, ok, dropped, wantOK, wantDropped)
			}
		}
		throttleMu.Lock()
		size := len(throttles)
		throttleMu.Unlock()
		if size > maxThrottleKeys || size != len(model) {
			t.Fatalf("throttle table holds %d keys, model %d (bound %d)", size, len(model), maxThrottleKeys)
		}
	})
}

// FuzzClockSteady: readings whose wall and monotonic clocks moved together are steady for any
// gap (both readings monotonic, both wall-only, or one of each), and a zero previous reading
// always is; nothing panics on extreme times.
func FuzzClockSteady(f *testing.F) {
	f.Add(int64(0), int64(0), int64(0))
	f.Add(int64(1<<62), int64(999999999), int64(1<<62))
	f.Add(int64(-1<<62), int64(-1), int64(-1<<62))
	f.Add(int64(1735689600), int64(5), int64(time.Hour))
	f.Fuzz(func(t *testing.T, sec, nsec, gap int64) {
		monotonic := time.Now()
		wall := time.Unix(sec, nsec)
		d := time.Duration(gap)
		for _, pair := range [][2]time.Time{
			{monotonic.Add(d), monotonic},
			{wall.Add(d), wall},
			{wall, monotonic},
			{monotonic, wall},
		} {
			if !ClockSteady(pair[0], pair[1]) {
				t.Fatalf("a consistent pair was flagged: %v / %v", pair[0], pair[1])
			}
		}
		if !ClockSteady(wall, time.Time{}) {
			t.Fatal("a zero previous reading was flagged")
		}
	})
}

// listEntries mirrors what an operator sees: comma-separated, trimmed, empty entries counted.
func listEntries(raw string) []string {
	parts := strings.Split(raw, listSeparator)
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

// expectListError: a refusal is ErrListEntry at a real position whose entry is non-empty, and
// its text is the position alone (the entry is never echoed).
func expectListError(t *testing.T, raw string, err error) int {
	t.Helper()
	var entryErr ErrListEntry
	if !errors.As(err, &entryErr) {
		t.Fatalf("%q refused with %v, not ErrListEntry", raw, err)
	}
	parts := listEntries(raw)
	if entryErr.Position < 1 || entryErr.Position > len(parts) || parts[entryErr.Position-1] == "" {
		t.Fatalf("%q refused at position %d", raw, entryErr.Position)
	}
	if err.Error() != "entry "+strconv.Itoa(entryErr.Position)+" is malformed" {
		t.Fatalf("%q refused with the text %q", raw, err.Error())
	}
	return entryErr.Position
}

// FuzzParseProxyList: every non-empty entry is kept (an address or a range), none silently
// dropped; a refusal names the first malformed entry by position only.
func FuzzParseProxyList(f *testing.F) {
	addSeeds(f, "10.0.0.1", "10.0.0.0/8, ::1, fd00::/8", "10.0.0.1,,192.168.0.0/16", "10.0.0.1/33",
		"fe80::1%eth0", "::ffff:10.0.0.1", "010.0.0.1", "10.0.0.1 , 10.0.0.256", "0.0.0.0/0",
		"10.0.0.0/7", "2001:db8::/15", "2001::/16", "::/0", "::ffff:0:0/96", "::ffff:10.0.0.0/104")
	f.Fuzz(func(t *testing.T, raw string) {
		ips, nets, err := ParseProxyList(raw)
		parts := listEntries(raw)
		good := func(entry string) bool {
			if net.ParseIP(entry) != nil {
				return true
			}
			if _, _, cidrErr := net.ParseCIDR(entry); cidrErr != nil {
				return false
			}
			return proxyRangeWideEnoughOracle(entry)
		}
		if err != nil {
			position := expectListError(t, raw, err)
			for _, entry := range parts[:position-1] {
				if entry != "" && !good(entry) {
					t.Fatalf("%q: an earlier malformed entry went unreported", raw)
				}
			}
			if good(parts[position-1]) {
				t.Fatalf("%q: a well-formed entry was reported at %d", raw, position)
			}
			return
		}
		nonEmpty := 0
		for _, entry := range parts {
			if entry != "" {
				nonEmpty++
			}
		}
		if len(ips)+len(nets) != nonEmpty {
			t.Fatalf("%q: %d entries but %d addresses and %d ranges kept", raw, nonEmpty, len(ips), len(nets))
		}
		for _, n := range nets {
			if n == nil || n.IP == nil || n.Mask == nil {
				t.Fatalf("%q: an empty range was kept", raw)
			}
		}
	})
}

// proxyRangeWideEnoughOracle restates the minimum proxy prefix from the text of a range that
// net.ParseCIDR accepts, through net/netip instead of net.IPNet: an IPv4 range needs at least
// MinProxyPrefixIPv4 bits, an IPv6 range over IPv4-mapped addresses the same after its 96, any
// other IPv6 range MinProxyPrefixIPv6.
func proxyRangeWideEnoughOracle(entry string) bool {
	slash := strings.LastIndexByte(entry, '/')
	addr, addrErr := netip.ParseAddr(entry[:slash])
	length, lengthErr := strconv.Atoi(entry[slash+1:])
	if addrErr != nil || lengthErr != nil {
		return false
	}
	masked, maskErr := addr.Prefix(length)
	if maskErr != nil {
		return false
	}
	switch {
	case addr.Is4():
		return length >= MinProxyPrefixIPv4
	case masked.Addr().Is4In6():
		return length-96 >= MinProxyPrefixIPv4
	default:
		return length >= MinProxyPrefixIPv6
	}
}

// forbiddenInOrigin can never appear after "scheme://" in a bare origin
const forbiddenInOrigin = "/?#@*\\ \t"

// FuzzParseOrigins: an accepted list holds only bare origins, exactly as listed: http or https,
// a host, no path, query, fragment, credentials or wildcard.
func FuzzParseOrigins(f *testing.F) {
	addSeeds(f, "http://localhost", "https://elyrn.example, http://localhost:3000",
		"https://*.example", "https://a.example/", "https://user@a.example", "https://a.example?x",
		"https://a.example#x", "ftp://a.example", "https://a.example:99999", "HTTPS://A.EXAMPLE",
		"https://[::1]:443", "http://localhost:3000.evil.example", "https://a.example,,")
	f.Fuzz(func(t *testing.T, raw string) {
		origins, err := ParseOrigins(raw)
		if errors.Is(err, ErrEmptyList) {
			for _, entry := range listEntries(raw) {
				if entry != "" {
					t.Fatalf("%q: reported empty", raw)
				}
			}
			return
		}
		if err != nil {
			expectListError(t, raw, err)
			return
		}
		listed := make(map[string]struct{})
		for _, entry := range listEntries(raw) {
			listed[entry] = struct{}{}
		}
		for origin := range origins {
			if _, ok := listed[origin]; !ok {
				t.Fatalf("%q: origin %q is not one of the entries", raw, origin)
			}
			scheme, rest, found := strings.Cut(origin, "://")
			if !found || (scheme != "http" && scheme != "https") || rest == "" || strings.ContainsAny(rest, forbiddenInOrigin) {
				t.Fatalf("%q: accepted the non-origin %q", raw, origin)
			}
			if u, parseErr := url.Parse(origin); parseErr != nil || u.Host != rest {
				t.Fatalf("%q: accepted %q, which is not scheme://host", raw, origin)
			}
		}
	})
}

// FuzzDecodeExact: whatever is accepted is canonical base64url of exactly the asked size.
func FuzzDecodeExact(f *testing.F) {
	for _, size := range []int{1, 16, 32, 37} {
		f.Add(base64.RawURLEncoding.EncodeToString(make([]byte, size)), size)
	}
	f.Add("AAB", 2)
	f.Add("AA==", 1)
	f.Add("AA\nAA", 3)
	f.Add("", 0)
	f.Add("A", -1)
	f.Fuzz(func(t *testing.T, encoded string, size int) {
		if size > maxDecodeSize || size < -maxDecodeSize {
			return
		}
		raw, ok := DecodeExact(encoded, size)
		if ok && (size <= 0 || len(raw) != size || base64.RawURLEncoding.EncodeToString(raw) != encoded) {
			t.Fatalf("%q accepted for size %d", encoded, size)
		}
	})
}

// FuzzFilePartCount: for every file size the settings allow, the parts hold the file and one
// part fewer would not.
func FuzzFilePartCount(f *testing.F) {
	for _, size := range []int64{1, FilePartBytes - 1, FilePartBytes, FilePartBytes + 1, config.MaxFileBytesBound} {
		f.Add(size)
	}
	f.Fuzz(func(t *testing.T, size int64) {
		if size < 1 || size > config.MaxFileBytesBound {
			return
		}
		parts := FilePartCount(size)
		if parts < 1 || parts*FilePartBytes < size || (parts-1)*FilePartBytes >= size {
			t.Fatalf("a file of %d bytes takes %d parts", size, parts)
		}
	})
}

// roomBlobSeed builds a structurally valid room blob: magic, version, wraps and a padded frame.
func roomBlobSeed(magic string, wraps, frame int) string {
	raw := make([]byte, RoomHeaderBytes+wraps*RoomWrapBytes+frame+cryptoengine.GCMTagSize)
	copy(raw, magic)
	raw[len(magic)] = RoomVersion
	raw[RoomHeaderBytes-1] = byte(wraps)
	for i := RoomDigestOffset; i < RoomHeaderBytes-1; i++ {
		raw[i] = byte(i) // a recognisable digest
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

// roomMagics are the two blob kinds ParseRoomBlob is called with
var roomMagics = [...]string{RoomMessageMagic, RoomNoteMagic}

// FuzzParseRoomBlob: an accepted blob is canonical, has the asked magic and version, 1..maxWraps
// wraps, a padded frame, and the digest it reports is the header's; acceptance is monotonic in
// maxWraps (a blob a smaller room takes, a larger one takes too).
func FuzzParseRoomBlob(f *testing.F) {
	for _, seed := range []struct {
		blob        string
		magic, maxW int
	}{
		{roomBlobSeed(RoomMessageMagic, 2, minFrameBytes), 0, 2},
		{roomBlobSeed(RoomNoteMagic, 1, maxFrameBytes), 1, 1},
		{roomBlobSeed(RoomMessageMagic, 3, minFrameBytes), 0, 2},
		{roomBlobSeed(RoomMessageMagic, 1, minFrameBytes+1), 0, 4},
		{roomBlobSeed(RoomNoteMagic, 1, minFrameBytes), 0, 1},
		{"", 0, 1},
	} {
		f.Add(seed.blob, seed.magic, seed.maxW)
	}
	f.Fuzz(func(t *testing.T, encoded string, magicIndex, maxWraps int) {
		magic := roomMagics[uint(magicIndex)%uint(len(roomMagics))]
		blob, ok := ParseRoomBlob(encoded, magic, maxWraps)
		if !ok {
			return
		}
		raw, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
		if err != nil || base64.RawURLEncoding.EncodeToString(raw) != encoded || len(raw) < RoomHeaderBytes {
			t.Fatalf("accepted a non-canonical blob %q", encoded)
		}
		frame := len(raw) - RoomHeaderBytes - blob.Wraps*RoomWrapBytes - cryptoengine.GCMTagSize
		if string(raw[:len(magic)]) != magic || raw[len(magic)] != RoomVersion || blob.Wraps != int(raw[RoomHeaderBytes-1]) ||
			blob.Wraps < 1 || blob.Wraps > maxWraps || !isPaddedFrame(frame) ||
			string(blob.Digest) != string(raw[RoomDigestOffset:RoomHeaderBytes-1]) {
			t.Fatalf("accepted a malformed blob (%d wraps, frame %d)", blob.Wraps, frame)
		}
		for larger := maxWraps; larger <= config.MaxRoomMembersBound; larger++ {
			if _, ok := ParseRoomBlob(encoded, magic, larger); !ok {
				t.Fatalf("accepted at %d wraps but refused at %d", maxWraps, larger)
			}
		}
	})
}
