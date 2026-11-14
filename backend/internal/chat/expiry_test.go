package chat

import (
	"testing"
	"time"
)

// expiryAfter: an invite's or a note's expiry is the first whole hour at or after now + ttl
// (UTC), so it never tells the creation second and never cuts the TTL short.
func TestExpiryAfter(t *testing.T) {
	base := time.Unix(fuzzNowUnix, 0).UTC() // on a whole hour
	cases := []struct {
		now  time.Time
		ttl  time.Duration
		want time.Time
	}{
		{base, 24 * time.Hour, base.Add(24 * time.Hour)},
		{base.Add(time.Nanosecond), 24 * time.Hour, base.Add(25 * time.Hour)},
		{base.Add(59*time.Minute + 59*time.Second), time.Minute, base.Add(2 * time.Hour)},
		{base.Add(17 * time.Second), 60 * time.Second, base.Add(time.Hour)},
		{base.Add(-time.Second), time.Second, base},
	}
	for _, c := range cases {
		if got := expiryAfter(c.now, c.ttl); !got.Equal(c.want) {
			t.Errorf("expiryAfter(%v, %v) = %v, want %v", c.now, c.ttl, got, c.want)
		}
	}
	// Every second of an hour, in another zone too: on the hour, at least the TTL, under one hour more
	zone := time.FixedZone("UTC+0530", 5*3600+1800)
	for offset := time.Duration(0); offset < time.Hour; offset += time.Second {
		for _, now := range []time.Time{base.Add(offset), base.Add(offset).In(zone)} {
			ttl := 86400 * time.Second
			got := expiryAfter(now, ttl)
			if got.Location() != time.UTC || !got.Truncate(expiryGranularity).Equal(got) ||
				got.Before(now.Add(ttl)) || !got.Before(now.Add(ttl+expiryGranularity)) {
				t.Fatalf("expiryAfter(%v, %v) = %v", now, ttl, got)
			}
		}
	}
}
