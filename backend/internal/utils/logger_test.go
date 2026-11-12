package utils

import (
	"testing"
	"time"
)

// admitLine allows LogBurst lines per key per window, counts the rest, and reports that count
// once with the first line of the next window.
func TestAdmitLineWindows(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	const key = "test/admit"
	for i := 0; i < LogBurst; i++ {
		if ok, dropped := admitLine(key, start); !ok || dropped != 0 {
			t.Fatalf("line %d refused inside the burst", i)
		}
	}
	for i := 0; i < 7; i++ {
		if ok, _ := admitLine(key, start.Add(time.Second)); ok {
			t.Fatal("a line beyond the burst was admitted")
		}
	}
	ok, dropped := admitLine(key, start.Add(LogWindow))
	if !ok || dropped != 7 {
		t.Fatalf("next window: ok=%v dropped=%d, want true 7", ok, dropped)
	}
	if _, dropped := admitLine(key, start.Add(LogWindow+time.Second)); dropped != 0 {
		t.Fatal("a drop count was reported twice")
	}
	// A clock set back starts a new window instead of silencing the key for good
	if ok, _ := admitLine(key, start.Add(-time.Hour)); !ok {
		t.Fatal("a clock set back silenced the key")
	}
}

// ClockSteady accepts readings whose wall and monotonic clocks moved together, and a first
// reading with nothing to compare. (A real jump needs the system clock moved; retention's own
// tests drive the same rules through clockTrusted.)
func TestClockSteady(t *testing.T) {
	prev := time.Now()
	if !ClockSteady(prev.Add(5*time.Minute), prev) || !ClockSteady(prev, time.Time{}) {
		t.Fatal("a steady clock was flagged")
	}
}
