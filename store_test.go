package main

import (
	"testing"
	"time"
)

func TestStoreUpsertActiveThenFinal(t *testing.T) {
	s := NewStore()

	base := time.Date(2021, 3, 4, 5, 6, 7, 0, time.UTC)

	// First realtime snapshot for a socket.
	s.Upsert(Session{ID: 42, Start: base, Active: true, RX: 100, TX: 5})

	if count, active, rx, tx := s.Stats(); count != 1 || active != 1 || rx != 100 || tx != 5 {
		t.Fatalf("after first snapshot: count/active/rx/tx = %d/%d/%d/%d", count, active, rx, tx)
	}
	if !s.HasActive() {
		t.Fatal("HasActive() = false, want true")
	}

	// A later snapshot updates counters in place, no new row.
	s.Upsert(Session{ID: 42, Start: base, Active: true, RX: 300, TX: 20})

	if count, _, rx, tx := s.Stats(); count != 1 || rx != 300 || tx != 20 {
		t.Fatalf("after update: count/rx/tx = %d/%d/%d, want 1/300/20", count, rx, tx)
	}

	// Final event flips Active to false and keeps last counters.
	s.Upsert(Session{ID: 42, Start: base, Active: false, RX: 500, TX: 30})

	count, active, rx, tx := s.Stats()
	if count != 1 || active != 0 || rx != 500 || tx != 30 {
		t.Fatalf("after final: count/active/rx/tx = %d/%d/%d/%d", count, active, rx, tx)
	}
	if s.HasActive() {
		t.Fatal("HasActive() = true after final, want false")
	}

	snap := s.Snapshot()
	if len(snap) != 1 || snap[0].ID != 42 || snap[0].Active {
		t.Fatalf("snapshot = %+v", snap)
	}
}

func TestStorePreservesInsertionOrder(t *testing.T) {
	s := NewStore()

	for _, id := range []uint64{3, 1, 2} {
		s.Upsert(Session{ID: id})
	}
	// Update must not reorder.
	s.Upsert(Session{ID: 1, RX: 9})

	snap := s.Snapshot()
	want := []uint64{3, 1, 2}

	if len(snap) != len(want) {
		t.Fatalf("snapshot len = %d, want %d", len(snap), len(want))
	}

	for i, id := range want {
		if snap[i].ID != id {
			t.Fatalf("snapshot[%d].ID = %d, want %d", i, snap[i].ID, id)
		}
	}
}

func TestStoreClear(t *testing.T) {
	s := NewStore()
	s.Upsert(Session{ID: 1, Active: true, RX: 10})
	s.Upsert(Session{ID: 2, RX: 20})
	_ = s.takeDirty()

	s.Clear()

	if count, active, rx, tx := s.Stats(); count != 0 || active != 0 || rx != 0 || tx != 0 {
		t.Fatalf("after clear: count/active/rx/tx = %d/%d/%d/%d", count, active, rx, tx)
	}
	if !s.takeDirty() {
		t.Fatal("Clear must mark the store dirty")
	}
}

func TestSessionFromEvent(t *testing.T) {
	now := time.Date(2021, 3, 4, 5, 6, 7, 0, time.UTC)
	dur := 1500 * time.Millisecond

	e := &Event{
		Skaddr:        0xdeadbeef,
		DurationNS:    uint64(dur),
		BytesReceived: 1234,
		BytesAcked:    5678,
		PID:           1000,
		Family:        2, // AF_INET
		SPort:         40268,
		DPort:         80,
		Active:        1,
		State:         1, // TCP_ESTABLISHED
		Proto:         6, // IPPROTO_TCP
	}
	e.SAddr = [16]byte{192, 168, 1, 10}
	e.DAddr = [16]byte{93, 184, 216, 34}

	sess := sessionFromEvent(e, now)

	if sess.ID != 0xdeadbeef {
		t.Errorf("ID = %#x", sess.ID)
	}
	if !sess.Active {
		t.Error("Active = false, want true")
	}
	if sess.Laddr != "192.168.1.10:40268" || sess.Raddr != "93.184.216.34:80" {
		t.Errorf("addrs = %q -> %q", sess.Laddr, sess.Raddr)
	}
	if sess.Duration != dur {
		t.Errorf("Duration = %v, want %v", sess.Duration, dur)
	}
	if want := now.Add(-dur); !sess.Start.Equal(want) {
		t.Errorf("Start = %v, want %v", sess.Start, want)
	}
	if sess.RX != 1234 || sess.TX != 5678 {
		t.Errorf("RX/TX = %d/%d", sess.RX, sess.TX)
	}
	if sess.State != 1 {
		t.Errorf("State = %d, want 1", sess.State)
	}
	if sess.Proto != 6 {
		t.Errorf("Proto = %d, want 6", sess.Proto)
	}
}

func TestSessionFromEventFinalInactive(t *testing.T) {
	e := &Event{} // Active == 0
	sess := sessionFromEvent(e, time.Unix(1000, 0))
	if sess.Active {
		t.Fatal("Active = true for final event, want false")
	}
}

func TestStoreTickRate(t *testing.T) {
	s := NewStore()
	base := time.Date(2021, 3, 4, 5, 6, 7, 0, time.UTC)

	// First active snapshot seeds the rate window at base.
	s.Upsert(Session{ID: 1, Time: base, Start: base, Active: true, RX: 1000, TX: 0})

	// Two seconds of traffic, then a tick measures the rate over that window.
	s.Upsert(Session{ID: 1, Time: base.Add(2 * time.Second), Start: base, Active: true, RX: 3000, TX: 500})
	s.Tick(base.Add(2 * time.Second))

	snap := s.Snapshot()
	if snap[0].RxRate != 1000 || snap[0].TxRate != 250 {
		t.Fatalf("rates = %d/%d, want 1000/250 bytes/s", snap[0].RxRate, snap[0].TxRate)
	}

	// Idle tick (counters unchanged) decays the rate to zero.
	s.Tick(base.Add(4 * time.Second))

	snap = s.Snapshot()
	if snap[0].RxRate != 0 || snap[0].TxRate != 0 {
		t.Fatalf("after idle tick rates = %d/%d, want 0/0", snap[0].RxRate, snap[0].TxRate)
	}
}

func TestStoreRates(t *testing.T) {
	s := NewStore()
	base := time.Date(2021, 3, 4, 5, 6, 7, 0, time.UTC)

	// Two active sockets with independent traffic over the same window.
	s.Upsert(Session{ID: 1, Time: base, Start: base, Active: true, RX: 0, TX: 0})
	s.Upsert(Session{ID: 2, Time: base, Start: base, Active: true, RX: 0, TX: 0})
	s.Upsert(Session{ID: 1, Time: base.Add(time.Second), Start: base, Active: true, RX: 2000, TX: 100})
	s.Upsert(Session{ID: 2, Time: base.Add(time.Second), Start: base, Active: true, RX: 400, TX: 300})
	s.Tick(base.Add(time.Second))

	if rx, tx := s.Rates(); rx != 2400 || tx != 400 {
		t.Fatalf("Rates() = %d/%d, want 2400/400", rx, tx)
	}

	if count, active, _, _ := s.Stats(); count != 2 || active != 2 {
		t.Fatalf("Stats() count/active = %d/%d, want 2/2", count, active)
	}

	// Closing one socket clears its contribution immediately on Upsert.
	s.Upsert(Session{ID: 1, Time: base.Add(time.Second), Start: base, Active: false, RX: 2000, TX: 100})

	if rx, tx := s.Rates(); rx != 400 || tx != 300 {
		t.Fatalf("Rates() after close = %d/%d, want 400/300 (socket 2 only)", rx, tx)
	}

	// A tick for the remaining idle socket decays it to zero too.
	s.Tick(base.Add(2 * time.Second))

	if rx, tx := s.Rates(); rx != 0 || tx != 0 {
		t.Fatalf("Rates() after idle tick = %d/%d, want 0/0", rx, tx)
	}
}
