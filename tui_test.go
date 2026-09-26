package main

import "testing"

func TestSelectionKey(t *testing.T) {
	rows := []viewRow{
		{ID: 7},
		{isGroup: true, groupKey: "P|777"},
		{ID: 9},
	}

	cases := []struct {
		sel  int
		want string
	}{
		{1, "S|7"},
		{2, "G|P|777"},
		{3, "S|9"},
		{0, ""},
		{4, ""},
		{-1, ""},
	}

	for _, tc := range cases {
		if got := selectionKey(rows, tc.sel); got != tc.want {
			t.Errorf("selectionKey(rows, %d) = %q, want %q", tc.sel, got, tc.want)
		}
	}
}

func TestRestoreSelFollowsEntityWhenRowsInsertAbove(t *testing.T) {
	lastRows := []viewRow{{ID: 1}, {ID: 2}, {ID: 3}}

	// Cursor on ID 2 (table row 2) in the previously rendered list.
	target := selectionKey(lastRows, 2)

	// Two new connections appear above it.
	rows := []viewRow{{ID: 9}, {ID: 8}, {ID: 1}, {ID: 2}, {ID: 3}}

	if got := restoreSel(rows, 2, target); got != 4 {
		t.Errorf("restoreSel = %d, want 4 (same session, shifted by 2)", got)
	}
}

func TestRestoreSelGroupKeepsIdentity(t *testing.T) {
	lastRows := []viewRow{{isGroup: true, groupKey: "P|777"}, {ID: 2}}
	target := selectionKey(lastRows, 1)

	rows := []viewRow{{isGroup: true, groupKey: "P|5"}, {isGroup: true, groupKey: "P|777"}, {ID: 2}}

	if got := restoreSel(rows, 1, target); got != 2 {
		t.Errorf("restoreSel = %d, want 2 (group followed)", got)
	}
}

func TestRestoreSelFallbacksToIndex(t *testing.T) {
	// Target gone (filtered/collapsed): keep the old index.
	rows := []viewRow{{ID: 5}, {ID: 6}}
	if got := restoreSel(rows, 1, "S|99"); got != 1 {
		t.Errorf("restoreSel missing = %d, want 1", got)
	}

	// No selection at all: passthrough.
	if got := restoreSel(rows, 0, ""); got != 0 {
		t.Errorf("restoreSel empty = %d, want 0", got)
	}
}

func TestMeasureRateWidth(t *testing.T) {
	rows := []viewRow{
		{Active: true, RxRate: 0},                   // "0 B/s" = 5
		{Active: true, TxRate: 5 * 1024 * 1024},     // "5.0 MiB/s" = 9
		{isGroup: true, TxRate: 1024 * 1024 * 1024}, // "1.0 GiB/s" = 9
		{ID: 3, RxRate: 999 * 1024 * 1024 * 1024},   // inactive: ignored
	}

	if got := measureRateWidth(rows); got != 9 {
		t.Errorf("measureRateWidth = %d, want 9", got)
	}

	if got := measureRateWidth(nil); got != 0 {
		t.Errorf("measureRateWidth(nil) = %d, want 0", got)
	}
}

func TestPadRate(t *testing.T) {
	if got := padRate("0 B/s", 12); got != "       0 B/s" {
		t.Errorf("padRate short = %q, want %q", got, "       0 B/s")
	}

	if got := padRate("", 5); got != "     " {
		t.Errorf("padRate empty = %q, want 5 spaces", got)
	}

	if got := padRate("1234567890123", 12); got != "1234567890123" {
		t.Errorf("padRate must not truncate, got %q", got)
	}

	if got := padRate("abc", 0); got != "abc" {
		t.Errorf("padRate w=0 = %q, want %q", got, "abc")
	}
}

func TestRateVisible(t *testing.T) {
	cases := []struct {
		name   string
		proto  string
		rx, tx uint64
		want   bool
	}{
		{"TCP zero shows", "TCP", 0, 0, true},
		{"UDP both zero hidden", "UDP", 0, 0, false},
		{"UDP rx only shows", "UDP", 0, 5, true},
		{"UDP tx only shows", "UDP", 5, 0, true},
		{"UDP both show", "UDP", 5, 5, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := rateVisible(tc.proto, tc.rx, tc.tx); got != tc.want {
				t.Errorf("rateVisible(%q, %d, %d) = %v, want %v", tc.proto, tc.rx, tc.tx, got, tc.want)
			}
		})
	}
}
