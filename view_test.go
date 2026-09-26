package main

import (
	"strings"
	"testing"
	"time"
)

func TestProcessGroupLabelUsesQuestionForZeroPID(t *testing.T) {
	base := time.Date(2021, 3, 4, 5, 6, 7, 0, time.UTC)

	sess := []Session{
		{ID: 1, Time: base, Start: base, Active: true, PID: 0, Comm: "-", Lhost: "10.0.0.1", Rhost: "1.1.1.1"},
		{ID: 2, Time: base, Start: base, PID: 777, Comm: "curl", Lhost: "10.0.0.1", Rhost: "1.1.1.1"},
	}

	rows := buildView(sess, viewOptions{group: GroupProcess, sort: SortPID, asc: true, filter: compileFilter(""), proto: ProtoAll, now: base})

	var names []string
	for _, r := range rows {
		if r.isGroup {
			names = append(names, r.name)
		}
	}

	if len(names) != 2 {
		t.Fatalf("groups = %v, want 2", names)
	}

	// SortPID asc -> PID 0 (unknown) first, rendered as "?".
	if names[0] != "?  -" {
		t.Errorf("zero-pid group = %q, want %q", names[0], "?  -")
	}
	if !strings.HasPrefix(names[1], "777  curl") {
		t.Errorf("pid 777 group = %q, want prefix %q", names[1], "777  curl")
	}
}

func TestSessionRowState(t *testing.T) {
	now := time.Now()

	if got := sessionRow(Session{Active: true, State: 1}, now).State; got != "ESTABLISHED" {
		t.Errorf("active State = %q, want ESTABLISHED", got)
	}

	if got := sessionRow(Session{Active: true, State: 6}, now).State; got != "TIME_WAIT" {
		t.Errorf("active State = %q, want TIME_WAIT", got)
	}

	if got := sessionRow(Session{Active: false, State: 7}, now).State; got != "" {
		t.Errorf("closed State = %q, want empty", got)
	}
}

func TestSessionRowProto(t *testing.T) {
	now := time.Now()

	udp := sessionRow(Session{Active: true, Proto: protoUDP, State: 0}, now)
	if udp.Proto != "UDP" {
		t.Errorf("udp Proto = %q, want UDP", udp.Proto)
	}

	if udp.State != "" {
		t.Errorf("udp State = %q, want empty", udp.State)
	}

	tcp := sessionRow(Session{Active: true, Proto: protoTCP, State: 1}, now)
	if tcp.Proto != "TCP" || tcp.State != "ESTABLISHED" {
		t.Errorf("tcp row = %q/%q", tcp.Proto, tcp.State)
	}
}

func TestSortRateModes(t *testing.T) {
	now := time.Now()

	sess := []Session{
		{ID: 1, Active: true, RxRate: 5, TxRate: 100},
		{ID: 2, Active: true, RxRate: 50, TxRate: 1},
	}

	byRx := buildView(sess, viewOptions{group: GroupFlat, sort: SortRxRate, asc: true, filter: compileFilter(""), proto: ProtoAll, now: now})
	if byRx[0].ID != 1 || byRx[1].ID != 2 {
		t.Errorf("SortRxRate asc = %d,%d, want 1,2", byRx[0].ID, byRx[1].ID)
	}

	byRate := buildView(sess, viewOptions{group: GroupFlat, sort: SortRate, asc: false, filter: compileFilter(""), proto: ProtoAll, now: now})
	if byRate[0].ID != 1 || byRate[1].ID != 2 {
		t.Errorf("SortRate desc = %d,%d, want 1,2 (105 vs 51)", byRate[0].ID, byRate[1].ID)
	}

	if got := SortTraffic.String(); got != "RX+TX" {
		t.Errorf("SortTraffic label = %q", got)
	}

	if got := SortRate.String(); got != "RX/s+TX/s" {
		t.Errorf("SortRate label = %q", got)
	}
}

func TestSortByEffectiveDuration(t *testing.T) {
	now := time.Date(2021, 3, 4, 5, 6, 7, 0, time.UTC)

	// ID 1 has a frozen Duration of 5s but started 2 minutes ago (active,
	// so it is really 120s old). ID 2 is closed after 10s.
	sess := []Session{
		{ID: 1, Active: true, Start: now.Add(-120 * time.Second), Duration: 5 * time.Second, PID: 1},
		{ID: 2, Active: false, Start: now.Add(-300 * time.Second), Duration: 10 * time.Second, PID: 2},
	}

	// Sorting by frozen Duration would put ID 1 before ID 2; effective
	// duration (desc) must put ID 1 first, and asc must put ID 2 first.
	desc := buildView(sess, viewOptions{group: GroupFlat, sort: SortDuration, asc: false, filter: compileFilter(""), proto: ProtoAll, now: now})
	if desc[0].ID != 1 || desc[1].ID != 2 {
		t.Errorf("desc = %d,%d, want 1,2 (120s vs 10s)", desc[0].ID, desc[1].ID)
	}

	asc := buildView(sess, viewOptions{group: GroupFlat, sort: SortDuration, asc: true, filter: compileFilter(""), proto: ProtoAll, now: now})
	if asc[0].ID != 2 || asc[1].ID != 1 {
		t.Errorf("asc = %d,%d, want 2,1", asc[0].ID, asc[1].ID)
	}

	// The view row carries the live duration, not the frozen event value.
	if got := asc[1].Dur; got != 120*time.Second {
		t.Errorf("active row Dur = %v, want 120s", got)
	}

	// Group totals sum effective durations: 120 + 10 = 130s.
	grouped := buildView(sess, viewOptions{group: GroupRemotePort, sort: SortDuration, asc: false, filter: compileFilter(""), proto: ProtoAll, now: now})

	var found bool

	for _, r := range grouped {
		if r.isGroup {
			found = true
			if r.Dur != 130*time.Second {
				t.Errorf("group Dur = %v, want 130s", r.Dur)
			}
		}
	}

	if !found {
		t.Error("no group rows")
	}
}

func TestSortColumns(t *testing.T) {
	cases := []struct {
		mode SortMode
		want []int
	}{
		{SortTime, []int{colTime}},
		{SortPID, []int{colPID}},
		{SortComm, []int{colComm}},
		{SortLaddr, []int{colLaddr}},
		{SortRaddr, []int{colRaddr}},
		{SortRX, []int{colRX}},
		{SortTX, []int{colTX}},
		{SortTraffic, []int{colRX, colTX}},
		{SortRxRate, []int{colRxRate}},
		{SortTxRate, []int{colTxRate}},
		{SortRate, []int{colRxRate, colTxRate}},
		{SortDuration, []int{colDur}},
	}

	for _, tc := range cases {
		got := sortColumns(tc.mode)
		if len(got) != len(tc.want) {
			t.Errorf("sortColumns(%v) = %v, want %v", tc.mode, got, tc.want)
			continue
		}

		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("sortColumns(%v) = %v, want %v", tc.mode, got, tc.want)
				break
			}
		}
	}
}

func TestProtoModeString(t *testing.T) {
	cases := map[ProtoMode]string{ProtoAll: "All", ProtoTCP: "TCP", ProtoUDP: "UDP"}
	for mode, want := range cases {
		if got := mode.String(); got != want {
			t.Errorf("ProtoMode(%d).String() = %q, want %q", mode, got, want)
		}
	}
}

func TestFilterSessionsRegexp(t *testing.T) {
	sess := []Session{
		{ID: 1, Proto: protoTCP, Comm: "curl", Raddr: "1.1.1.1:80", State: 1}, // ESTABLISHED
		{ID: 2, Proto: protoUDP, Comm: "dig", Raddr: "8.8.8.8:53"},
		{ID: 3, Proto: protoTCP, Comm: "sshd", Raddr: "10.0.0.1:22", State: 6, Active: true}, // TIME_WAIT
	}

	ids := func(in []Session) []uint64 {
		out := make([]uint64, 0, len(in))
		for _, s := range in {
			out = append(out, s.ID)
		}
		return out
	}

	// Empty pattern with ProtoAll returns everything untouched.
	if got := ids(filterSessions(sess, compileFilter(""), ProtoAll)); len(got) != 3 {
		t.Errorf("empty = %v, want all", got)
	}

	// Literal substring still works as a regexp.
	if got := ids(filterSessions(sess, compileFilter("curl"), ProtoAll)); len(got) != 1 || got[0] != 1 {
		t.Errorf("curl = %v, want [1]", got)
	}

	// Alternation and anchors.
	if got := ids(filterSessions(sess, compileFilter("curl|dig"), ProtoAll)); len(got) != 2 {
		t.Errorf("curl|dig = %v, want [1 2]", got)
	}
	if got := ids(filterSessions(sess, compileFilter(":53$"), ProtoAll)); len(got) != 1 || got[0] != 2 {
		t.Errorf(":53$ = %v, want [2]", got)
	}
	if got := ids(filterSessions(sess, compileFilter("^8\\.8\\."), ProtoAll)); len(got) != 1 || got[0] != 2 {
		t.Errorf("^8\\.8\\. = %v, want [2]", got)
	}

	// STATE is searched for TCP; UDP has no state and must not match "?".
	if got := ids(filterSessions(sess, compileFilter("TIME_WAIT"), ProtoAll)); len(got) != 1 || got[0] != 3 {
		t.Errorf("TIME_WAIT = %v, want [3]", got)
	}
	if got := ids(filterSessions(sess, compileFilter(`^\?$`), ProtoAll)); len(got) != 0 {
		t.Errorf("^\\?$ = %v, want none (UDP state excluded)", got)
	}

	// Case sensitivity is the user's business (no implicit (?i)).
	if got := ids(filterSessions(sess, compileFilter("CURL"), ProtoAll)); len(got) != 0 {
		t.Errorf("CURL = %v, want none", got)
	}
	if got := ids(filterSessions(sess, compileFilter("(?i)CURL"), ProtoAll)); len(got) != 1 || got[0] != 1 {
		t.Errorf("(?i)CURL = %v, want [1]", got)
	}

	// Invalid pattern matches nothing.
	if got := ids(filterSessions(sess, compileFilter("["), ProtoAll)); len(got) != 0 {
		t.Errorf("invalid = %v, want none", got)
	}

	// AND with the protocol mode.
	if got := ids(filterSessions(sess, compileFilter("8\\.8"), ProtoTCP)); len(got) != 0 {
		t.Errorf("TCP + 8.8 = %v, want none", got)
	}

	if got := ids(filterSessions(sess, compileFilter("8\\.8"), ProtoUDP)); len(got) != 1 || got[0] != 2 {
		t.Errorf("UDP + 8.8 = %v, want [2]", got)
	}
}

func TestBuildViewProto(t *testing.T) {
	now := time.Now()
	sess := []Session{
		{ID: 1, Proto: protoTCP},
		{ID: 2, Proto: protoUDP},
	}

	rows := buildView(sess, viewOptions{group: GroupFlat, sort: SortPID, asc: true, filter: compileFilter(""), proto: ProtoUDP, now: now})
	if len(rows) != 1 || rows[0].ID != 2 {
		t.Errorf("ProtoUDP rows = %v, want [2]", rows)
	}
}

// aggOf builds the group aggregate that cmpAgg would see for a single session,
// so session and aggregate comparisons can be checked against each other.
func aggOf(s Session) groupAcc {
	return groupAcc{
		rx: s.RX, tx: s.TX, dur: s.Duration, latest: s.Time,
		pid: s.PID, comm: s.Comm,
		lhost: s.Lhost, lport: s.Lport, rhost: s.Rhost, rport: s.Rport,
		rxRate: s.RxRate, txRate: s.TxRate,
	}
}

// TestCmpSessionAggParity locks in that the unified cmpByMode makes session
// and group-aggregate sorting agree field-for-field for every sort mode.
func TestCmpSessionAggParity(t *testing.T) {
	now := time.Date(2021, 3, 4, 5, 6, 7, 0, time.UTC)

	mk := func(rx, tx, rxRate, txRate uint64, dur time.Duration, at time.Time, pid uint32, comm, lhost string, lport uint16, rhost string, rport uint16) Session {
		return Session{
			RX: rx, TX: tx, RxRate: rxRate, TxRate: txRate,
			Duration: dur, Time: at, PID: pid, Comm: comm,
			Lhost: lhost, Lport: lport, Rhost: rhost, Rport: rport,
		}
	}

	a := mk(10, 20, 5, 6, 30*time.Second, now.Add(-time.Minute), 7, "curl", "10.0.0.1", 1000, "1.1.1.1", 80)
	b := mk(11, 21, 7, 8, 31*time.Second, now.Add(-2*time.Minute), 8, "dig", "10.0.0.2", 1001, "8.8.8.8", 53)

	aggA, aggB := aggOf(a), aggOf(b)

	modes := []SortMode{
		SortTime, SortDuration, SortPID, SortComm, SortLaddr, SortRaddr,
		SortRX, SortTX, SortTraffic, SortRxRate, SortTxRate, SortRate,
	}

	for _, mode := range modes {
		want := cmpSession(a, b, mode, now)
		if got := cmpAgg(aggA, aggB, mode); got != want {
			t.Errorf("cmpAgg(%v) = %d, want %d (same as cmpSession)", mode, got, want)
		}
	}
}
