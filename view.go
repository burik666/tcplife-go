package main

import (
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

type GroupMode int

const (
	GroupProcess GroupMode = iota
	GroupComm
	GroupRemoteAddr
	GroupRemoteHost
	GroupRemotePort
	GroupLocalAddr
	GroupLocalHost
	GroupLocalPort
	GroupFlat
)

// ProtoMode is the protocol filter: show everything, TCP only, or UDP only.
type ProtoMode int

const (
	ProtoAll ProtoMode = iota
	ProtoTCP
	ProtoUDP
)

func (p ProtoMode) String() string {
	switch p {
	case ProtoTCP:
		return "TCP"
	case ProtoUDP:
		return "UDP"
	default:
		return "All"
	}
}

func (g GroupMode) String() string {
	switch g {
	case GroupProcess:
		return "Process"
	case GroupComm:
		return "Command"
	case GroupRemoteAddr:
		return "Remote addr"
	case GroupRemoteHost:
		return "Remote host"
	case GroupRemotePort:
		return "Remote port"
	case GroupLocalAddr:
		return "Local addr"
	case GroupLocalHost:
		return "Local host"
	case GroupLocalPort:
		return "Local port"
	default:
		return "No grouping"
	}
}

type SortMode int

// Declared in table column order (PROTO/STATE have no sort mode); the sum
// variants follow their components: RX, TX, RX+TX, RX/s, TX/s, RX/s+TX/s.
// SortTime is the zero value, matching the default view.
const (
	SortTime SortMode = iota
	SortDuration
	SortPID
	SortComm
	SortLaddr
	SortRaddr
	SortRX
	SortTX
	SortTraffic
	SortRxRate
	SortTxRate
	SortRate
)

func (s SortMode) String() string {
	switch s {
	case SortTime:
		return "Time"
	case SortPID:
		return "PID"
	case SortComm:
		return "Command"
	case SortLaddr:
		return "Local addr"
	case SortRaddr:
		return "Remote addr"
	case SortRX:
		return "RX"
	case SortTX:
		return "TX"
	case SortTraffic:
		return "RX+TX"
	case SortRxRate:
		return "RX/s"
	case SortTxRate:
		return "TX/s"
	case SortRate:
		return "RX/s+TX/s"
	default:
		return "Duration"
	}
}

// viewRow is a single rendered table line.
type viewRow struct {
	isGroup  bool
	groupKey string

	// ID is the socket id (skaddr) for session rows, 0 for group rows.
	// It lets the TUI keep the cursor on the same connection across
	// re-renders instead of drifting by row index.
	ID uint64

	collapsed bool

	name    string
	nameCol int

	Time   time.Time
	Start  time.Time
	Active bool
	Out    bool
	PID    uint32
	Comm   string
	Laddr  string
	Raddr  string
	RX     uint64
	TX     uint64
	RxRate uint64
	TxRate uint64
	Dur    time.Duration
	State  string
	Proto  string

	count int
}

type groupAcc struct {
	key     string
	label   string
	nameCol int
	showPID bool

	sessions []Session

	rx, tx uint64
	dur    time.Duration
	latest time.Time

	rxRate, txRate uint64

	pid   uint32
	comm  string
	lhost string
	lport uint16
	rhost string
	rport uint16
}

// effectiveDuration is the live lifetime of a session: active rows keep
// growing because their stored Duration is only as fresh as the last event
// that touched the socket.
func effectiveDuration(s Session, now time.Time) time.Duration {
	if s.Active {
		return now.Sub(s.Start)
	}
	return s.Duration
}

func (g *groupAcc) add(s Session, now time.Time) {
	if len(g.sessions) == 0 {
		g.pid = s.PID
		g.comm = s.Comm
		g.lhost = s.Lhost
		g.lport = s.Lport
		g.rhost = s.Rhost
		g.rport = s.Rport
	}
	g.sessions = append(g.sessions, s)
	g.rx += s.RX
	g.tx += s.TX
	g.dur += effectiveDuration(s, now)
	g.rxRate += s.RxRate
	g.txRate += s.TxRate

	if s.Time.After(g.latest) {
		g.latest = s.Time
	}
}

// groupOf returns the aggregation key, label and target column for a session.
func groupOf(mode GroupMode, s Session) (key, label string, col int) {
	switch mode {
	case GroupProcess:
		return "P|" + strconv.FormatUint(uint64(s.PID), 10), s.Comm, colComm
	case GroupComm:
		return "C|" + s.Comm, s.Comm, colComm
	case GroupRemoteAddr:
		return "RA|" + s.Raddr, s.Raddr, colRaddr
	case GroupRemoteHost:
		return "RH|" + s.Rhost, s.Rhost, colRaddr
	case GroupRemotePort:
		return "RP|" + strconv.Itoa(int(s.Rport)),
			":" + strconv.Itoa(int(s.Rport)), colRaddr
	case GroupLocalAddr:
		return "LA|" + s.Laddr, s.Laddr, colLaddr
	case GroupLocalHost:
		return "LH|" + s.Lhost, s.Lhost, colLaddr
	case GroupLocalPort:
		return "LP|" + strconv.Itoa(int(s.Lport)),
			":" + strconv.Itoa(int(s.Lport)), colLaddr
	default:
		return "", "", 0
	}
}

// viewOptions bundles everything buildView needs to turn raw sessions into
// the rows to display.
type viewOptions struct {
	group     GroupMode
	sort      SortMode
	asc       bool
	filter    textFilter
	proto     ProtoMode
	collapsed map[string]bool
	now       time.Time
}

// buildView turns raw sessions into the ordered, filtered rows to display.
func buildView(sessions []Session, opt viewOptions) []viewRow {
	filtered := filterSessions(sessions, opt.filter, opt.proto)

	if opt.group == GroupFlat {
		sortSessions(filtered, opt.sort, opt.asc, opt.now)

		out := make([]viewRow, 0, len(filtered))
		for _, s := range filtered {
			out = append(out, sessionRow(s, opt.now))
		}
		return out
	}

	var order []*groupAcc
	byKey := make(map[string]*groupAcc)

	for _, s := range filtered {
		key, label, col := groupOf(opt.group, s)

		acc, ok := byKey[key]
		if !ok {
			acc = &groupAcc{key: key, label: label, nameCol: col, showPID: opt.group == GroupProcess}
			byKey[key] = acc
			order = append(order, acc)
		}
		acc.add(s, opt.now)
	}

	sort.SliceStable(order, func(i, j int) bool {
		c := cmpAgg(*order[i], *order[j], opt.sort)
		if c == 0 {
			c = strings.Compare(order[i].label, order[j].label)
		}
		return orient(c, opt.asc)
	})

	out := make([]viewRow, 0, len(filtered)+len(order))
	for _, g := range order {
		sortSessions(g.sessions, opt.sort, opt.asc, opt.now)

		isCol := opt.collapsed[g.key]

		name := g.label
		if g.showPID {
			name = formatPID(g.pid) + "  " + g.label
		}

		out = append(out, viewRow{
			isGroup:   true,
			groupKey:  g.key,
			collapsed: isCol,
			name:      name,
			nameCol:   g.nameCol,
			Time:      g.latest,
			RX:        g.rx,
			TX:        g.tx,
			RxRate:    g.rxRate,
			TxRate:    g.txRate,
			Dur:       g.dur,
			count:     len(g.sessions),
		})

		if isCol {
			continue
		}

		for _, s := range g.sessions {
			out = append(out, sessionRow(s, opt.now))
		}
	}

	return out
}

// sortSessions orders sessions in place by the active sort mode, breaking ties
// by total traffic so equal keys keep a deterministic order.
func sortSessions(sessions []Session, mode SortMode, asc bool, now time.Time) {
	sort.SliceStable(sessions, func(i, j int) bool {
		c := cmpSession(sessions[i], sessions[j], mode, now)
		if c == 0 {
			c = cmpU64(sessions[i].RX+sessions[i].TX, sessions[j].RX+sessions[j].TX)
		}
		return orient(c, asc)
	})
}

func sessionRow(s Session, now time.Time) viewRow {
	state := ""
	if s.Active && s.Proto != protoUDP {
		state = tcpStateName(s.State)
	}

	return viewRow{
		ID:     s.ID,
		Time:   s.Time,
		Start:  s.Start,
		Active: s.Active,
		Out:    s.Out,
		State:  state,
		Proto:  protoName(s.Proto),
		PID:    s.PID,
		Comm:   s.Comm,
		Laddr:  s.Laddr,
		Raddr:  s.Raddr,
		RX:     s.RX,
		TX:     s.TX,
		RxRate: s.RxRate,
		TxRate: s.TxRate,
		Dur:    effectiveDuration(s, now),
	}
}

// protoMatch reports whether a session protocol passes the filter mode.
func protoMatch(mode ProtoMode, proto uint8) bool {
	switch mode {
	case ProtoTCP:
		return proto != protoUDP
	case ProtoUDP:
		return proto == protoUDP
	default:
		return true
	}
}

// textFilter is a compiled filter pattern. re is nil when no pattern is set
// or when it failed to compile (err != nil), in which case nothing matches.
type textFilter struct {
	pattern string
	re      *regexp.Regexp
	err     error
}

// compileFilter compiles a regular expression; the syntax and case handling
// are exactly what the user typed (no implicit flags).
func compileFilter(pattern string) textFilter {
	f := textFilter{pattern: pattern}
	if pattern == "" {
		return f
	}

	f.re, f.err = regexp.Compile(pattern)

	return f
}

// match reports whether the session matches the pattern. The command line,
// PID, addresses and (for TCP) the state name are searched; UDP has no
// state, so it is excluded instead of matching the "?" placeholder.
func (f textFilter) match(s Session) bool {
	if f.re == nil {
		return false
	}

	if f.re.MatchString(s.Comm) ||
		f.re.MatchString(strconv.Itoa(int(s.PID))) ||
		f.re.MatchString(s.Laddr) ||
		f.re.MatchString(s.Raddr) {
		return true
	}

	return s.Proto != protoUDP && f.re.MatchString(tcpStateName(s.State))
}

func filterSessions(in []Session, f textFilter, mode ProtoMode) []Session {
	if f.re == nil && f.err == nil && mode == ProtoAll {
		return in
	}

	out := make([]Session, 0, len(in))

	for _, s := range in {
		if !protoMatch(mode, s.Proto) {
			continue
		}

		switch {
		case f.err != nil:
			continue // invalid pattern: nothing matches
		case f.re == nil:
			out = append(out, s) // no pattern set
		case f.match(s):
			out = append(out, s)
		}
	}

	return out
}

const (
	colTime = iota
	colDur
	colPID
	colProto
	colLaddr
	colRaddr
	colRX
	colTX
	colRxRate
	colTxRate
	colState
	colComm
)

const colCount = colComm + 1

func orient(c int, asc bool) bool {
	if asc {
		return c < 0
	}
	return c > 0
}

// sortColumns maps a sort mode to the table columns it orders by, so the TUI
// can mark them in the header. The sum modes mark both of their components.
func sortColumns(mode SortMode) []int {
	switch mode {
	case SortTime:
		return []int{colTime}
	case SortPID:
		return []int{colPID}
	case SortComm:
		return []int{colComm}
	case SortLaddr:
		return []int{colLaddr}
	case SortRaddr:
		return []int{colRaddr}
	case SortRX:
		return []int{colRX}
	case SortTX:
		return []int{colTX}
	case SortTraffic:
		return []int{colRX, colTX}
	case SortRxRate:
		return []int{colRxRate}
	case SortTxRate:
		return []int{colTxRate}
	case SortRate:
		return []int{colRxRate, colTxRate}
	case SortDuration:
		return []int{colDur}
	default:
		return nil
	}
}

func cmpU64(a, b uint64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}

func cmpU32(a, b uint32) int {
	return cmpU64(uint64(a), uint64(b))
}

func cmpDur(a, b time.Duration) int {
	return cmpU64(uint64(a), uint64(b))
}

func cmpTime(a, b time.Time) int {
	switch {
	case a.Before(b):
		return -1
	case a.After(b):
		return 1
	default:
		return 0
	}
}

func cmpAddr(h1 string, p1 uint16, h2 string, p2 uint16) int {
	if c := strings.Compare(h1, h2); c != 0 {
		return c
	}
	return cmpU32(uint32(p1), uint32(p2))
}

// cmpKey holds every field a sort mode can order by, so sessions and group
// aggregates share a single comparison implementation.
type cmpKey struct {
	traffic uint64
	rx      uint64
	tx      uint64
	rxRate  uint64
	txRate  uint64
	dur     time.Duration
	at      time.Time
	pid     uint32
	comm    string
	lhost   string
	lport   uint16
	rhost   string
	rport   uint16
}

func sessionKey(a Session, now time.Time) cmpKey {
	return cmpKey{
		traffic: a.RX + a.TX,
		rx:      a.RX,
		tx:      a.TX,
		rxRate:  a.RxRate,
		txRate:  a.TxRate,
		dur:     effectiveDuration(a, now),
		at:      a.Time,
		pid:     a.PID,
		comm:    a.Comm,
		lhost:   a.Lhost,
		lport:   a.Lport,
		rhost:   a.Rhost,
		rport:   a.Rport,
	}
}

func aggKey(a groupAcc) cmpKey {
	return cmpKey{
		traffic: a.rx + a.tx,
		rx:      a.rx,
		tx:      a.tx,
		rxRate:  a.rxRate,
		txRate:  a.txRate,
		dur:     a.dur,
		at:      a.latest,
		pid:     a.pid,
		comm:    a.comm,
		lhost:   a.lhost,
		lport:   a.lport,
		rhost:   a.rhost,
		rport:   a.rport,
	}
}

func cmpByMode(a, b cmpKey, mode SortMode) int {
	switch mode {
	case SortTraffic:
		return cmpU64(a.traffic, b.traffic)
	case SortRX:
		return cmpU64(a.rx, b.rx)
	case SortTX:
		return cmpU64(a.tx, b.tx)
	case SortDuration:
		return cmpDur(a.dur, b.dur)
	case SortTime:
		return cmpTime(a.at, b.at)
	case SortPID:
		return cmpU32(a.pid, b.pid)
	case SortComm:
		return strings.Compare(a.comm, b.comm)
	case SortRaddr:
		return cmpAddr(a.rhost, a.rport, b.rhost, b.rport)
	case SortLaddr:
		return cmpAddr(a.lhost, a.lport, b.lhost, b.lport)
	case SortRxRate:
		return cmpU64(a.rxRate, b.rxRate)
	case SortTxRate:
		return cmpU64(a.txRate, b.txRate)
	case SortRate:
		return cmpU64(a.rxRate+a.txRate, b.rxRate+b.txRate)
	default:
		return 0
	}
}

func cmpSession(a, b Session, mode SortMode, now time.Time) int {
	return cmpByMode(sessionKey(a, now), sessionKey(b, now), mode)
}

func cmpAgg(a, b groupAcc, mode SortMode) int {
	return cmpByMode(aggKey(a), aggKey(b), mode)
}
