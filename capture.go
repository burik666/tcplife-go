package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"
)

// Event mirrors struct event in bpf.c (padding-free, decoded sequentially).
type Event struct {
	Skaddr        uint64
	TS            uint64
	DurationNS    uint64
	BytesReceived uint64
	BytesAcked    uint64
	PID           uint32
	Family        uint16
	SPort         uint16
	DPort         uint16
	Active        uint8
	Dir           uint8
	State         uint8
	Proto         uint8
	SAddr         [16]byte
	DAddr         [16]byte
	Comm          [16]byte
}

// IP protocol numbers reported by the BPF programs in Event.Proto.
const (
	protoTCP = 6
	protoUDP = 17
)

// Session is a decoded, display-ready TCP or UDP connection/flow.
type Session struct {
	ID       uint64
	Time     time.Time
	Start    time.Time
	Active   bool
	Out      bool
	State    uint8
	Proto    uint8
	PID      uint32
	Comm     string
	Laddr    string
	Raddr    string
	Lhost    string
	Lport    uint16
	Rhost    string
	Rport    uint16
	Family   uint16
	RX       uint64
	TX       uint64
	RxRate   uint64
	TxRate   uint64
	Duration time.Duration
}

func sessionFromEvent(e *Event, now time.Time) Session {
	comm := string(bytes.TrimRight(e.Comm[:], "\x00"))
	if comm == "" {
		comm = "-"
	}

	lhost := ipFromBytes(e.SAddr[:], e.Family).String()
	rhost := ipFromBytes(e.DAddr[:], e.Family).String()

	dur := time.Duration(e.DurationNS)

	return Session{
		ID:       e.Skaddr,
		Time:     now,
		Start:    now.Add(-dur),
		Active:   e.Active != 0,
		Out:      e.Dir != 0,
		State:    e.State,
		Proto:    e.Proto,
		PID:      e.PID,
		Comm:     comm,
		Laddr:    net.JoinHostPort(lhost, strconv.Itoa(int(e.SPort))),
		Raddr:    net.JoinHostPort(rhost, strconv.Itoa(int(e.DPort))),
		Lhost:    lhost,
		Lport:    e.SPort,
		Rhost:    rhost,
		Rport:    e.DPort,
		Family:   e.Family,
		RX:       e.BytesReceived,
		TX:       e.BytesAcked,
		Duration: dur,
	}
}

// rateSample records counters at a given instant so Tick can derive a
// per-second rate over the elapsed window.
type rateSample struct {
	rx, tx uint64
	at     time.Time
}

// Store accumulates sessions thread-safely for the TUI.
type Store struct {
	mu    sync.RWMutex
	order []uint64
	byID  map[uint64]Session
	last  map[uint64]rateSample
	dirty bool
}

func NewStore() *Store {
	return &Store{byID: make(map[uint64]Session), last: make(map[uint64]rateSample)}
}

// Upsert inserts or updates a session keyed by its socket id. Active snapshots
// grow counters in place; the final event flips Active to false.
func (s *Store) Upsert(sess Session) {
	s.mu.Lock()
	if _, ok := s.byID[sess.ID]; !ok {
		s.order = append(s.order, sess.ID)
	}
	// Seed the rate window on first sight so the first Tick measures from here.
	if _, ok := s.last[sess.ID]; !ok {
		s.last[sess.ID] = rateSample{rx: sess.RX, tx: sess.TX, at: sess.Time}
	}
	// Closed sessions carry no live rate.
	if !sess.Active {
		sess.RxRate, sess.TxRate = 0, 0
	}
	s.byID[sess.ID] = sess
	s.dirty = true
	s.mu.Unlock()
}

// Tick recomputes per-second rates for active sessions over the window since
// their last sample. Idle connections (no new counters) decay to 0.
func (s *Store) Tick(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for id, sess := range s.byID {
		if !sess.Active {
			if sess.RxRate != 0 || sess.TxRate != 0 {
				sess.RxRate, sess.TxRate = 0, 0
				s.byID[id] = sess
			}
			continue
		}

		prev, ok := s.last[id]
		if !ok {
			s.last[id] = rateSample{rx: sess.RX, tx: sess.TX, at: now}
			continue
		}

		if secs := now.Sub(prev.at).Seconds(); secs > 0 {
			if sess.RX >= prev.rx {
				sess.RxRate = uint64(float64(sess.RX-prev.rx) / secs)
			}
			if sess.TX >= prev.tx {
				sess.TxRate = uint64(float64(sess.TX-prev.tx) / secs)
			}
		}

		s.last[id] = rateSample{rx: sess.RX, tx: sess.TX, at: now}
		s.byID[id] = sess
	}
}

func (s *Store) Snapshot() []Session {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]Session, 0, len(s.byID))
	for _, id := range s.order {
		if sess, ok := s.byID[id]; ok {
			out = append(out, sess)
		}
	}
	return out
}

// Stats reports totals plus how many sessions are currently active.
func (s *Store) Stats() (count, active int, rx, tx uint64) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, sess := range s.byID {
		rx += sess.RX
		tx += sess.TX
		if sess.Active {
			active++
		}
	}

	return len(s.byID), active, rx, tx
}

// Rates reports the summed live per-second rates across all sessions. Closed
// sessions keep zeroed rates (see Tick/Upsert), so idle history never sticks.
func (s *Store) Rates() (rxRate, txRate uint64) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, sess := range s.byID {
		rxRate += sess.RxRate
		txRate += sess.TxRate
	}

	return
}

// HasActive reports whether any open connection is tracked.
func (s *Store) HasActive() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, sess := range s.byID {
		if sess.Active {
			return true
		}
	}

	return false
}

func (s *Store) Clear() {
	s.mu.Lock()
	s.order = nil
	s.byID = make(map[uint64]Session)
	s.last = make(map[uint64]rateSample)
	s.dirty = true
	s.mu.Unlock()
}

func (s *Store) takeDirty() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.dirty
	s.dirty = false
	return d
}

// capture owns the loaded BPF objects and ring-buffer reader.
type capture struct {
	objs        *bpfObjects
	tp          link.Link
	links       []link.Link
	rd          *ringbuf.Reader
	ktimeOffset int64
	haveKtime   bool
	cmds        *cmdlineResolver
}

func openCapture() (c *capture, err error) {
	objs := &bpfObjects{}

	if err = loadBpfObjects(objs, nil); err != nil {
		return nil, err
	}

	// Deferred cleanups fire only on a later failure, in reverse registration
	// order (tp before objs), matching the previous manual unwinding.
	defer func() {
		if err != nil {
			objs.Close()
		}
	}()

	tp, err := link.Tracepoint("sock", "inet_sock_set_state", objs.TcpState, nil)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			tp.Close()
		}
	}()

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		return nil, err
	}

	c = &capture{objs: objs, tp: tp, rd: rd, cmds: newCmdlineResolver()}

	// Realtime hooks are best-effort: on kernels/configs without fentry the
	// tool still works in close-only mode.
	if err := attachRealtime(objs, c); err != nil {
		fmt.Fprintf(os.Stderr, "realtime disabled (fentry/fexit): %v\n", err)
	}

	if err := attachUdp(objs, c); err != nil {
		fmt.Fprintf(os.Stderr, "udp disabled (fentry/fexit): %v\n", err)
	}

	if off, err := ktimeWallOffset(); err == nil {
		c.ktimeOffset = off
		c.haveKtime = true
	}

	return c, nil
}

// attachRealtime wires the data-path probes used for live updates and correct
// per-connection ownership attribution.
func attachRealtime(objs *bpfObjects, c *capture) error {
	return attachTracingAll(c,
		objs.TcpSendmsgExit,
		objs.TcpCleanup,
		objs.InetCskAcceptExit,
	)
}

// attachUdp wires the UDP accounting probes (sendmsg/recvmsg/destroy_sock).
// It is best-effort and separate from the TCP realtime hooks: failing to
// attach these leaves TCP unaffected.
func attachUdp(objs *bpfObjects, c *capture) error {
	return attachTracingAll(c,
		objs.UdpSendmsgExit,
		objs.UdpRecvmsgExit,
		objs.UdpDestroySockExit,
	)
}

// attachTracingAll attaches every program, closing only the links it added
// itself if one fails, so a caller can safely try another group afterwards.
func attachTracingAll(c *capture, progs ...*ebpf.Program) error {
	start := len(c.links)

	for _, p := range progs {
		l, err := link.AttachTracing(link.TracingOptions{Program: p})
		if err != nil {
			for _, ok := range c.links[start:] {
				ok.Close()
			}
			c.links = c.links[:start]

			return err
		}

		c.links = append(c.links, l)
	}

	return nil
}

// ktimeWallOffset returns wall_ns - monotonic_ns so a bpf_ktime_get_ns()
// value can be converted to a local wall-clock time.
func ktimeWallOffset() (int64, error) {
	var ts unix.Timespec

	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return 0, err
	}

	mono := ts.Sec*int64(time.Second) + ts.Nsec

	return time.Now().UnixNano() - mono, nil
}

// wallTime converts a bpf_ktime_get_ns() timestamp to local wall-clock time,
// falling back to the read instant when the monotonic clock is unavailable.
func (c *capture) wallTime(tsNS uint64) time.Time {
	if !c.haveKtime {
		return time.Now()
	}
	return time.Unix(0, int64(tsNS)+c.ktimeOffset)
}

func (c *capture) Close() {
	if c == nil {
		return
	}
	if c.rd != nil {
		c.rd.Close()
	}
	for _, l := range c.links {
		l.Close()
	}
	if c.tp != nil {
		c.tp.Close()
	}
	if c.objs != nil {
		c.objs.Close()
	}
}

// cmdlineCacheEntry holds a resolved command line and the process start time
// it was captured for, so a recycled PID is not shown with a stale command.
type cmdlineCacheEntry struct {
	start uint64
	cmd   string
}

// cmdlineResolver turns a PID into a ps-style full command line via /proc,
// caching per process and re-reading when the start time changes (PID reuse).
type cmdlineResolver struct {
	mu    sync.Mutex
	root  string // normally "/proc"
	cache map[uint32]cmdlineCacheEntry
}

func newCmdlineResolver() *cmdlineResolver {
	return &cmdlineResolver{root: "/proc", cache: make(map[uint32]cmdlineCacheEntry)}
}

// last returns the most recently cached command line for pid, regardless of
// its start time; used once the process is gone (or /proc is unreadable).
func (r *cmdlineResolver) last(pid uint32) (string, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	e, ok := r.cache[pid]

	return e.cmd, ok
}

// cached returns the command line for pid when it was resolved for the same
// process start time, so a recycled PID is never shown with a stale command.
func (r *cmdlineResolver) cached(pid uint32, start uint64) (string, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	e, ok := r.cache[pid]
	if !ok || e.start != start {
		return "", false
	}

	return e.cmd, true
}

// put records a resolved command line together with the start time it was
// captured for.
func (r *cmdlineResolver) put(pid uint32, start uint64, cmd string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.cache[pid] = cmdlineCacheEntry{start: start, cmd: cmd}
}

// resolve returns the display command line for pid, falling back to
// "[comm]" for kernel threads (pid 0) and to the last value we saw once the
// process has exited. comm is the truncated kernel name used in fallbacks.
func (r *cmdlineResolver) resolve(pid uint32, comm string) string {
	if pid == 0 {
		return "[" + comm + "]"
	}

	start, err := procStartTime(r.root, pid)
	if err != nil {
		// Gone (or unreadable): keep the last known value, else kernel-style.
		if cmd, ok := r.last(pid); ok {
			return cmd
		}

		return "[" + comm + "]"
	}

	if cmd, ok := r.cached(pid, start); ok {
		return cmd
	}

	cmd := readProcCmdline(r.root, pid, comm)
	r.put(pid, start, cmd)

	return cmd
}

// procStartTime reads field 22 of /proc/<pid>/stat (starttime, in clock
// ticks). The comm field is parenthesized and may contain spaces, so we
// parse tokens after the last ')'.
func procStartTime(root string, pid uint32) (uint64, error) {
	data, err := os.ReadFile(root + "/" + strconv.FormatUint(uint64(pid), 10) + "/stat")
	if err != nil {
		return 0, err
	}

	s := string(data)
	rparen := strings.LastIndexByte(s, ')')
	if rparen < 0 {
		return 0, errors.New("proc: malformed stat")
	}

	// Tokens after the closing paren start at field 3 (state); starttime is
	// field 22, i.e. the token at index 19.
	rest := strings.Fields(s[rparen+1:])
	if len(rest) < 20 {
		return 0, errors.New("proc: short stat")
	}

	return strconv.ParseUint(rest[19], 10, 64)
}

// readProcCmdline reads /proc/<pid>/cmdline and formats it; a missing or
// empty cmdline (kernel thread) becomes "[comm]".
func readProcCmdline(root string, pid uint32, comm string) string {
	raw, err := os.ReadFile(root + "/" + strconv.FormatUint(uint64(pid), 10) + "/cmdline")
	if err != nil {
		return "[" + comm + "]"
	}

	return formatCmdline(raw, comm)
}

func (c *capture) readEvent() (Session, error) {
	record, err := c.rd.Read()
	if err != nil {
		return Session{}, err
	}

	var e Event

	if err := binary.Read(
		bytes.NewReader(record.RawSample),
		binary.LittleEndian,
		&e,
	); err != nil {
		return Session{}, err
	}

	sess := sessionFromEvent(&e, c.wallTime(e.TS))

	// Replace the truncated kernel comm (already trimmed/normalized by
	// sessionFromEvent) with the full ps-style command line.
	if c.cmds != nil {
		sess.Comm = c.cmds.resolve(e.PID, sess.Comm)
	}

	return sess, nil
}
