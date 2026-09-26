# AGENTS.md

## Overview
Single-package Go tool (`package main`, module
`github.com/burik666/tcplife-go`). Loads a CO-RE eBPF
tracepoint program (`bpf.c`) and reports TCP session lifetime and UDP flows
(see "UDP flows"), addresses and byte counts in two output modes, auto-selected
by whether stdout is a terminal:
- TUI (`tui.go`, built on `rivo/tview` + `gdamore/tcell`): live grouped/aggregated
  table with on-the-fly grouping, sorting, filtering, collapse, pause, and realtime
  byte counts for open connections (see "Realtime traffic").
- Plain streaming (`plain.go`): original tcplife-style one-line-per-session output,
  used when stdout is not a TTY.
Event-time format is configurable via the `-time-format` flag (see `format.go`).
Tests exist (`*_test.go`); no CI, no linter/formatter config (use `gofmt`).

## Build / codegen
Always use `make build` (not bare `go build`): it runs `go generate ./...` first.
`go generate` (see `bpf.go`) runs, in order:
1. `bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h`
2. `bpf2go -cc clang -cflags "-O2 -g -Wall -Wno-missing-declarations -I." bpf bpf.c`
Requires `bpftool` and `clang` in PATH. `vmlinux.h` is generated from the running
kernel's BTF and is gitignored; never edit or commit it. Generated artifacts:
`bpf_bpfel.go`, `bpf_bpfeb.go`, `bpf_bpf*.o` — these ARE committed (bpf2go embeds
the `.o` via `//go:embed`), so a plain `go build`/`go install` works without
`bpftool`/`clang`; only `make build`/`go generate` needs them.

## Layout (all `package main`)
- `main.go` — flag parsing (`-time-format`), eBPF open, auto-selects TUI vs plain by
  `isTerminal(os.Stdout)`, signal handling.
- `capture.go` — `Event` (matches `bpf.c`), `Session`, thread-safe `Store`, BPF load/attach,
  ring-buffer reader, `cmdlineResolver` (turns `Event.PID` into a `ps aux`-style command line
  via `/proc/<pid>/cmdline`, cached per pid and invalidated on `/proc/<pid>/stat` starttime
  change = PID reuse; empty/missing cmdline or pid 0 → `[comm]`; a dead process keeps its last
  resolved value), and `bpf_ktime_get_ns()`→wall-clock conversion (via `CLOCK_MONOTONIC`
  offset from `golang.org/x/sys/unix`; falls back to `time.Now()` if unavailable).
- `view.go` — pure grouping/sorting/filter logic (`GroupMode`, `SortMode`, `ProtoMode`,
  `buildView`); no
  tview. `buildView` takes a `now time.Time` (passed by `tui.viewRows`) and derives live
  durations via `effectiveDuration` (active rows = `now - Start`; frozen `Session.Duration`
  is only as fresh as the last event), used for `SortDuration` comparisons, group totals and
  `viewRow.Dur` — so `renderSessionRow` must NOT recompute duration from `time.Since`.
  `buildView` also takes a `textFilter` (compiled in `tui` on every filter edit via
  `compileFilter`; `tui.flt`) and a `ProtoMode` (`tui` cycles All/TCP/UDP with the `t` key,
  shown in the summary): `filterSessions` ANDs the two. The text filter is a full regexp
  (`regexp.Compile`, user-supplied flags only — no implicit `(?i)`) matched against the
  command line, PID, addresses and (TCP only — UDP state is excluded, not `?`) the state
  name; an empty pattern matches everything, an invalid one matches nothing and the summary
  shows `filter: <pattern> (invalid regexp)` in red.
- `tui.go` / `tui_modals.go` — tview app, live refresh, modals, keybindings. `rebuild()`
  pins the cursor to the selected row's identity (session `viewRow.ID` / group key)
  resolved against `tui.lastRows` — the list rendered on the *previous* rebuild (the fresh
  `viewRows()` may already contain new connections, so indexing it with the old selection
  would describe a different row) — and restores the scroll offset across the
  re-render. No scroll auto-adjustment: the viewport stays where the user put it.
- `plain.go` — tcplife-style streaming output.
- `format.go` — `humanBytes`/`humanRate`/`humanDuration`/`formatTime`/`tcpStateName`, named time-layout map + `resolveTimeLayout`.
Run-time needs privileges to load maps/prog (usually root or `CAP_BPF`+`CAP_PERFMON`); on
kernels without memcg-based accounting you may also have to raise `RLIMIT_MEMLOCK` (the code
does not call `rlimit.RemoveMemlock` itself).

## Hard gotchas
- `bpf.c` MUST keep `//go:build ignore` on line 1. Without it `go build` fails with
  `C source files not allowed when not using cgo or SWIG`. gopls/LSP keeps reporting this
  same error on `bpf.go`/`main.go`/generated files — it is a false positive; trust `make build`.
- Kernel structs (`trace_event_raw_inet_sock_set_state`, `tcp_sock`, TCP state enums,
  `IPPROTO_TCP`) come from `vmlinux.h` via CO-RE. Do not hand-write them. `AF_INET`/
  `AF_INET6` are NOT in `vmlinux.h`; they are `#define`d locally in `bpf.c`.
- Reading kernel pointers (e.g. `tcp_sock.bytes_acked` / `bytes_received`) must use
  `BPF_CORE_READ`; a direct dereference is rejected by the verifier. Direct reads of the
  tracepoint context (`args->...`) are fine.
- Endianness of the 4-tuple: the `inet_sock_set_state` raw tracepoint fields `sport`/`dport`
  are ALREADY host-order (the kernel's `TP_fast_assign` applies `ntohs`), so
  `set_addrs_from_args` copies them directly — do not add byte swapping. The `saddr`/`daddr`
  arrays are raw network-order bytes (correct for `net.IP` as-is). `fill_addrs` reads live
  socket fields instead: `skc_num` is host-order, `skc_dport` is BE and needs `bpf_ntohs`.
- The tracepoint context starts with an 8-byte `struct trace_entry` header, so `skaddr`
  is at offset 8, not 0. `vmlinux.h` handles this; don't re-introduce offset-0 casts.

## C <-> Go contract
- `struct event` in `bpf.c` and `Event` in `capture.go` must match exactly and stay
  padding-free: `capture.go` decodes ring-buffer samples with `encoding/binary` sequentially
  (it does not account for C struct padding). Reordering or inserting an unaligned field
  breaks decoding. `struct event` leads with `__u64 skaddr` (socket pointer = session id),
  then `__u64 ts` (emit time from `bpf_ktime_get_ns()`), and carries `__u8 active`
  (1 = realtime snapshot of an open connection, 0 = final session on close) plus `__u8 dir`
  (1 = outgoing/client, set at `SYN_SENT`; 0 = incoming/server, set at `SYN_RECV`/accept).
  `dir` lives right after `active` (a byte array with 1-byte alignment) so the C and Go
  layouts stay byte-identical; `capture.go` surfaces it as `Session.Out` and the TUI draws it
  as a `→`/`←` arrow before the remote address (plain mode ignores it). `__u8 state` (the
  latest `newstate`, a TCP_* enum 1-12) follows `dir` for the same alignment reason; it maps
  to `Session.State` and renders via `tcpStateName` in the STATE column. `__u8 proto`
  (IPPROTO_TCP=6 / IPPROTO_UDP=17) follows `state`; `struct start_val` gained `proto` plus
  `__u64 rx/tx` (UDP byte counters; unused for TCP). UDP rows keep `state` 0 and the TUI
  renders STATE blank for them.
- Generated identifiers: `bpfObjects`, `objs.TcpState`, `objs.TcpCleanup`,
  `objs.TcpSendmsgExit`, `objs.InetCskAcceptExit`, `objs.UdpSendmsgExit`,
  `objs.UdpRecvmsgExit`, `objs.UdpDestroySockExit`, `objs.Events`, `objs.Start`,
  `objs.UdpStart`, `objs.UdpHeads` (from `bpf2go`).

## Realtime traffic
Besides the close-time event, `bpf.c` attaches three `fentry`/`fexit` probes:
- `SEC("fentry/tcp_cleanup_rbuf")` → `objs.TcpCleanup` (receive signal).
- `SEC("fexit/tcp_sendmsg")` → `objs.TcpSendmsgExit` (send signal).
- `SEC("fexit/inet_csk_accept")` → `objs.InetCskAcceptExit` (owner of incoming
  connections).
The two data-path probes are only *triggers*: they look up the socket in the `start`
map (which caches identity, addresses and a per-socket `last_emit`), read exact
`tcp_sock.bytes_received`/`bytes_acked` via `BPF_CORE_READ`, and emit an `active=1`
event — throttled to once per `ACTIVE_INTERVAL_NS` (250 ms) per socket. They also
backfill `sv->pid`/`comm` from the (process-context) current task if still unset.

Ownership/attribution notes:
- `SYN_SENT` (outgoing) emits immediately even though `args->sport` and the local
  address are usually still 0 at that point (the kernel enters `TCP_SYN_SENT` *before*
  `inet_hash_connect()` assigns the local port): attempts that never get an ACK and so
  skip `ESTABLISHED` must still be visible. The row shows `0.0.0.0:0` until the first
  `ESTABLISHED`/teardown/`CLOSE` event (whose `args` carry the real 4-tuple) refreshes it.
  `SYN_RECV` does NOT emit — it runs in softirq where the owner is unknown.
- `ESTABLISHED` refreshes cached addresses from `args` but only emits when `sv->pid != 0`.
- All other teardown states (FIN_WAIT1/2, CLOSING, TIME_WAIT, CLOSE_WAIT, LAST_ACK) are
  recorded into `sv->state` and emit an `active=1` event when `sv->pid != 0` (rare, so
  unthrottled); `LAST_ACK` also backfills `sv->pid`/`comm`. This keeps the STATE column live.
- `fexit/inet_csk_accept` sets `sv->pid`/`comm` to the accepting process (in its own
  context) and emits, so incoming connections show the real owner (e.g. `sshd-session`,
  never a `napi/*` kernel thread) from the moment they are accepted.
- Tracepoint events (SYN/ESTABLISHED/CLOSE) take the 4-tuple from `args`; data-path/accept
  events read it from the socket via `fill_addrs` with per-field fallback to cached `sv`
  (a socket can transiently report a 0 local port).
`capture.go` attaches these best-effort (`attachRealtime`); if unavailable it prints a
warning and degrades to close-only. The `Store` upserts by `skaddr`, the TUI fills a
`STATE` column (after `TX/s`) with `tcpStateName` for active rows (blank once closed and
always blank for UDP) and recomputes `DURATION` each refresh; plain mode
ignores `active=1`. Table
column order is defined by the `colTime..colComm` iota block in `view.go` (`colCount` is the
total): `TIME DURATION PID PROTO LADDR RADDR RX TX RX/s TX/s STATE COMMAND`. The `COMMAND`
cell holds the full `ps aux`-style command line (see the cmdline resolver below) and is
**never clipped**: the table scrolls horizontally instead (tview's `columnOffset`, moved with
the ←/→ keys — columns are not selectable, so the table handles them). The `RX/s`/`TX/s` columns
show a live per-second rate for active rows only; `Store.Tick(now)` (called every refresh
tick in the TUI loop when not paused) recomputes them as a sliding-window delta of the
cumulative counters so idle connections decay to 0 — plain mode never calls it. Closed
sessions carry zero rates (`Upsert` zeroes them; `Tick` also clears any leftover on an
already-inactive entry), so `Store.Rates()` sums only live per-second traffic for the
`RX/s`/`TX/s` totals in the summary header (next to the `Stats()` `RX`/`TX` totals). Active
**UDP** rows hide both rate cells while `RxRate` and `TxRate` are both 0 (`rateVisible`);
TCP always renders the values (`0 B/s` included). Group rows
sum `RxRate`/`TxRate` and render them (bold; blank when 0). The rate columns never resize:
`tui.rateW` remembers the widest `humanRate` string ever seen and `padRate` left-pads every
rate cell (active rows, and blank cells of inactive/group rows) to that width, so columns
only grow, never shrink. Keep `renderGroupRow`'s loop bound at `colCount`. The header marks
the column(s) the active sort mode orders by with `view.go:sortColumns` + `dirArrow(m.asc)`
(`↑`/`↓`); the sum modes (RX+TX, RX/s+TX/s) mark both component columns.

## UDP flows
UDP has no connection states, so a "session" is a flow keyed by 4-tuple
(`struct flow_key`): one row per peer — an unconnected server socket gets a separate row
for every remote address it exchanges datagrams with. Mechanics (`bpf.c`):
- Maps: `udp_start` (key = `flow_key`, value = `udp_val{start_val sv; prev flow}`) plus
  `udp_heads` (key = skaddr) forming a per-socket chain of flows via `prev`/`has_prev`.
- Accounting at the API level: `fexit/udp_sendmsg` and `fexit/udp_recvmsg` add `ret > 0`
  bytes to `sv->tx`/`sv->rx` (`__sync_fetch_and_add`) and emit `active=1` snapshots
  throttled by `ACTIVE_INTERVAL_NS` (first event emits unthrottled). `read()`/`write()` and
  `send()`/`recv()` all funnel through these; datagrams received but never read are NOT
  counted (deliberate tradeoff).
- The peer comes from `msg->msg_name` (sendto/recvfrom on unconnected sockets; connected
  sockets fall back to `skc_daddr`/`skc_dport`). An unconnected server's `raddr` may show
  `0.0.0.0:0` — expected, like `ss`.
- `emit_udp()` (not `emit()`): byte counters from `sv->rx/tx` (never from `tcp_sock`),
  addresses from the cached flow identity, and `e->skaddr` = FNV-1a hash of the flow key —
  the flow hash is the Store/row id for UDP (the socket pointer cannot distinguish peers).
- Flow close == socket close: `fexit/udp_destroy_sock` walks the per-socket chain (capped
  at `UDP_FLOW_MAX` = 256; overflow leaves stale rows until map pressure evicts them),
  emits `active=0` finals and deletes entries. No timeouts anywhere.
- `dir`/`Out` is fixed by the first event on the flow (send → `→`, recv → `←`); `state`
  stays 0 (STATE column blank). `capture.go` attaches these via `attachUdp` best-effort
  and separately from TCP realtime (`udp disabled (fentry/fexit): ...` warning).

## Verify
- `make build`, `go vet ./...`, `gofmt -l .`, and `go test ./...` (unit tests in
  `format_test.go` and friends cover the pure logic: layouts, grouping, sorting).
- **Never launch `./bin` yourself** (even ad hoc, even with `sudo`/root) to test
  eBPF loading or attach paths — there is no passwordless sudo, and running it is
  disruptive. The user runs the tool manually; report what changed and let them
  verify. This applies outside `make build`/`go vet`/`go test` verification too.
- Do not attempt to run `./bin` during verification: loading the program needs root/
  `CAP_BPF` + memlock and the TUI needs a real TTY. Parsing flags (`-h`, bad `-time-format`)
  is safe because it exits before `openCapture`.
