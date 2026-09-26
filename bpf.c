//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#define AF_INET		2
#define AF_INET6	10
#define TASK_COMM_LEN	16
#define ACTIVE_INTERVAL_NS 250000000ULL /* 250 ms */

struct event {
    __u64 skaddr;
    __u64 ts;
    __u64 duration_ns;
    __u64 bytes_received;
    __u64 bytes_acked;
    __u32 pid;
    __u16 family;
    __u16 sport;
    __u16 dport;
    __u8  active;
    __u8  dir;
    __u8  state;
    __u8  proto;
    __u8  saddr[16];
    __u8  daddr[16];
    char  comm[TASK_COMM_LEN];
};

struct start_val {
    __u64 ts;
    __u64 last_emit;
    __u64 rx;
    __u64 tx;
    __u32 pid;
    __u16 family;
    __u16 sport;
    __u16 dport;
    __u8  dir;
    __u8  state;
    __u8  proto;
    __u8  saddr[16];
    __u8  daddr[16];
    char  comm[TASK_COMM_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, struct start_val);
    __uint(max_entries, 65536);
} start SEC(".maps");

// UDP has no connection states, so a "session" is a flow: local tuple +
// remote tuple. One connected/unconnected socket may serve many peers, so
// each peer gets its own flow entry; flows are chained per socket (via
// udp_heads + prev) so udp_destroy_sock can finalize all of them on close().
struct flow_key {
    __u8  saddr[16];
    __u8  daddr[16];
    __u16 sport;
    __u16 dport;
    __u16 family;
};

struct udp_val {
    struct start_val sv;
    struct flow_key  prev;
    __u8  has_prev;
    __u8  __pad[7];
};

#define UDP_FLOW_MAX 256

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct flow_key);
    __type(value, struct udp_val);
    __uint(max_entries, 32768);
} udp_start SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, struct flow_key);
    __uint(max_entries, 32768);
} udp_heads SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

// COPY_ADDRS_FROM_ARGS copies the authoritative 4-tuple carried by the
// inet_sock_set_state tracepoint args into a struct that has the same
// family/sport/dport/saddr/daddr fields (struct event or struct start_val).
#define COPY_ADDRS_FROM_ARGS(dst, args) do {                       \
    (dst)->family = (args)->family;                                \
    (dst)->sport = (args)->sport;                                  \
    (dst)->dport = (args)->dport;                                  \
    if ((args)->family == AF_INET) {                               \
        __builtin_memcpy((dst)->saddr, (args)->saddr, 4);          \
        __builtin_memcpy((dst)->daddr, (args)->daddr, 4);          \
    } else {                                                       \
        __builtin_memcpy((dst)->saddr, (args)->saddr_v6, 16);      \
        __builtin_memcpy((dst)->daddr, (args)->daddr_v6, 16);      \
    }                                                              \
} while (0)

// set_addrs_from_args fills the 4-tuple from the tracepoint arguments, which
// are authoritative for events emitted from tcp_state (SYN/ESTABLISHED/CLOSE).
static __always_inline void set_addrs_from_args(
    struct event *e, struct trace_event_raw_inet_sock_set_state *args)
{
    COPY_ADDRS_FROM_ARGS(e, args);
}

// save_addrs_from_args caches the authoritative 4-tuple in a start_val so
// later data-path events (which read live socket fields) can fall back to it.
static __always_inline void save_addrs_from_args(
    struct start_val *sv, struct trace_event_raw_inet_sock_set_state *args)
{
    COPY_ADDRS_FROM_ARGS(sv, args);
}

// fill_addrs reads the 4-tuple from the socket for the data-path hooks. A
// socket can briefly report a zero local port (e.g. a server child at
// SYN_RECV before its port is copied from the listener), so each field falls
// back to the cached value in start_val when the live read yields 0.
static __always_inline void fill_addrs(struct event *e, __u64 sk, struct start_val *sv)
{
    struct sock *skp = (struct sock *)sk;
    __u16 family = BPF_CORE_READ(skp, __sk_common.skc_family);

    if (!family) {
        e->family = sv->family;
        e->sport = sv->sport;
        e->dport = sv->dport;
        __builtin_memcpy(e->saddr, sv->saddr, sizeof(e->saddr));
        __builtin_memcpy(e->daddr, sv->daddr, sizeof(e->daddr));
        return;
    }

    __u16 sport = BPF_CORE_READ(skp, __sk_common.skc_num);
    __be16 dport = BPF_CORE_READ(skp, __sk_common.skc_dport);

    e->family = family;
    e->sport = sport ? sport : sv->sport;
    e->dport = dport ? bpf_ntohs(dport) : sv->dport;

    if (family == AF_INET) {
        __be32 saddr = BPF_CORE_READ(skp, __sk_common.skc_rcv_saddr);
        __be32 daddr = BPF_CORE_READ(skp, __sk_common.skc_daddr);

        if (!saddr)
            __builtin_memcpy(&saddr, sv->saddr, 4);
        if (!daddr)
            __builtin_memcpy(&daddr, sv->daddr, 4);

        __builtin_memcpy(e->saddr, &saddr, 4);
        __builtin_memcpy(e->daddr, &daddr, 4);
    } else {
        BPF_CORE_READ_INTO(&e->saddr, skp, __sk_common.skc_v6_rcv_saddr);
        BPF_CORE_READ_INTO(&e->daddr, skp, __sk_common.skc_v6_daddr);
    }
}

// fill_emitter copies the owner pid/comm into the event, falling back to the
// current task when the socket owner is still unknown (e.g. softirq paths).
static __always_inline void fill_emitter(struct event *e, struct start_val *sv)
{
    e->pid = sv->pid;
    if (!e->pid)
        e->pid = bpf_get_current_pid_tgid() >> 32;

    if (sv->comm[0])
        __builtin_memcpy(e->comm, sv->comm, sizeof(e->comm));
    else
        bpf_get_current_comm(&e->comm, sizeof(e->comm));
}

// set_current_owner attributes a start_val to the current task, used wherever
// the owning process runs in its own context (send/recv/accept).
static __always_inline void set_current_owner(struct start_val *sv)
{
    sv->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&sv->comm, sizeof(sv->comm));
}

// emit pushes a snapshot of an in-flight socket to userspace.
// active == 1: realtime update; active == 0: final session on close.
// args != NULL: emitted from the tracepoint -> use the authoritative 4-tuple.
static __always_inline int emit(struct start_val *sv, __u64 sk, __u8 active,
                               struct trace_event_raw_inet_sock_set_state *args)
{
    struct event *e;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    struct tcp_sock *tp = (struct tcp_sock *)sk;
    __u64 now = bpf_ktime_get_ns();

    e->skaddr = sk;
    e->ts = now;
    e->duration_ns = now - sv->ts;
    e->bytes_received = BPF_CORE_READ(tp, bytes_received);
    e->bytes_acked = BPF_CORE_READ(tp, bytes_acked);
    e->active = active;
    e->dir = sv->dir;
    e->state = sv->state;
    e->proto = sv->proto;

    fill_emitter(e, sv);

    if (args)
        set_addrs_from_args(e, args);
    else
        fill_addrs(e, sk, sv);

    bpf_ringbuf_submit(e, 0);

    return 0;
}

SEC("tracepoint/sock/inet_sock_set_state")
int tcp_state(struct trace_event_raw_inet_sock_set_state *args)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    if (args->protocol != IPPROTO_TCP)
        return 0;

    __u64 key = (__u64)args->skaddr;
    __s32 newstate = args->newstate;

    if (newstate == BPF_TCP_SYN_SENT || newstate == BPF_TCP_SYN_RECV) {
        struct start_val *old = bpf_map_lookup_elem(&start, &key);
        struct start_val val = {};

        val.ts = old ? old->ts : bpf_ktime_get_ns();

        if (newstate == BPF_TCP_SYN_SENT) {
            val.pid = pid;
            val.dir = 1; // outgoing: this host sent SYN
            bpf_get_current_comm(&val.comm, sizeof(val.comm));
        } else if (old) {
            val.pid = old->pid;
            val.dir = old->dir;
            __builtin_memcpy(val.comm, old->comm, sizeof(val.comm));
        }

        val.state = (__u8)newstate;
        val.proto = IPPROTO_TCP;
        save_addrs_from_args(&val, args);

        bpf_map_update_elem(&start, &key, &val, BPF_ANY);

        struct start_val *sv = bpf_map_lookup_elem(&start, &key);

        // Surface outgoing (client) connections at once, even before the
        // kernel assigns a local port: tcp_set_state(TCP_SYN_SENT) runs
        // before inet_hash_connect(), so args->sport (and often the local
        // addr) are still 0 here. The remote tuple is already real, so the
        // row shows 0.0.0.0:0 -> peer until the first ESTABLISHED/CLOSE
        // refreshes it. This is what makes attempts that never get an ACK (no
        // ESTABLISHED at all) visible. Server children stay silent: SYN_RECV
        // is softirq (owner unknown, port 0) and is revealed by the accept
        // hook (fexit/inet_csk_accept).
        if (sv && newstate == BPF_TCP_SYN_SENT) {
            sv->last_emit = bpf_ktime_get_ns();
            emit(sv, key, 1, args);
        }

        return 0;
    }

    if (newstate == BPF_TCP_ESTABLISHED) {
        struct start_val *sv = bpf_map_lookup_elem(&start, &key);

        if (sv) {
            sv->state = (__u8)newstate;
            save_addrs_from_args(sv, args);

            // Client connections already know their owner here; for a server
            // child (pid == 0, softirq) skip and let the accept hook surface it.
            if (sv->pid) {
                sv->last_emit = bpf_ktime_get_ns();
                emit(sv, key, 1, args);
            }
        }

        return 0;
    }

    struct start_val *sv = bpf_map_lookup_elem(&start, &key);

    if (!sv)
        return 0;

    sv->state = (__u8)newstate;

    if (newstate == BPF_TCP_CLOSE) {
        emit(sv, key, 0, args);

        bpf_map_delete_elem(&start, &key);

        return 0;
    }

    if (newstate == BPF_TCP_LAST_ACK) {
        sv->pid = pid;
        bpf_get_current_comm(&sv->comm, sizeof(sv->comm));
    }

    // Surface teardown transitions (FIN_WAIT*, CLOSING, TIME_WAIT,
    // CLOSE_WAIT, ...) so the state column stays live. They are rare, so no
    // throttling; skipped while the owner is unknown (pre-accept softirq).
    if (sv->pid) {
        sv->last_emit = bpf_ktime_get_ns();
        emit(sv, key, 1, args);
    }

    return 0;
}

// activity-based realtime snapshots: no per-packet cost beyond a map lookup,
// throttled per socket to at most one event per ACTIVE_INTERVAL_NS.
SEC("fentry/tcp_cleanup_rbuf")
int BPF_PROG(tcp_cleanup, struct sock *sk, int copied)
{
    __u64 key = (__u64)sk;
    struct start_val *sv = bpf_map_lookup_elem(&start, &key);

    if (!sv)
        return 0;

    // Owner process runs recv() in process context: fill in what SYN missed.
    if (!sv->pid)
        set_current_owner(sv);

    __u64 now = bpf_ktime_get_ns();

    if (now - sv->last_emit < ACTIVE_INTERVAL_NS)
        return 0;

    sv->last_emit = now;
    emit(sv, key, 1, NULL);

    return 0;
}

SEC("fexit/tcp_sendmsg")
int BPF_PROG(tcp_sendmsg_exit, struct sock *sk, struct msghdr *msg, size_t size, int ret)
{
    __u64 key = (__u64)sk;
    struct start_val *sv = bpf_map_lookup_elem(&start, &key);

    if (!sv)
        return 0;

    // Owner process runs send() in process context: fill in what SYN missed.
    if (!sv->pid)
        set_current_owner(sv);

    __u64 now = bpf_ktime_get_ns();

    if (now - sv->last_emit < ACTIVE_INTERVAL_NS)
        return 0;

    sv->last_emit = now;
    emit(sv, key, 1, NULL);

    return 0;
}

// accept() runs in the server process context and returns the accepted child
// socket, so this is where an incoming connection gets its real owner (fixes
// misattribution to softirq/kernel threads like napi/phy-0).
// Prototype is inet_csk_accept(struct sock *sk, int *err) -> struct sock *;
// for fexit the final BPF_PROG argument is the return value.
SEC("fexit/inet_csk_accept")
int BPF_PROG(inet_csk_accept_exit, struct sock *sk, int *err, struct sock *ret)
{
    if (!ret || (long)ret < 0)
        return 0;

    __u64 key = (__u64)ret;
    struct start_val *sv = bpf_map_lookup_elem(&start, &key);

    if (!sv)
        return 0;

    set_current_owner(sv);

    sv->dir = 0; // incoming: accepted by this host

    sv->last_emit = bpf_ktime_get_ns();
    emit(sv, key, 1, NULL);

    return 0;
}

// flow_hash folds a flow key into the 64-bit session id for UDP rows
// (skaddr alone cannot distinguish peers of one unconnected socket).
static __always_inline __u64 flow_hash(const struct flow_key *k)
{
    const unsigned char *p = (const unsigned char *)k;
    __u64 h = 1469598103934665603ULL; /* FNV-1a */

    for (int i = 0; i < (int)sizeof(*k); i++) {
        h ^= p[i];
        h *= 1099511628211ULL;
    }

    return h;
}

// udp_fill_flow builds the flow key from the socket and the peer address
// passed to sendto()/recvfrom(): an unconnected socket reports the actual
// peer in msg->msg_name during the call; the socket's own daddr/dport only
// reflect a connected peer.
static __always_inline void udp_fill_flow(struct sock *skp,
                                          struct msghdr *msg,
                                          struct flow_key *fk)
{
    __u16 family = BPF_CORE_READ(skp, __sk_common.skc_family);

    fk->family = family;
    fk->sport = BPF_CORE_READ(skp, __sk_common.skc_num);

    void *name = BPF_CORE_READ(msg, msg_name);

    if (family == AF_INET) {
        __be32 saddr = BPF_CORE_READ(skp, __sk_common.skc_rcv_saddr);
        __builtin_memcpy(fk->saddr, &saddr, 4);

        __be32 daddr = BPF_CORE_READ(skp, __sk_common.skc_daddr);
        __be16 dport = BPF_CORE_READ(skp, __sk_common.skc_dport);

        if (name) {
            struct sockaddr_in *sin = name;

            if (BPF_CORE_READ(sin, sin_family) == AF_INET) {
                daddr = BPF_CORE_READ(sin, sin_addr.s_addr);
                dport = BPF_CORE_READ(sin, sin_port);
            }
        }

        __builtin_memcpy(fk->daddr, &daddr, 4);
        fk->dport = bpf_ntohs(dport);
    } else {
        BPF_CORE_READ_INTO(&fk->saddr, skp, __sk_common.skc_v6_rcv_saddr);
        BPF_CORE_READ_INTO(&fk->daddr, skp, __sk_common.skc_v6_daddr);
        fk->dport = bpf_ntohs(BPF_CORE_READ(skp, __sk_common.skc_dport));

        if (name) {
            struct sockaddr_in6 *sin6 = name;

            if (BPF_CORE_READ(sin6, sin6_family) == AF_INET6) {
                BPF_CORE_READ_INTO(&fk->daddr, sin6, sin6_addr);
                fk->dport = bpf_ntohs(BPF_CORE_READ(sin6, sin6_port));
            }
        }
    }
}

static __always_inline void udp_sv_identity(struct start_val *sv,
                                            const struct flow_key *fk)
{
    sv->family = fk->family;
    sv->sport = fk->sport;
    sv->dport = fk->dport;
    __builtin_memcpy(sv->saddr, fk->saddr, sizeof(sv->saddr));
    __builtin_memcpy(sv->daddr, fk->daddr, sizeof(sv->daddr));
}

// emit_udp pushes a UDP flow snapshot: addresses come from the cached flow
// identity (live socket fields may not match the packet's peer) and the
// byte counters are the accumulated sendmsg/recvmsg totals, not tcp_sock
// fields. id is the flow hash, not the socket pointer.
static __always_inline int emit_udp(struct start_val *sv, __u64 id, __u8 active)
{
    struct event *e;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    __u64 now = bpf_ktime_get_ns();

    e->skaddr = id;
    e->ts = now;
    e->duration_ns = now - sv->ts;
    e->bytes_received = sv->rx;
    e->bytes_acked = sv->tx;
    e->active = active;
    e->dir = sv->dir;
    e->state = 0;
    e->proto = IPPROTO_UDP;

    fill_emitter(e, sv);

    e->family = sv->family;
    e->sport = sv->sport;
    e->dport = sv->dport;
    __builtin_memcpy(e->saddr, sv->saddr, sizeof(e->saddr));
    __builtin_memcpy(e->daddr, sv->daddr, sizeof(e->daddr));

    bpf_ringbuf_submit(e, 0);

    return 0;
}

// udp_traffic records sendmsg/recvmsg bytes for a flow and emits throttled
// active snapshots, creating the flow (and its per-socket chain link) on
// first sight. The first event also fixes dir: send -> outgoing,
// recv -> incoming (UDP has no handshake to derive it from otherwise).
static __always_inline int udp_traffic(struct sock *sk, struct msghdr *msg,
                                       __u64 bytes, __u8 incoming)
{
    __u64 skaddr = (__u64)sk;
    struct flow_key fk = {};

    udp_fill_flow(sk, msg, &fk);

    __u64 id = flow_hash(&fk);
    __u64 now = bpf_ktime_get_ns();

    struct udp_val *uv = bpf_map_lookup_elem(&udp_start, &fk);

    if (uv) {
        if (!uv->sv.pid)
            set_current_owner(&uv->sv);

        udp_sv_identity(&uv->sv, &fk);

        if (incoming)
            __sync_fetch_and_add(&uv->sv.rx, bytes);
        else
            __sync_fetch_and_add(&uv->sv.tx, bytes);

        if (now - uv->sv.last_emit < ACTIVE_INTERVAL_NS)
            return 0;

        uv->sv.last_emit = now;
        emit_udp(&uv->sv, id, 1);

        return 0;
    }

    struct udp_val v = {};

    v.sv.ts = now;
    v.sv.last_emit = now;
    set_current_owner(&v.sv);
    v.sv.proto = IPPROTO_UDP;
    v.sv.rx = incoming ? bytes : 0;
    v.sv.tx = incoming ? 0 : bytes;
    v.sv.dir = incoming ? 0 : 1;
    udp_sv_identity(&v.sv, &fk);

    struct flow_key *head = bpf_map_lookup_elem(&udp_heads, &skaddr);

    if (head) {
        v.prev = *head;
        v.has_prev = 1;
    }

    bpf_map_update_elem(&udp_heads, &skaddr, &fk, BPF_ANY);
    bpf_map_update_elem(&udp_start, &fk, &v, BPF_ANY);

    emit_udp(&v.sv, id, 1);

    return 0;
}

// read()/write() and send()/recv() all funnel through these two, so the
// API-level accounting covers every userspace data path (at the cost of
// not counting datagrams that were received but never read).
SEC("fexit/udp_sendmsg")
int BPF_PROG(udp_sendmsg_exit, struct sock *sk, struct msghdr *msg,
             size_t len, int ret)
{
    if (ret <= 0)
        return 0;

    return udp_traffic(sk, msg, (__u64)ret, 0);
}

SEC("fexit/udp_recvmsg")
int BPF_PROG(udp_recvmsg_exit, struct sock *sk, struct msghdr *msg,
             size_t len, int flags, int ret)
{
    if (ret <= 0)
        return 0;

    return udp_traffic(sk, msg, (__u64)ret, 1);
}

// close() of a UDP socket finalizes every flow chained under it. The chain
// walk is capped at UDP_FLOW_MAX; overflow (only possible on sockets with
// more distinct peers than that) leaves stale rows until map pressure
// evicts them.
SEC("fexit/udp_destroy_sock")
int BPF_PROG(udp_destroy_sock_exit, struct sock *sk)
{
    __u64 skaddr = (__u64)sk;

    struct flow_key *head = bpf_map_lookup_elem(&udp_heads, &skaddr);

    if (!head)
        return 0;

    struct flow_key cur = *head;
    int has = 1;

    for (int i = 0; i < UDP_FLOW_MAX && has; i++) {
        struct udp_val *uv = bpf_map_lookup_elem(&udp_start, &cur);

        if (!uv)
            break;

        emit_udp(&uv->sv, flow_hash(&cur), 0);

        has = uv->has_prev;
        struct flow_key nxt = uv->prev;

        bpf_map_delete_elem(&udp_start, &cur);
        cur = nxt;
    }

    bpf_map_delete_elem(&udp_heads, &skaddr);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
