package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func fakeProc(t *testing.T, pid uint32, comm string, start uint64, cmdline string) string {
	t.Helper()

	root := t.TempDir()
	dir := filepath.Join(root, strconv.FormatUint(uint64(pid), 10))

	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(dir, "cmdline"), []byte(cmdline), 0o644); err != nil {
		t.Fatal(err)
	}

	// Tokens after the closing paren: state first (field 3), so starttime
	// (field 22) must land at index 19.
	stat := fmt.Sprintf("%d (%s) S 1 1 1 0 -1 4194304 100 200 0 0 10 20 30 40 20 0 1 0 %d 12345 100 0 0\n", pid, comm, start)
	if err := os.WriteFile(filepath.Join(dir, "stat"), []byte(stat), 0o644); err != nil {
		t.Fatal(err)
	}

	return root
}

func TestCmdlineResolver(t *testing.T) {
	root := fakeProc(t, 4321, "curl", 100, "curl\x00-sS\x00http://example.com\x00")
	r := &cmdlineResolver{root: root, cache: make(map[uint32]cmdlineCacheEntry)}

	if got := r.resolve(4321, "curl"); got != "curl -sS http://example.com" {
		t.Errorf("resolve = %q", got)
	}

	// Kernel thread (empty cmdline) gets the ps-style bracket fallback.
	kt := fakeProc(t, 22, "kworker/0:1", 50, "\x00\x00")
	kr := &cmdlineResolver{root: kt, cache: make(map[uint32]cmdlineCacheEntry)}
	if got := kr.resolve(22, "kworker/0:1"); got != "[kworker/0:1]" {
		t.Errorf("kernel resolve = %q", got)
	}

	if got := r.resolve(0, "swapper"); got != "[swapper]" {
		t.Errorf("pid 0 = %q", got)
	}
}

func TestCmdlineResolverCacheAndReuse(t *testing.T) {
	root := fakeProc(t, 4321, "old", 100, "old-app\x00--x\x00")
	r := &cmdlineResolver{root: root, cache: make(map[uint32]cmdlineCacheEntry)}

	if got := r.resolve(4321, "old"); got != "old-app --x" {
		t.Fatalf("first resolve = %q", got)
	}

	// Same start time: the cached value wins even though the files changed.
	dir := filepath.Join(root, "4321")
	os.WriteFile(filepath.Join(dir, "cmdline"), []byte("mutated\x00"), 0o644)

	if got := r.resolve(4321, "old"); got != "old-app --x" {
		t.Errorf("cached resolve = %q, want old-app --x", got)
	}

	// PID recycled (new start time) with a new command: re-read.
	os.WriteFile(filepath.Join(dir, "stat"),
		[]byte("4321 (new) S 1 1 1 0 -1 4194304 100 200 0 0 10 20 30 40 20 0 1 0 999 12345 100 0 0\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "cmdline"), []byte("new-app\x00--y\x00"), 0o644)

	if got := r.resolve(4321, "new"); got != "new-app --y" {
		t.Errorf("reuse resolve = %q, want new-app --y", got)
	}
}

func TestCmdlineResolverDeadProcess(t *testing.T) {
	root := fakeProc(t, 4321, "svc", 100, "svc\x00--run\x00")
	r := &cmdlineResolver{root: root, cache: make(map[uint32]cmdlineCacheEntry)}

	r.resolve(4321, "svc")

	// The process exited: the last known command line is kept.
	os.RemoveAll(filepath.Join(root, "4321"))

	if got := r.resolve(4321, "svc"); got != "svc --run" {
		t.Errorf("dead cached = %q, want svc --run", got)
	}

	// Never-seen pid, unreadable /proc: plain comm fallback.
	if got := r.resolve(777, "ghost"); got != "[ghost]" {
		t.Errorf("unknown pid = %q, want [ghost]", got)
	}
}
