package main

import (
	"testing"
	"time"
)

func TestResolveTimeLayoutNamed(t *testing.T) {
	cases := map[string]string{
		"time":        time.TimeOnly,
		"TIME":        time.TimeOnly,
		" Time ":      time.TimeOnly,
		"date":        time.DateOnly,
		"datetime":    time.DateTime,
		"DateTime":    time.DateTime,
		"timeonly":    time.TimeOnly,
		"dateonly":    time.DateOnly,
		"rfc3339":     time.RFC3339,
		"RFC3339":     time.RFC3339,
		"rfc3339nano": time.RFC3339Nano,
		"RFC3339Nano": time.RFC3339Nano,
		"kitchen":     time.Kitchen,
		"stamp":       time.Stamp,
		"stampmilli":  time.StampMilli,
		"unixdate":    time.UnixDate,
		"rfc1123z":    time.RFC1123Z,
	}

	for in, want := range cases {
		got, err := resolveTimeLayout(in)
		if err != nil {
			t.Errorf("resolveTimeLayout(%q): unexpected error %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("resolveTimeLayout(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestResolveTimeLayoutCustom(t *testing.T) {
	custom := "2006-01-02 15:04:05"

	got, err := resolveTimeLayout(custom)
	if err != nil {
		t.Fatalf("custom layout rejected: %v", err)
	}
	if got != custom {
		t.Fatalf("resolveTimeLayout(%q) = %q, want verbatim", custom, got)
	}
}

func TestResolveTimeLayoutEmpty(t *testing.T) {
	for _, in := range []string{"", "   "} {
		if _, err := resolveTimeLayout(in); err == nil {
			t.Errorf("resolveTimeLayout(%q) = nil error, want error", in)
		}
	}
}

func TestTimeLayoutWidth(t *testing.T) {
	if got := timeLayoutWidth(time.TimeOnly); got != len("15:04:05") {
		t.Errorf("width(TimeOnly) = %d, want %d", got, len("15:04:05"))
	}

	if got := timeLayoutWidth("2006-01-02 15:04:05"); got != 19 {
		t.Errorf("width(custom) = %d, want 19", got)
	}

	// Never narrower than the "TIME" header.
	if got := timeLayoutWidth("15"); got < 4 {
		t.Errorf("width('15') = %d, want >= 4", got)
	}

	// Matches the reference rendering for every named layout.
	for _, layout := range namedTimeLayouts {
		want := max(len(referenceTime.Format(layout)), 4)
		if got := timeLayoutWidth(layout); got != want {
			t.Errorf("width(%q) = %d, want %d", layout, got, want)
		}
	}
}

func TestFormatTime(t *testing.T) {
	ref := time.Date(2021, 3, 4, 5, 6, 7, 0, time.UTC)

	cases := []struct {
		name   string
		t      time.Time
		layout string
		want   string
	}{
		{"timeonly", ref, time.TimeOnly, "05:06:07"},
		{"dateonly", ref, time.DateOnly, "2021-03-04"},
		{"datetime", ref, time.DateTime, "2021-03-04 05:06:07"},
		{"custom", ref, "2006/01/02", "2021/03/04"},
		{"zero is blank", time.Time{}, time.DateTime, ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := formatTime(tc.t, tc.layout); got != tc.want {
				t.Errorf("formatTime = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestFormatPID(t *testing.T) {
	if got := formatPID(0); got != "?" {
		t.Errorf("formatPID(0) = %q, want ?", got)
	}
	if got := formatPID(4242); got != "4242" {
		t.Errorf("formatPID(4242) = %q, want 4242", got)
	}
}

func TestHumanRate(t *testing.T) {
	cases := []struct {
		in   uint64
		want string
	}{
		{0, "0 B/s"},
		{1023, "1023 B/s"},
		{1024, "1.0 KiB/s"},
		{1536, "1.5 KiB/s"},
		{1024 * 1024, "1.0 MiB/s"},
		{5 * 1024 * 1024, "5.0 MiB/s"},
		{3 * 1024 * 1024 * 1024, "3.0 GiB/s"},
	}

	for _, tc := range cases {
		if got := humanRate(tc.in); got != tc.want {
			t.Errorf("humanRate(%d) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestTcpStateName(t *testing.T) {
	cases := []struct {
		in   uint8
		want string
	}{
		{0, "?"},
		{1, "ESTABLISHED"},
		{2, "SYN_SENT"},
		{3, "SYN_RECV"},
		{6, "TIME_WAIT"},
		{7, "CLOSE"},
		{11, "CLOSING"},
		{12, "NEW_SYN_RECV"},
		{13, "?"},
		{255, "?"},
	}

	for _, tc := range cases {
		if got := tcpStateName(tc.in); got != tc.want {
			t.Errorf("tcpStateName(%d) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestFormatCmdline(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		comm string
		want string
	}{
		{"args joined", "curl\x00-sS\x00http://x\x00", "curl", "curl -sS http://x"},
		{"trailing garbage trimmed", "  nc -l 80  \x00\x00", "nc", "nc -l 80"},
		{"empty is kernel thread", "\x00\x00", "kworker/0:1", "[kworker/0:1]"},
		{"nil raw", "", "sshd", "[sshd]"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := formatCmdline([]byte(tc.raw), tc.comm); got != tc.want {
				t.Errorf("formatCmdline(%q, %q) = %q, want %q", tc.raw, tc.comm, got, tc.want)
			}
		})
	}
}

func TestProtoName(t *testing.T) {
	if got := protoName(protoUDP); got != "UDP" {
		t.Errorf("protoName(UDP) = %q", got)
	}

	if got := protoName(protoTCP); got != "TCP" {
		t.Errorf("protoName(TCP) = %q", got)
	}

	if got := protoName(0); got != "TCP" {
		t.Errorf("protoName(0) = %q, want TCP", got)
	}
}
