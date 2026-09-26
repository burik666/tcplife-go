package main

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func ipFromBytes(b []byte, family uint16) net.IP {
	if family == syscall.AF_INET {
		return net.IP(b[:4])
	}
	return net.IP(b[:16])
}

// humanUnit scales n by powers of 1024 and renders it with one fractional
// digit. It returns the number and the binary-prefix letter; below 1024 no
// prefix is used and the value is rendered as an exact integer.
func humanUnit(n uint64) (string, byte) {
	const unit = 1024
	if n < unit {
		return strconv.FormatUint(n, 10), 0
	}
	div, exp := uint64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f", float64(n)/float64(div)), "KMGTPE"[exp]
}

func humanBytes(n uint64) string {
	s, prefix := humanUnit(n)
	if prefix == 0 {
		return s + " B"
	}
	return s + " " + string(prefix) + "B"
}

// formatCmdline renders NUL-separated /proc/<pid>/cmdline data like `ps aux`
// (arguments joined by spaces). Empty or kernel-style cmdlines fall back to
// the bracketed comm, also like ps.
func formatCmdline(raw []byte, comm string) string {
	s := strings.TrimSpace(strings.ReplaceAll(string(raw), "\x00", " "))
	if s == "" {
		return "[" + comm + "]"
	}
	return s
}

// humanRate formats a bytes-per-second rate with binary units (KiB/s, MiB/s...).
func humanRate(bps uint64) string {
	s, prefix := humanUnit(bps)
	if prefix == 0 {
		return s + " B/s"
	}
	return s + " " + string(prefix) + "iB/s"
}

// tcpStateNames maps the kernel TCP state enum (vmlinux.h TCP_ESTABLISHED...)
// to display names for the STATE column.
var tcpStateNames = [...]string{
	1:  "ESTABLISHED",
	2:  "SYN_SENT",
	3:  "SYN_RECV",
	4:  "FIN_WAIT1",
	5:  "FIN_WAIT2",
	6:  "TIME_WAIT",
	7:  "CLOSE",
	8:  "CLOSE_WAIT",
	9:  "LAST_ACK",
	10: "LISTEN",
	11: "CLOSING",
	12: "NEW_SYN_RECV",
}

// tcpStateName renders a TCP state value; unknown or unset states show "?".
func tcpStateName(state uint8) string {
	if state == 0 || int(state) >= len(tcpStateNames) {
		return "?"
	}
	return tcpStateNames[state]
}

// protoName renders an IP protocol number for the PROTO column; anything but
// UDP shows as TCP (the tool only tracks those two).
func protoName(proto uint8) string {
	if proto == protoUDP {
		return "UDP"
	}
	return "TCP"
}

func humanDuration(d time.Duration) string {
	s := d.String()

	if i := strings.IndexByte(s, '.'); i >= 0 {
		end := i + 1
		for end < len(s) && s[end] >= '0' && s[end] <= '9' {
			end++
		}

		// Keep at most two fractional digits.
		if end-i-1 > 2 {
			s = s[:i+3] + s[end:]
		}
	}

	return s
}

// namedTimeLayouts maps case-insensitive names accepted by -time-format to Go
// reference layouts. Unknown values are treated as raw layouts.
var namedTimeLayouts = map[string]string{
	"layout":      time.Layout,
	"ansic":       time.ANSIC,
	"unixdate":    time.UnixDate,
	"rubydate":    time.RubyDate,
	"rfc822":      time.RFC822,
	"rfc822z":     time.RFC822Z,
	"rfc850":      time.RFC850,
	"rfc1123":     time.RFC1123,
	"rfc1123z":    time.RFC1123Z,
	"rfc3339":     time.RFC3339,
	"rfc3339nano": time.RFC3339Nano,
	"kitchen":     time.Kitchen,
	"stamp":       time.Stamp,
	"stampmilli":  time.StampMilli,
	"stampmicro":  time.StampMicro,
	"stampnano":   time.StampNano,
	"datetime":    time.DateTime,
	"dateonly":    time.DateOnly,
	"timeonly":    time.TimeOnly,
	// Aliases.
	"time": time.TimeOnly, // default
	"date": time.DateOnly,
}

// resolveTimeLayout turns a -time-format value into a Go reference layout.
// Known names (case-insensitive) map to the standard time.* layouts; anything
// else is returned verbatim so callers can pass a custom layout.
func resolveTimeLayout(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", errors.New("time format must not be empty")
	}

	if layout, ok := namedTimeLayouts[strings.ToLower(s)]; ok {
		return layout, nil
	}

	return s, nil
}

// referenceTime is used to measure how wide a rendered layout will be.
var referenceTime = time.Date(2006, time.November, 22, 15, 4, 5, 0, time.Local)

// timeLayoutWidth reports the display width of a layout so fixed-width output
// (plain mode) can keep its columns aligned for any format.
func timeLayoutWidth(layout string) int {
	if w := len(referenceTime.Format(layout)); w > 4 {
		return w
	}
	return 4 // never shrink below the "TIME" header
}

// formatTime renders an event timestamp with the given layout; zero times
// become a blank column.
func formatTime(t time.Time, layout string) string {
	if t.IsZero() {
		return ""
	}
	return t.Format(layout)
}

// formatPID renders a process id; 0 (kernel context / unknown owner) shows "?".
func formatPID(pid uint32) string {
	if pid == 0 {
		return "?"
	}
	return strconv.FormatUint(uint64(pid), 10)
}
