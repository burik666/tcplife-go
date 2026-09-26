package main

import (
	"fmt"
)

// runPlain reproduces the original tcplife-style output: one line per closed
// TCP session, streamed as events arrive. Used when stdout is not a terminal.
func runPlain(c *capture, layout string) {
	w := timeLayoutWidth(layout)

	fmt.Printf(
		"%-*s %-8s %-16s %-24s %-24s %-10s %-10s %s\n",
		w, "TIME", "PID", "COMM", "LADDR", "RADDR", "RX", "TX", "DURATION",
	)

	for {
		sess, err := c.readEvent()
		if err != nil {
			return
		}

		// Realtime snapshots are a TUI-only concept; plain output stays
		// one line per closed session, exactly like the original tcplife.
		if sess.Active {
			continue
		}

		fmt.Printf(
			"%-*s %-8s %s %-24s %-24s %-10s %-10s %8.3f ms\n",
			w,
			formatTime(sess.Time, layout),
			formatPID(sess.PID),
			sess.Comm,
			sess.Laddr,
			sess.Raddr,
			humanBytes(sess.RX),
			humanBytes(sess.TX),
			sess.Duration.Seconds()*1000,
		)
	}
}
