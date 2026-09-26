package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

// version is overridden at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	timeFormat := flag.String(
		"time-format",
		"time",
		"event-time format: a named layout (time, datetime, date, rfc3339, "+
			"rfc3339nano, kitchen, stamp, unixdate, rfc1123, ...) or any custom "+
			"Go layout, e.g. '2006-01-02 15:04:05'",
	)
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println("tcplife-go", version)
		return
	}

	layout, err := resolveTimeLayout(*timeFormat)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid -time-format: %v\n", err)
		os.Exit(2)
	}

	c, err := openCapture()
	if err != nil {
		fmt.Fprintf(os.Stderr, "tcplife-go: %v\n", err)
		os.Exit(1)
	}
	defer c.Close()

	if isTerminal(os.Stdout) {
		runTUI(c, layout)
		return
	}

	// Non-interactive: original tcplife-style streaming output.
	onShutdown(func() { c.rd.Close() })

	runPlain(c, layout)
}

// onShutdown runs fn in its own goroutine once SIGINT or SIGTERM arrives.
func onShutdown(fn func()) {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sig
		fn()
	}()
}

func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}
