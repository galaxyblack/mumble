package protocol

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

func SignalHandler() {
	sigchan := make(chan os.Signal, 10)
	signal.Notify(sigchan, syscall.SIGUSR2, syscall.SIGTERM, syscall.SIGINT)
	for sig := range sigchan {
		if sig == syscall.SIGUSR2 {
			err := logtarget.Target.Rotate()
			if err != nil {
				fmt.Fprintf(os.Stderr, "unable to rotate log file: %v", err)
			}
			continue
		}
		if sig == syscall.SIGINT || sig == syscall.SIGTERM {
			os.Exit(0)
		}
	}
}
