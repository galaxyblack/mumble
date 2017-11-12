package mumble

import (
	//"fmt"
	"os"
	"os/signal"
	"syscall"
)

func SignalHandler() {
	signalChannel := make(chan os.Signal, 10)
	signal.Notify(signalChannel, syscall.SIGUSR2, syscall.SIGTERM, syscall.SIGINT)
	// TODO: Handle 'REHUP' or configuration reload
	for signal := range signalChannel {
		if signal == syscall.SIGUSR2 {
			// TODO: this needs to be passed in or it can fuck off!!!! fuck global variables
			//err := Target.Rotate()
			//if err != nil {
			//	fmt.Fprintf(os.Stderr, "unable to rotate log file: %v", err)
			//}
			continue
		}
		if signal == syscall.SIGINT || signal == syscall.SIGTERM {
			os.Exit(0)
		}
	}
}
