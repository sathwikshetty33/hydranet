package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/sathwikshetty33/hydranet/core/config"
)

func main() {

	ctx, stop := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer stop()

	hydranetAgent, err := config.NewHydranetAgent()
	if err != nil {
		log.Fatalf("Error while confuguring the agent: %v", err)
	}

	if err := hydranetAgent.TelemetryCollector.Start(ctx); err != nil {
		// TODO: Add a retry mechanism with exponential backoff here.
		log.Fatalf("Error while starting Telemetry collector: %v", err)
	}

	log.Println("HydraNet agent started successfully")

	for {
		select {
		case event, ok := <-hydranetAgent.TelemetryCollector.Events():
			if !ok {
				log.Println("Tetragon event stream closed")
				return
			}
			log.Printf(
				"SYSCALL | Time=%s | Node=%s | Pod=%s/%s | Container=%s | PID=%d | ExecID=%s | SyscallID=%d | Phase=%s",
				event.Timestamp.Format("15:04:05.000"),
				event.NodeName,
				event.PodNamespace,
				event.PodName,
				event.ContainerName,
				event.PID,
				event.ProcessExecID,
				event.SyscallID,
				event.Phase,
			)

		case <-ctx.Done():
			log.Println("Shutting down HydraNet agent...")
			return
		}
	}
}
