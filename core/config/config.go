package config

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/sathwikshetty33/hydranet/core/telemetry"
)

type HydranetAgent struct {
	TelemetryCollector telemetry.TelemetryCollector
}

func NewHydranetAgent() (*HydranetAgent, error) {
	collector, err := newTelemetryCollector()
	if err != nil {
		return nil, err
	}

	return &HydranetAgent{
		TelemetryCollector: collector,
	}, nil
}

func newTelemetryCollector() (telemetry.TelemetryCollector, error) {
	collector := strings.ToLower(
		strings.TrimSpace(os.Getenv("TELEMETRYCOLLECTOR")),
	)

	if collector == "" {
		collector = "tetragon"
		log.Printf("Using default Tetragon collector")
	} else {
		log.Printf("Using Telemetry collector: %v", collector)
	}

	switch collector {
	case "tetragon":
		socketPath := os.Getenv("SOCKETPATH")
		if socketPath == "" {
			socketPath = "/var/run/tetragon/tetragon.sock"
		}

		return telemetry.NewTetragonCollector(socketPath), nil

	default:
		return nil, fmt.Errorf(
			"unknown telemetry collector: %s", collector,
		)
	}
}
