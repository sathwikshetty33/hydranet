package telemetry

import (
	"context"
	"time"
)

// This is a high level event object, we would want to make the event not vendor locked to
// a particular telemetry collector or a detection engine. So this type acts as a bridge between
// both the modules so we try to include all the necessary fields.

type Event struct {
	Timestamp time.Time

	ProcessExecID string
	ParentExecID  string
	PID           uint32
	ParentPID     uint32
	TID           uint32
	ProcessStart  time.Time

	// Workload identity (some fields might be not present/different name
	// trying to keep the names generalized here.)
	NodeName      string
	ContainerID   string
	ContainerName string
	PodName       string
	PodNamespace  string
	PodUID        string
	WorkloadName  string
	WorkloadKind  string

	SyscallID uint32
	Phase     string
	Arch      string

	Source    string
	EventType string
	Metadata  map[string]any
}
type TelemetryCollector interface {
	Start(ctx context.Context) error
	Events() <-chan Event
}
