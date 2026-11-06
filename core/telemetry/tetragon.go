package telemetry

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	api "github.com/cilium/tetragon/api/v1/tetragon"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const socketPath = "/var/run/tetragon/tetragon.sock"

type TetragonCollector struct {
	events chan Event
	client api.FineGuidanceSensorsClient
	conn   *grpc.ClientConn

	mu      sync.Mutex
	started bool
}

func NewTetragonCollector() *TetragonCollector {
	return &TetragonCollector{
		events: make(chan Event, 1024),
	}
}

func (t *TetragonCollector) Events() <-chan Event {
	return t.events
}

func (t *TetragonCollector) Start(ctx context.Context) error {
	t.mu.Lock()
	if t.started {
		t.mu.Unlock()
		return fmt.Errorf("the collector is already running")
	}
	t.started = true
	t.mu.Unlock()
	conn, err := grpc.NewClient(
		"passthrough:///tetragon",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(
			func(ctx context.Context, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
			},
		),
	)
	if err != nil {
		return fmt.Errorf("creating tetragon connection: %w", err)
	}
	log.Print("Sucessfully established Tetragon connection.")
	t.conn = conn
	t.client = api.NewFineGuidanceSensorsClient(conn)
	stream, err := t.client.GetEvents(ctx, &api.GetEventsRequest{})
	if err != nil {
		conn.Close()
		return fmt.Errorf("subscribing to tetragon events: %w", err)
	}

	go func() {
		defer close(t.events)
		defer conn.Close()
		defer log.Print("Succesfully closed Tetragon connection.")
		_ = t.consumeEvents(ctx, stream)
	}()

	return nil
}

func (t *TetragonCollector) consumeEvents(
	ctx context.Context,
	stream grpc.ServerStreamingClient[api.GetEventsResponse],
) error {
	for {
		resp, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("receiving tetragon event: %w", err)
		}

		event, err := t.convertToEvent(resp)
		if err != nil {
			log.Printf("Skipping Tetragon event: %v", err)
		}

		select {
		case t.events <- event:
		case <-ctx.Done():
			return ctx.Err()
		}
	}

}

func (t *TetragonCollector) convertToEvent(
	resp *api.GetEventsResponse,
) (Event, error) {
	tp := resp.GetProcessTracepoint()
	if tp == nil {
		return Event{}, errors.New("not a process tracepoint event")
	}

	if tp.GetSubsys() != "raw_syscalls" ||
		tp.GetEvent() != "sys_enter" {
		return Event{}, errors.New("not a syscall-entry event")
	}

	process := tp.GetProcess()
	if process == nil {
		return Event{}, errors.New("process metadata missing")
	}

	args := tp.GetArgs()
	if len(args) == 0 {
		return Event{}, errors.New("syscall ID argument missing")
	}

	syscallID := args[0].GetLongArg()
	if syscallID < 0 || syscallID > int64(^uint32(0)) {
		return Event{}, fmt.Errorf("invalid syscall ID: %d", syscallID)
	}

	var pid, parentPID uint32

	if p := process.GetPid(); p != nil {
		pid = p.GetValue()
	}

	if parent := tp.GetParent(); parent != nil {
		if p := parent.GetPid(); p != nil {
			parentPID = p.GetValue()
		}
	}

	var (
		containerID   string
		containerName string
		podName       string
		podNamespace  string
		podUID        string
		workloadName  string
		workloadKind  string
	)

	if pod := process.GetPod(); pod != nil {
		podName = pod.GetName()
		podNamespace = pod.GetNamespace()
		podUID = pod.GetUid()
		workloadName = pod.GetWorkload()
		workloadKind = pod.GetWorkloadKind()

		if container := pod.GetContainer(); container != nil {
			containerID = container.GetId()
			containerName = container.GetName()
		}
	}

	var timestamp time.Time
	if ts := resp.GetTime(); ts != nil {
		timestamp = ts.AsTime()
	}

	return Event{
		Timestamp: timestamp,

		PID:           pid,
		ParentPID:     parentPID,
		ProcessExecID: process.GetExecId(),
		ParentExecID:  process.GetParentExecId(),

		NodeName:      resp.GetNodeName(),
		ContainerID:   containerID,
		ContainerName: containerName,
		PodName:       podName,
		PodNamespace:  podNamespace,
		PodUID:        podUID,
		WorkloadName:  workloadName,
		WorkloadKind:  workloadKind,

		SyscallID: uint32(syscallID),
		Phase:     "enter",
		Source:    "tetragon",
		EventType: "syscall",

		Metadata: map[string]any{
			"subsystem":  tp.GetSubsys(),
			"tracepoint": tp.GetEvent(),
			"policy":     tp.GetPolicyName(),
		},
	}, nil
}
