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

type TetragonCollector struct {
	events     chan Event
	client     api.FineGuidanceSensorsClient
	conn       *grpc.ClientConn
	socketPath string

	// making sure we only run the collector once.
	mu      sync.Mutex
	started bool
}

func NewTetragonCollector(socketPath string) *TetragonCollector {
	return &TetragonCollector{
		socketPath: socketPath,
		events:     make(chan Event, 1024),
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
				return (&net.Dialer{}).DialContext(ctx, "unix", t.socketPath)
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
			continue
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
	if resp == nil {
		return Event{}, errors.New("nil Tetragon response")
	}

	tp := resp.GetProcessTracepoint()
	if tp == nil {
		return Event{}, errors.New("not a process tracepoint event")
	}

	if tp.GetSubsys() != "raw_syscalls" ||
		tp.GetEvent() != "sys_enter" {
		return Event{}, errors.New("not a syscall-entry event")
	}

	args := tp.GetArgs()
	if len(args) == 0 || args[0] == nil {
		return Event{}, errors.New("syscall ID argument missing")
	}

	syscallID := args[0].GetLongArg()
	if syscallID < 0 || syscallID > int64(^uint32(0)) {
		return Event{}, fmt.Errorf("invalid syscall ID: %d", syscallID)
	}

	process := tp.GetProcess()
	parent := tp.GetParent()

	var (
		pid           uint32
		parentPID     uint32
		tid           uint32
		processStart  time.Time
		processExecID string
		parentExecID  string
	)

	if process != nil {
		if p := process.GetPid(); p != nil {
			pid = p.GetValue()
		}

		if p := process.GetTid(); p != nil {
			tid = p.GetValue()
		}

		processExecID = process.GetExecId()
		parentExecID = process.GetParentExecId()

		if start := process.GetStartTime(); start != nil {
			processStart = start.AsTime()
		}
	}

	if parent != nil {
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

	if process != nil {
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
	}

	metadataComplete := process != nil &&
		processExecID != "" &&
		podName != "" &&
		podNamespace != "" &&
		containerID != ""

	var timestamp time.Time
	if ts := resp.GetTime(); ts != nil {
		timestamp = ts.AsTime()
	}

	return Event{
		Timestamp: timestamp,

		ProcessExecID: processExecID,
		ParentExecID:  parentExecID,
		PID:           pid,
		ParentPID:     parentPID,
		TID:           tid,
		ProcessStart:  processStart,

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

		MetadataComplete: metadataComplete,

		Source:    "tetragon",
		EventType: "syscall",

		Metadata: map[string]any{
			"subsystem":  tp.GetSubsys(),
			"tracepoint": tp.GetEvent(),
			"policy":     tp.GetPolicyName(),
		},
	}, nil
}
