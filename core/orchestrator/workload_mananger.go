package orchestrator

import "context"

type Workload struct {
	ID        string
	Name      string
	Namespace string
	Runtime   string
	NodeID    string
}

type WorkloadManager interface {
	GetWorkloads(ctx context.Context) []Workload

	GetWorkload(ctx context.Context, id string) *Workload
}
