package orchestrator

import "context"

type Node struct {
	ID          string
	Name        string
	Runtime     string
	Status      NodeStatus
	WorkloadIDs []string
	Labels      map[string]string
}

type NodeStatus string

const (
	NodeReady       NodeStatus = "READY"
	NodeNotReady    NodeStatus = "NOT_READY"
	NodeQuarantined NodeStatus = "QUARANTINED"
)

type NodeManager interface {
	GetNode(ctx context.Context, id string) (*Node, error)

	ListNodes(ctx context.Context) ([]Node, error)
}
