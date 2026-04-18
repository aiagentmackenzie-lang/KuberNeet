package graph

import (
	"fmt"
	"strings"
)

// NodeType represents the type of resource in the graph
type NodeType string

const (
	NodeTypeService       NodeType = "service"
	NodeTypePod          NodeType = "pod"
	NodeTypeDeployment   NodeType = "deployment"
	NodeTypeServiceAccount NodeType = "serviceaccount"
	NodeTypeRole         NodeType = "role"
	NodeTypeClusterRole  NodeType = "clusterrole"
	NodeTypeRoleBinding  NodeType = "rolebinding"
	NodeTypeNode         NodeType = "node"
	NodeTypeVolume       NodeType = "volume"
)

// Node represents a resource in the Kubernetes graph
type Node struct {
	ID        string                 `json:"id"`
	Type      NodeType               `json:"type"`
	Name      string                 `json:"name"`
	Namespace string                 `json:"namespace,omitempty"`
	Labels    map[string]string      `json:"labels,omitempty"`
	RiskScore float64                `json:"risk_score"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// Edge represents a relationship between nodes
type Edge struct {
	Source      string `json:"source"`
	Target      string `json:"target"`
	Type        string `json:"type"`
	Description string `json:"description,omitempty"`
}

// Graph represents the Kubernetes resource graph
type Graph struct {
	Nodes map[string]*Node `json:"nodes"`
	Edges []Edge         `json:"edges"`
}

// NewGraph creates a new empty graph
func NewGraph() *Graph {
	return &Graph{
		Nodes: make(map[string]*Node),
		Edges: []Edge{},
	}
}

// AddNode adds a node to the graph
func (g *Graph) AddNode(node *Node) {
	g.Nodes[node.ID] = node
}

// AddEdge adds an edge between two nodes
func (g *Graph) AddEdge(source, target, edgeType, description string) {
	g.Edges = append(g.Edges, Edge{
		Source:      source,
		Target:      target,
		Type:        edgeType,
		Description: description,
	})
}

// NodeID generates a unique ID for a node
func NodeID(kind, namespace, name string) string {
	if namespace == "" {
		return fmt.Sprintf("%s/%s", strings.ToLower(kind), name)
	}
	return fmt.Sprintf("%s/%s/%s", strings.ToLower(kind), namespace, name)
}

// AttackPath represents a chain of exploitataion from entry to impact
type AttackPath struct {
	Start       *Node    `json:"start"`
	End         *Node    `json:"end"`
	Path        []*Node  `json:"path"`
	RiskScore   float64  `json:"risk_score"`
	Technique   string   `json:"technique"`
	Tactic      string   `json:"tactic"`
	Description string   `json:"description"`
}

// Builder constructs the service mesh graph
type Builder struct {
	graph *Graph
}

// NewBuilder creates a new graph builder
func NewBuilder() *Builder {
	return &Builder{
		graph: NewGraph(),
	}
}

// BuildPod adds a pod and its relationships to the graph
func (b *Builder) BuildPod(name, namespace, serviceAccount, node string, labels map[string]string, privileged bool) {
	podID := NodeID("pod", namespace, name)
	pod := &Node{
		ID:        podID,
		Type:      NodeTypePod,
		Name:      name,
		Namespace: namespace,
		Labels:    labels,
		Metadata: map[string]interface{}{
			"privileged": privileged,
		},
	}

	// Higher risk for privileged containers
	if privileged {
		pod.RiskScore += 50
	}

	b.graph.AddNode(pod)

	// Link to ServiceAccount
	if serviceAccount != "" {
		saID := NodeID("serviceaccount", namespace, serviceAccount)
		b.graph.AddEdge(podID, saID, "uses", fmt.Sprintf("Pod uses ServiceAccount %s", serviceAccount))
	}

	// Link to Node
	if node != "" {
		nodeID := NodeID("node", "", node)
		b.graph.AddEdge(podID, nodeID, "runs_on", fmt.Sprintf("Pod runs on node %s", node))
	}
}

// BuildService adds a service and links to pods
func (b *Builder) BuildService(name, namespace string, selector map[string]string, serviceType string) {
	svcID := NodeID("service", namespace, name)
	svc := &Node{
		ID:        svcID,
		Type:      NodeTypeService,
		Name:      name,
		Namespace: namespace,
		Labels:    selector,
		Metadata: map[string]interface{}{
			"type": serviceType,
		},
	}

	// External exposure increases risk
	if serviceType == "LoadBalancer" || serviceType == "NodePort" {
		svc.RiskScore += 30
	}

	b.graph.AddNode(svc)
}

// BuildRole adds a role/clusterrole
func (b *Builder) BuildRole(name, namespace string, isClusterRole bool, rules []map[string]interface{}) {
	nodeType := NodeTypeRole
	if isClusterRole {
		nodeType = NodeTypeClusterRole
	}

	roleID := NodeID(string(nodeType), namespace, name)
	role := &Node{
		ID:        roleID,
		Type:      nodeType,
		Name:      name,
		Namespace: namespace,
		Metadata: map[string]interface{}{
			"rules": rules,
		},
	}

	// Check for wildcards
	hasWildcard := false
	for _, rule := range rules {
		if verbs, ok := rule["verbs"].([]interface{}); ok {
			for _, v := range verbs {
				if v == "*" {
					hasWildcard = true
					role.RiskScore += 40
				}
			}
		}
	}
	role.Metadata["has_wildcard"] = hasWildcard

	b.graph.AddNode(role)
}

// BuildBinding links subjects to roles
func (b *Builder) BuildBinding(bindingName, namespace string, isClusterBinding bool, roleKind, roleName string, subjects []map[string]interface{}) {
	for _, subj := range subjects {
		subjKind, _ := subj["kind"].(string)
		subjName, _ := subj["name"].(string)
		subjNS, _ := subj["namespace"].(string)

		if subjKind == "ServiceAccount" {
			saID := NodeID("serviceaccount", subjNS, subjName)
			roleID := NodeID(strings.ToLower(roleKind), namespace, roleName)
			b.graph.AddEdge(saID, roleID, "can_assume", fmt.Sprintf("%s can assume %s", subjName, roleName))

			// Critical: cluster-admin on default SA
			if roleName == "cluster-admin" && subjName == "default" {
				sa := b.graph.Nodes[saID]
				if sa != nil {
					sa.RiskScore += 80
				}
			}
		}
	}
}

// GetGraph returns the constructed graph
func (b *Builder) GetGraph() *Graph {
	return b.graph
}

// PathFinder finds attack paths in the graph
type PathFinder struct {
	graph *Graph
}

// NewPathFinder creates a new path finder
func NewPathFinder(graph *Graph) *PathFinder {
	return &PathFinder{graph: graph}
}

// FindAttackPaths identifies high-risk attack paths
func (pf *PathFinder) FindAttackPaths() []AttackPath {
	var paths []AttackPath

	// Find external-facing services
	for _, node := range pf.graph.Nodes {
		if node.Type == NodeTypeService {
			if svcType, ok := node.Metadata["type"].(string); ok {
				if svcType == "LoadBalancer" || svcType == "NodePort" {
					// Trace to privileged pods
					path := pf.traceToPrivilegedPod(node)
					if path != nil {
						paths = append(paths, *path)
					}
				}
			}
		}
	}

	// Find RBAC escalation paths
	paths = append(paths, pf.findRBACEscalationPaths()...)

	return paths
}

// traceToPrivilegedPod follows service -> pod -> privileged checks
func (pf *PathFinder) traceToPrivilegedPod(svc *Node) *AttackPath {
	// Get selector
	selector := svc.Labels
	if len(selector) == 0 {
		return nil
	}

	// Find pods matching selector in same namespace
	for _, node := range pf.graph.Nodes {
		if node.Type != NodeTypePod || node.Namespace != svc.Namespace {
			continue
		}

		// Check if pod matches service selector
		if !matchesSelector(node.Labels, selector) {
			continue
		}

		// Check if pod has privileged containers
		if privileged, ok := node.Metadata["privileged"].(bool); ok && privileged {
			return &AttackPath{
				Start:       svc,
				End:         node,
				Path:        []*Node{svc, node},
				RiskScore:   svc.RiskScore + node.RiskScore + 50,
				Technique:   "Container Escape via Privileged Pod",
				Tactic:      "Privilege Escalation",
				Description: fmt.Sprintf("External-facing service '%s' selects privileged pod '%s' enabling container escape", svc.Name, node.Name),
			}
		}
	}

	return nil
}

// findRBACEscalationPaths identifies RBAC-based privilege escalation
func (pf *PathFinder) findRBACEscalationPaths() []AttackPath {
	var paths []AttackPath

	// Find serviceaccounts with cluster-admin
	for _, node := range pf.graph.Nodes {
		if node.Type != NodeTypeServiceAccount {
			continue
		}

		// Check edges to cluster-admin
		for _, edge := range pf.graph.Edges {
			if edge.Source == node.ID {
				target := pf.graph.Nodes[edge.Target]
				if target != nil && target.Type == NodeTypeClusterRole {
					if target.Name == "cluster-admin" {
						path := AttackPath{
							Start: node,
							End:   target,
							Path:  []*Node{node, target},
							RiskScore: node.RiskScore + 100,
							Technique: "RBAC Privilege Escalation",
							Tactic:    "Privilege Escalation",
							Description: fmt.Sprintf("ServiceAccount '%s' has cluster-admin access", node.Name),
						}
						paths = append(paths, path)
					}
				}
			}
		}
	}

	return paths
}

// matchesSelector checks if pod labels match service selector
func matchesSelector(labels, selector map[string]string) bool {
	for k, v := range selector {
		if labels[k] != v {
			return false
		}
	}
	return true
}
