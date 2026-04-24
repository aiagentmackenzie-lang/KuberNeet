package graph

import (
	"testing"
)

func TestNodeID(t *testing.T) {
	t.Run("with namespace", func(t *testing.T) {
		id := NodeID("pod", "default", "nginx")
		expected := "pod/default/nginx"
		if id != expected {
			t.Errorf("expected %s, got %s", expected, id)
		}
	})

	t.Run("without namespace", func(t *testing.T) {
		id := NodeID("node", "", "worker-1")
		expected := "node/worker-1"
		if id != expected {
			t.Errorf("expected %s, got %s", expected, id)
		}
	})
}

func TestAddNodeAndEdge(t *testing.T) {
	g := NewGraph()

	g.AddNode(&Node{
		ID:        "pod/default/nginx",
		Type:      NodeTypePod,
		Name:      "nginx",
		Namespace: "default",
		RiskScore: 10,
	})

	g.AddNode(&Node{
		ID:   "service/default/nginx-svc",
		Type: NodeTypeService,
		Name: "nginx-svc",
	})

	g.AddEdge("service/default/nginx-svc", "pod/default/nginx", "selects", "Service selects pod")

	if len(g.Nodes) != 2 {
		t.Errorf("expected 2 nodes, got %d", len(g.Nodes))
	}

	if len(g.Edges) != 1 {
		t.Errorf("expected 1 edge, got %d", len(g.Edges))
	}

	if g.Edges[0].Type != "selects" {
		t.Errorf("expected edge type 'selects', got %s", g.Edges[0].Type)
	}
}

func TestBuildPod(t *testing.T) {
	b := NewBuilder()
	b.BuildPod("nginx", "default", "default", "worker-1", map[string]string{"app": "nginx"}, false)

	g := b.GetGraph()

	podNode, ok := g.Nodes["pod/default/nginx"]
	if !ok {
		t.Fatal("pod node not found in graph")
	}

	if podNode.Type != NodeTypePod {
		t.Errorf("expected NodeTypePod, got %s", podNode.Type)
	}

	if podNode.RiskScore != 0 {
		t.Errorf("expected risk score 0 for non-privileged pod, got %.0f", podNode.RiskScore)
	}

	// Privileged pod should have higher risk score
	b2 := NewBuilder()
	b2.BuildPod("privileged-pod", "default", "default", "worker-1", nil, true)
	g2 := b2.GetGraph()
	privPod := g2.Nodes["pod/default/privileged-pod"]
	if privPod.RiskScore != 50 {
		t.Errorf("expected risk score 50 for privileged pod, got %.0f", privPod.RiskScore)
	}
}

func TestBuildService(t *testing.T) {
	b := NewBuilder()
	b.BuildService("nginx-svc", "default", map[string]string{"app": "nginx"}, "LoadBalancer")

	g := b.GetGraph()
	svcNode, ok := g.Nodes["service/default/nginx-svc"]
	if !ok {
		t.Fatal("service node not found in graph")
	}

	if svcNode.Type != NodeTypeService {
		t.Errorf("expected NodeTypeService, got %s", svcNode.Type)
	}

	if svcNode.RiskScore != 30 {
		t.Errorf("expected risk score 30 for LoadBalancer, got %.0f", svcNode.RiskScore)
	}

	// ClusterIP should have no risk bump
	b2 := NewBuilder()
	b2.BuildService("internal-svc", "default", map[string]string{"app": "internal"}, "ClusterIP")
	g2 := b2.GetGraph()
	intSvc := g2.Nodes["service/default/internal-svc"]
	if intSvc.RiskScore != 0 {
		t.Errorf("expected risk score 0 for ClusterIP, got %.0f", intSvc.RiskScore)
	}
}

func TestBuildRole(t *testing.T) {
	b := NewBuilder()
	rules := []map[string]interface{}{
		{"verbs": []interface{}{"*"}, "resources": []interface{}{"secrets"}},
	}
	b.BuildRole("admin-role", "default", false, rules)

	g := b.GetGraph()
	roleNode, ok := g.Nodes["role/default/admin-role"]
	if !ok {
		t.Fatal("role node not found in graph")
	}

	if roleNode.RiskScore != 40 {
		t.Errorf("expected risk score 40 for wildcard role, got %.0f", roleNode.RiskScore)
	}
}

func TestMatchesSelector(t *testing.T) {
	tests := []struct {
		name     string
		labels   map[string]string
		selector map[string]string
		expected bool
	}{
		{"exact match", map[string]string{"app": "nginx"}, map[string]string{"app": "nginx"}, true},
		{"no match", map[string]string{"app": "nginx"}, map[string]string{"app": "redis"}, false},
		{"extra labels ok", map[string]string{"app": "nginx", "tier": "frontend"}, map[string]string{"app": "nginx"}, true},
		{"empty selector", map[string]string{"app": "nginx"}, map[string]string{}, true},
		{"missing label", map[string]string{"app": "nginx"}, map[string]string{"app": "nginx", "env": "prod"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := matchesSelector(tt.labels, tt.selector)
			if result != tt.expected {
				t.Errorf("matchesSelector(%v, %v) = %v, want %v", tt.labels, tt.selector, result, tt.expected)
			}
		})
	}
}

func TestFindAttackPathsPrivileged(t *testing.T) {
	b := NewBuilder()

	// Create an external service selecting a privileged pod
	b.BuildService("nginx-lb", "default", map[string]string{"app": "nginx"}, "LoadBalancer")
	b.BuildPod("nginx", "default", "default", "worker-1", map[string]string{"app": "nginx"}, true)

	g := b.GetGraph()
	pf := NewPathFinder(g)
	paths := pf.FindAttackPaths()

	if len(paths) == 0 {
		t.Error("expected at least one attack path for privileged pod behind LoadBalancer")
	}

	if paths[0].Technique != "Container Escape via Privileged Pod" {
		t.Errorf("expected Container Escape technique, got %s", paths[0].Technique)
	}
}

func TestFindAttackPathsNoRisk(t *testing.T) {
	b := NewBuilder()

	// Internal service, non-privileged pod
	b.BuildService("internal-svc", "default", map[string]string{"app": "safe"}, "ClusterIP")
	b.BuildPod("safe-pod", "default", "default", "worker-1", map[string]string{"app": "safe"}, false)

	g := b.GetGraph()
	pf := NewPathFinder(g)
	paths := pf.FindAttackPaths()

	if len(paths) != 0 {
		t.Errorf("expected no attack paths for safe configuration, got %d", len(paths))
	}
}