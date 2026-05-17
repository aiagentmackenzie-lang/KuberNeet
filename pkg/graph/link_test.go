package graph

import (
	"testing"
)

func TestLinkServicesToPods(t *testing.T) {
	b := NewBuilder()

	// Build a service that selects app=nginx
	b.BuildService("nginx-svc", "default", map[string]string{"app": "nginx"}, "LoadBalancer")
	b.BuildPod("nginx", "default", "default", "worker-1", map[string]string{"app": "nginx"}, false)
	b.BuildPod("redis", "default", "default", "worker-1", map[string]string{"app": "redis"}, false)

	// Link services to pods
	b.LinkServicesToPods()

	g := b.GetGraph()

	// Should have an edge from service to the matching pod
	foundEdge := false
	for _, edge := range g.Edges {
		if edge.Type == "selects" && edge.Source == "service/default/nginx-svc" && edge.Target == "pod/default/nginx" {
			foundEdge = true
		}
	}
	if !foundEdge {
		t.Error("expected edge from nginx-svc to nginx pod (matching selector)")
	}

	// Should NOT have an edge to redis (different selector)
	for _, edge := range g.Edges {
		if edge.Type == "selects" && edge.Target == "pod/default/redis" {
			t.Error("should not have edge from nginx-svc to redis pod (non-matching selector)")
		}
	}
}

func TestLinkServicesToPods_MultipleMatches(t *testing.T) {
	b := NewBuilder()

	b.BuildService("web-svc", "default", map[string]string{"app": "web"}, "ClusterIP")
	b.BuildPod("web-1", "default", "default", "worker-1", map[string]string{"app": "web"}, false)
	b.BuildPod("web-2", "default", "default", "worker-2", map[string]string{"app": "web"}, false)

	b.LinkServicesToPods()

	g := b.GetGraph()

	matchCount := 0
	for _, edge := range g.Edges {
		if edge.Type == "selects" && edge.Source == "service/default/web-svc" {
			matchCount++
		}
	}
	if matchCount != 2 {
		t.Errorf("expected 2 edges from web-svc to matching pods, got %d", matchCount)
	}
}

func TestLinkServicesToPods_EmptySelector(t *testing.T) {
	b := NewBuilder()

	// Service with no selector should not create edges
	b.BuildService("headless-svc", "default", nil, "ClusterIP")
	b.BuildPod("some-pod", "default", "default", "worker-1", map[string]string{"app": "test"}, false)

	b.LinkServicesToPods()

	g := b.GetGraph()

	for _, edge := range g.Edges {
		if edge.Source == "service/default/headless-svc" && edge.Type == "selects" {
			t.Error("headless service with nil selector should not create selects edges")
		}
	}
}

func TestFindAttackPaths_WithServicePodEdge(t *testing.T) {
	b := NewBuilder()

	// Build an external service selecting a privileged pod
	b.BuildService("nginx-lb", "default", map[string]string{"app": "nginx"}, "LoadBalancer")
	b.BuildPod("nginx", "default", "default", "worker-1", map[string]string{"app": "nginx"}, true)

	b.LinkServicesToPods()

	g := b.GetGraph()
	pf := NewPathFinder(g)
	paths := pf.FindAttackPaths()

	if len(paths) == 0 {
		t.Error("expected at least one attack path for privileged pod behind LoadBalancer")
	}

	// Verify the service-to-pod edge exists
	hasSelectsEdge := false
	for _, edge := range g.Edges {
		if edge.Type == "selects" {
			hasSelectsEdge = true
		}
	}
	if !hasSelectsEdge {
		t.Error("expected selects edge between service and pod")
	}
}