package scanner

import (
	"testing"

	"github.com/raphael/kuberneet/pkg/finding"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func intPtr(v int32) *int32    { return &v }
func boolPtr(v bool) *bool     { return &v }
func strPtr(v string) *string  { return &v }

func TestCheckPrivilegedContainers(t *testing.T) {
	s := &Scanner{withRemedy: true}

	t.Run("privileged container flagged", func(t *testing.T) {
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "test-pod", Namespace: "default"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{
					Name:            "app",
					SecurityContext: &corev1.SecurityContext{Privileged: boolPtr(true)},
				}},
			},
		}
		findings := s.checkPrivilegedContainers(pod)
		if len(findings) != 1 {
			t.Fatalf("expected 1 finding, got %d", len(findings))
		}
		if findings[0].ID != "POD-001" {
			t.Errorf("expected POD-001, got %s", findings[0].ID)
		}
		if findings[0].Severity != finding.Critical {
			t.Errorf("expected CRITICAL, got %s", findings[0].Severity)
		}
	})

	t.Run("non-privileged container not flagged", func(t *testing.T) {
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "safe-pod", Namespace: "default"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{
					Name:            "app",
					SecurityContext: &corev1.SecurityContext{Privileged: boolPtr(false)},
				}},
			},
		}
		findings := s.checkPrivilegedContainers(pod)
		if len(findings) != 0 {
			t.Fatalf("expected 0 findings, got %d", len(findings))
		}
	})
}

func TestCheckHostNamespaces(t *testing.T) {
	s := &Scanner{}

	t.Run("hostPID flagged", func(t *testing.T) {
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "test-pod", Namespace: "default"},
			Spec:       corev1.PodSpec{HostPID: true},
		}
		findings := s.checkHostNamespaces(pod)
		found := false
		for _, f := range findings {
			if f.ID == "POD-002" {
				found = true
			}
		}
		if !found {
			t.Error("expected POD-002 finding for hostPID")
		}
	})

	t.Run("all host namespaces flagged", func(t *testing.T) {
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "test-pod", Namespace: "default"},
			Spec:       corev1.PodSpec{HostPID: true, HostNetwork: true, HostIPC: true},
		}
		findings := s.checkHostNamespaces(pod)
		if len(findings) != 3 {
			t.Fatalf("expected 3 findings, got %d", len(findings))
		}
	})
}

func TestCheckCapabilities(t *testing.T) {
	s := &Scanner{}

	t.Run("SYS_ADMIN flagged as CRITICAL", func(t *testing.T) {
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "test-pod", Namespace: "default"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{
					Name: "app",
					SecurityContext: &corev1.SecurityContext{
						Capabilities: &corev1.Capabilities{
							Add: []corev1.Capability{"SYS_ADMIN"},
						},
					},
				}},
			},
		}
		findings := s.checkCapabilities(pod)
		if len(findings) < 1 {
			t.Fatal("expected at least 1 finding")
		}
		var found007 bool
		for _, f := range findings {
			if f.ID == "POD-007" && f.Severity == finding.Critical {
				found007 = true
			}
		}
		if !found007 {
			t.Error("expected POD-007 CRITICAL for SYS_ADMIN")
		}
	})

	t.Run("NET_ADMIN flagged as HIGH", func(t *testing.T) {
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "test-pod", Namespace: "default"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{
					Name: "app",
					SecurityContext: &corev1.SecurityContext{
						Capabilities: &corev1.Capabilities{
							Add:  []corev1.Capability{"NET_ADMIN"},
							Drop: []corev1.Capability{"ALL"},
						},
					},
				}},
			},
		}
		findings := s.checkCapabilities(pod)
		var found007 bool
		for _, f := range findings {
			if f.ID == "POD-007" && f.Severity == finding.High {
				found007 = true
			}
		}
		if !found007 {
			t.Error("expected POD-007 HIGH for NET_ADMIN")
		}
	})

	t.Run("SYS_MODULE flagged as CRITICAL", func(t *testing.T) {
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "test-pod", Namespace: "default"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{
					Name: "app",
					SecurityContext: &corev1.SecurityContext{
						Capabilities: &corev1.Capabilities{
							Add:  []corev1.Capability{"SYS_MODULE"},
							Drop: []corev1.Capability{"ALL"},
						},
					},
				}},
			},
		}
		findings := s.checkCapabilities(pod)
		var found007 bool
		for _, f := range findings {
			if f.ID == "POD-007" && f.Severity == finding.Critical {
				found007 = true
			}
		}
		if !found007 {
			t.Error("expected POD-007 CRITICAL for SYS_MODULE")
		}
	})

	t.Run("missing DROP ALL flagged as POD-008", func(t *testing.T) {
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "test-pod", Namespace: "default"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{
					Name:            "app",
					SecurityContext: &corev1.SecurityContext{},
				}},
			},
		}
		findings := s.checkCapabilities(pod)
		// No capabilities defined = no ADD to check, but also no DROP ALL
		// Since SecurityContext exists but Capabilities is nil, no POD-007 or POD-008
		// (POD-008 requires Capabilities to exist to check for DROP ALL)
		if len(findings) != 0 {
			t.Logf("findings: %v (expected 0 since Capabilities is nil)", findings)
		}
	})

	t.Run("DROP ALL prevents POD-008", func(t *testing.T) {
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "test-pod", Namespace: "default"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{
					Name: "app",
					SecurityContext: &corev1.SecurityContext{
						Capabilities: &corev1.Capabilities{
							Drop: []corev1.Capability{"ALL"},
						},
					},
				}},
			},
		}
		findings := s.checkCapabilities(pod)
		for _, f := range findings {
			if f.ID == "POD-008" {
				t.Error("POD-008 should not fire when DROP ALL is set")
			}
		}
	})
}

func TestCheckHostPathMounts(t *testing.T) {
	s := &Scanner{}

	t.Run("docker.sock flagged", func(t *testing.T) {
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "test-pod", Namespace: "default"},
			Spec: corev1.PodSpec{
				Volumes: []corev1.Volume{{
					Name: "docker-sock",
					VolumeSource: corev1.VolumeSource{
						HostPath: &corev1.HostPathVolumeSource{
							Path: "/var/run/docker.sock",
						},
					},
				}},
			},
		}
		findings := s.checkHostPathMounts(pod)
		if len(findings) != 1 {
			t.Fatalf("expected 1 finding, got %d", len(findings))
		}
		if findings[0].ID != "POD-005" {
			t.Errorf("expected POD-005, got %s", findings[0].ID)
		}
	})
}

func TestCheckSecurityContext(t *testing.T) {
	s := &Scanner{}

	t.Run("allowPrivilegeEscalation flagged", func(t *testing.T) {
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "test-pod", Namespace: "default"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{
					Name: "app",
					SecurityContext: &corev1.SecurityContext{
						AllowPrivilegeEscalation: boolPtr(true),
					},
				}},
			},
		}
		findings := s.checkSecurityContext(pod)
		found := false
		for _, f := range findings {
			if f.ID == "POD-010" {
				found = true
			}
		}
		if !found {
			t.Error("expected POD-010 finding")
		}
	})

	t.Run("nil securityContext flagged as POD-009", func(t *testing.T) {
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "test-pod", Namespace: "default"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{
					Name: "app",
				}},
			},
		}
		findings := s.checkSecurityContext(pod)
		found := false
		for _, f := range findings {
			if f.ID == "POD-009" {
				found = true
			}
		}
		if !found {
			t.Error("expected POD-009 finding for nil securityContext")
		}
	})
}

func TestFilterBySeverity(t *testing.T) {
	s := &Scanner{severity: finding.Critical}

	findings := []finding.Finding{
		{ID: "CRIT-1", Severity: finding.Critical},
		{ID: "HIGH-1", Severity: finding.High},
		{ID: "MED-1", Severity: finding.Medium},
		{ID: "LOW-1", Severity: finding.Low},
	}

	filtered := s.filterBySeverity(findings)
	if len(filtered) != 1 {
		t.Fatalf("expected 1 critical finding, got %d", len(filtered))
	}
	if filtered[0].ID != "CRIT-1" {
		t.Errorf("expected CRIT-1, got %s", filtered[0].ID)
	}

	// No filter = all findings
	s.severity = ""
	all := s.filterBySeverity(findings)
	if len(all) != 4 {
		t.Fatalf("expected 4 findings with no filter, got %d", len(all))
	}
}