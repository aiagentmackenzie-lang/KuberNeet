package admission

import (
	"encoding/json"
	"testing"

	"github.com/raphael/kuberneet/pkg/finding"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/api/admission/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func boolPtr(b bool) *bool { return &b }

func TestValidatePod_NilScanner_AllowsWithWarning(t *testing.T) {
	s := &Server{scanner: nil, mutating: false}

	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "test-pod", Namespace: "default"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:            "app",
				SecurityContext: &corev1.SecurityContext{Privileged: boolPtr(true)},
			}},
		},
	}
	podJSON, _ := json.Marshal(pod)

	req := &v1beta1.AdmissionRequest{
		UID:  "test-uid",
		Kind: metav1.GroupVersionKind{Kind: "Pod"},
		Object: runtime.RawExtension{
			Raw: podJSON,
		},
	}

	resp := s.validatePod(req)
	if !resp.Allowed {
		t.Error("expected pod to be allowed when scanner is nil, but got denied")
	}
	if resp.Result == nil {
		t.Error("expected warning result when scanner is nil")
	}
}

func TestValidateDeployment_NilScanner_AllowsWithWarning(t *testing.T) {
	s := &Server{scanner: nil, mutating: false}

	req := &v1beta1.AdmissionRequest{
		UID:  "test-uid",
		Kind: metav1.GroupVersionKind{Kind: "Deployment"},
		Object: runtime.RawExtension{
			Raw: []byte(`{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"test-deploy"},"spec":{"template":{"spec":{"containers":[{"name":"app"}]}}}}`),
		},
	}

	resp := s.validateDeployment(req)
	if !resp.Allowed {
		t.Error("expected deployment to be allowed when scanner is nil, but got denied")
	}
	if resp.Result == nil {
		t.Error("expected warning result when scanner is nil")
	}
}

func TestValidatePod_InvalidJSON(t *testing.T) {
	s := &Server{scanner: nil, mutating: false}

	req := &v1beta1.AdmissionRequest{
		UID:  "test-uid",
		Kind: metav1.GroupVersionKind{Kind: "Pod"},
		Object: runtime.RawExtension{
			Raw: []byte(`{invalid json`),
		},
	}

	resp := s.validatePod(req)
	if resp.Allowed {
		t.Error("expected pod to be denied when JSON is invalid")
	}
}

func TestGenerateSecurityPatches(t *testing.T) {
	s := &Server{scanner: nil, mutating: true}

	pod := &corev1.Pod{
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name: "app",
			}},
		},
	}

	patches := s.generateSecurityPatches(pod)
	if len(patches) == 0 {
		t.Error("expected security patches for pod without security context")
	}

	// Check that key patches are present
	hasSeccomp := false
	hasDropAll := false
	hasRunAsNonRoot := false
	for _, p := range patches {
		if p.Path == "/spec/securityContext/seccompProfile" {
			hasSeccomp = true
		}
		if p.Path == "/spec/containers/0/securityContext/capabilities" {
			hasDropAll = true
		}
		if p.Path == "/spec/containers/0/securityContext/runAsNonRoot" {
			hasRunAsNonRoot = true
		}
	}
	if !hasSeccomp {
		t.Error("expected seccomp profile patch")
	}
	if !hasDropAll {
		t.Error("expected DROP ALL capabilities patch")
	}
	if !hasRunAsNonRoot {
		t.Error("expected runAsNonRoot patch")
	}
}

func TestRequestSizeLimit(t *testing.T) {
	if maxRequestBodyBytes != 1<<20 {
		t.Errorf("expected maxRequestBodyBytes to be 1MB (1<<20), got %d", maxRequestBodyBytes)
	}
}

func TestSeverityConstants(t *testing.T) {
	// Verify severity constants match what admission webhook uses
	if finding.Critical != "CRITICAL" {
		t.Errorf("expected finding.Critical = 'CRITICAL', got %s", finding.Critical)
	}
	if finding.High != "HIGH" {
		t.Errorf("expected finding.High = 'HIGH', got %s", finding.High)
	}
}