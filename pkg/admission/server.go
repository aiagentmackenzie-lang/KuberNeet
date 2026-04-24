package admission

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/raphael/kuberneet/pkg/scanner"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/api/admission/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
)

var (
	runtimeScheme = runtime.NewScheme()
	codecs        = serializer.NewCodecFactory(runtimeScheme)
	deserializer  = codecs.UniversalDeserializer()
)

func init() {
	_ = corev1.AddToScheme(runtimeScheme)
	_ = v1beta1.AddToScheme(runtimeScheme)
}

// Server handles admission webhook requests
type Server struct {
	port      int
	certFile  string
	keyFile   string
	scanner   *scanner.Scanner
	mutating  bool // Whether to auto-fix issues (mutate) or just reject (validate)
}

// NewServer creates a new admission webhook server
func NewServer(port int, certFile, keyFile string, s *scanner.Scanner, mutating bool) *Server {
	return &Server{
		port:     port,
		certFile: certFile,
		keyFile:  keyFile,
		scanner:  s,
		mutating: mutating,
	}
}

// Start runs the admission webhook server
func (s *Server) Start(ctx context.Context) error {
	mux := http.NewServeMux()
	
	// Validation webhook endpoint
	mux.HandleFunc("/validate", s.handleValidate)
	
	// Mutation webhook endpoint (if enabled)
	if s.mutating {
		mux.HandleFunc("/mutate", s.handleMutate)
	}
	
	// Health endpoint
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", s.port),
		Handler: mux,
	}

	// Handle graceful shutdown
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		server.Shutdown(shutdownCtx)
	}()

	fmt.Printf("Starting admission webhook server on :%d\n", s.port)
	if s.certFile != "" && s.keyFile != "" {
		return server.ListenAndServeTLS(s.certFile, s.keyFile)
	}
	return server.ListenAndServe()
}

// handleValidate processes validation webhook requests
func (s *Server) handleValidate(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "could not read request body", http.StatusBadRequest)
		return
	}

	var admissionReview v1beta1.AdmissionReview
	if _, _, err := deserializer.Decode(body, nil, &admissionReview); err != nil {
		http.Error(w, fmt.Sprintf("could not deserialize request: %v", err), http.StatusBadRequest)
		return
	}

	req := admissionReview.Request
	if req == nil {
		http.Error(w, "missing admission request", http.StatusBadRequest)
		return
	}

	// Process the resource
	response := s.validateResource(req)

	// Send response
	admissionReview.Response = response
	respBytes, err := json.Marshal(admissionReview)
	if err != nil {
		http.Error(w, fmt.Sprintf("could not marshal response: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(respBytes)
}

// validateResource checks a resource against security policies
func (s *Server) validateResource(req *v1beta1.AdmissionRequest) *v1beta1.AdmissionResponse {
	response := &v1beta1.AdmissionResponse{
		UID:     req.UID,
		Allowed: true,
	}

	switch req.Kind.Kind {
	case "Pod":
		return s.validatePod(req)
	case "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet":
		return s.validateDeployment(req)
	}

	return response
}

// validatePod checks pod security
func (s *Server) validatePod(req *v1beta1.AdmissionRequest) *v1beta1.AdmissionResponse {
	response := &v1beta1.AdmissionResponse{
		UID:     req.UID,
		Allowed: true,
	}

	var pod corev1.Pod
	if err := json.Unmarshal(req.Object.Raw, &pod); err != nil {
		response.Allowed = false
		response.Result = &metav1.Status{
			Message: fmt.Sprintf("could not parse pod: %v", err),
			Code:    http.StatusBadRequest,
		}
		return response
	}

	if s.scanner == nil {
		// No cluster connection — do basic static checks only
		response.Allowed = false
		response.Result = &metav1.Status{
			Message: "Scanner unavailable: cannot validate pod security",
			Code:    http.StatusServiceUnavailable,
		}
		return response
	}

	// Run security checks
	findings := s.scanner.CheckPod(&pod)
	
	// Check for critical findings
	var criticalFindings []string
	for _, f := range findings {
		if f.Severity == "CRITICAL" || f.Severity == "HIGH" {
			criticalFindings = append(criticalFindings, 
				fmt.Sprintf("[%s] %s: %s", f.ID, f.Severity, f.Message))
		}
	}

	if len(criticalFindings) > 0 {
		response.Allowed = false
		response.Result = &metav1.Status{
			Message: fmt.Sprintf("Security policy violation:\n%s", 
				strings.Join(criticalFindings, "\n")),
			Code:    http.StatusForbidden,
			Reason:  metav1.StatusReasonForbidden,
		}
	}

	return response
}

// validateDeployment checks deployment security
func (s *Server) validateDeployment(req *v1beta1.AdmissionRequest) *v1beta1.AdmissionResponse {
	response := &v1beta1.AdmissionResponse{
		UID:     req.UID,
		Allowed: true,
	}

	if s.scanner == nil {
		response.Allowed = false
		response.Result = &metav1.Status{
			Message: "Scanner unavailable: cannot validate deployment security",
			Code:    http.StatusServiceUnavailable,
		}
		return response
	}

	var deploy appsv1.Deployment
	if err := json.Unmarshal(req.Object.Raw, &deploy); err != nil {
		response.Allowed = false
		response.Result = &metav1.Status{
			Message: fmt.Sprintf("could not parse deployment: %v", err),
			Code:    http.StatusBadRequest,
		}
		return response
	}

	// Check the pod template spec
	findings := s.scanner.CheckPod(&corev1.Pod{
		Spec: deploy.Spec.Template.Spec,
	})

	var criticalFindings []string
	for _, f := range findings {
		if f.Severity == "CRITICAL" || f.Severity == "HIGH" {
			criticalFindings = append(criticalFindings,
				fmt.Sprintf("[%s] %s: %s", f.ID, f.Severity, f.Message))
		}
	}

	if len(criticalFindings) > 0 {
		response.Allowed = false
		response.Result = &metav1.Status{
			Message: fmt.Sprintf("Security policy violation:\n%s",
				strings.Join(criticalFindings, "\n")),
			Code:    http.StatusForbidden,
			Reason:  metav1.StatusReasonForbidden,
		}
	}

	return response
}

// handleMutate processes mutation webhook requests
func (s *Server) handleMutate(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "could not read request body", http.StatusBadRequest)
		return
	}

	var admissionReview v1beta1.AdmissionReview
	if _, _, err := deserializer.Decode(body, nil, &admissionReview); err != nil {
		http.Error(w, fmt.Sprintf("could not deserialize request: %v", err), http.StatusBadRequest)
		return
	}

	req := admissionReview.Request
	if req == nil {
		http.Error(w, "missing admission request", http.StatusBadRequest)
		return
	}

	// Process and mutate
	response := s.mutateResource(req)

	admissionReview.Response = response
	respBytes, err := json.Marshal(admissionReview)
	if err != nil {
		http.Error(w, fmt.Sprintf("could not marshal response: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(respBytes)
}

// mutateResource auto-fixes security issues
func (s *Server) mutateResource(req *v1beta1.AdmissionRequest) *v1beta1.AdmissionResponse {
	response := &v1beta1.AdmissionResponse{
		UID:     req.UID,
		Allowed: true,
	}

	if req.Kind.Kind != "Pod" {
		return response
	}

	var pod corev1.Pod
	if err := json.Unmarshal(req.Object.Raw, &pod); err != nil {
		return response
	}

	// Apply security fixes as mutations
	patches := s.generateSecurityPatches(&pod)
	
	if len(patches) > 0 {
		patchBytes, _ := json.Marshal(patches)
		patchType := v1beta1.PatchTypeJSONPatch
		response.Patch = patchBytes
		response.PatchType = &patchType
	}

	return response
}

// generateSecurityPatches creates JSON patches to fix issues
func (s *Server) generateSecurityPatches(pod *corev1.Pod) []PatchOperation {
	var patches []PatchOperation

	// Ensure securityContext exists
	if pod.Spec.SecurityContext == nil {
		patches = append(patches, PatchOperation{
			Op:    "add",
			Path:  "/spec/securityContext",
			Value: map[string]interface{}{},
		})
	}

	// Add seccomp profile
	patches = append(patches, PatchOperation{
		Op:   "add",
		Path: "/spec/securityContext/seccompProfile",
		Value: map[string]string{
			"type": "RuntimeDefault",
		},
	})

	// Ensure containers have security context
	for i, container := range pod.Spec.Containers {
		if container.SecurityContext == nil {
			patches = append(patches, PatchOperation{
				Op:    "add",
				Path:  fmt.Sprintf("/spec/containers/%d/securityContext", i),
				Value: map[string]interface{}{},
			})
		}
		
		// Drop ALL capabilities
		patches = append(patches, PatchOperation{
			Op:   "add",
			Path: fmt.Sprintf("/spec/containers/%d/securityContext/capabilities", i),
			Value: map[string]interface{}{
				"drop": []string{"ALL"},
			},
		})
		
		// Set allowPrivilegeEscalation: false
		patches = append(patches, PatchOperation{
			Op:    "add",
			Path:  fmt.Sprintf("/spec/containers/%d/securityContext/allowPrivilegeEscalation", i),
			Value: false,
		})
		
		// Set readOnlyRootFilesystem: true
		patches = append(patches, PatchOperation{
			Op:    "add",
			Path:  fmt.Sprintf("/spec/containers/%d/securityContext/readOnlyRootFilesystem", i),
			Value: true,
		})
		
		// Set runAsNonRoot: true
		patches = append(patches, PatchOperation{
			Op:    "add",
			Path:  fmt.Sprintf("/spec/containers/%d/securityContext/runAsNonRoot", i),
			Value: true,
		})
	}

	// Disable service account token automount if not needed
	if pod.Spec.ServiceAccountName == "default" || pod.Spec.ServiceAccountName == "" {
		patches = append(patches, PatchOperation{
			Op:    "add",
			Path:  "/spec/automountServiceAccountToken",
			Value: false,
		})
	}

	return patches
}

// PatchOperation represents a JSON Patch operation
type PatchOperation struct {
	Op    string      `json:"op"`
	Path  string      `json:"path"`
	Value interface{} `json:"value,omitempty"`
}
