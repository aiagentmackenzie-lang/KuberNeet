package scanner

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/raphael/kuberneet/pkg/finding"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

type Options struct {
	Kubeconfig string
	Namespace  string
	Severity   string
	WithRemedy bool
	Verbose    bool
}

type Scanner struct {
	clientset  *kubernetes.Clientset
	config     *rest.Config
	namespace  string
	severity   string
	withRemedy bool
	verbose    bool
}

func New(opts Options) (*Scanner, error) {
	var config *rest.Config
	var err error

	if opts.Kubeconfig != "" {
		config, err = clientcmd.BuildConfigFromFlags("", opts.Kubeconfig)
	} else {
		// Try in-cluster config first
		config, err = rest.InClusterConfig()
		if err != nil {
			// Fall back to kubeconfig
			home := homedir.HomeDir()
			kubeconfig := filepath.Join(home, ".kube", "config")
			config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		}
	}

	if err != nil {
		return nil, fmt.Errorf("unable to load kubeconfig: %w", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("unable to create kubernetes client: %w", err)
	}

	return &Scanner{
		clientset:  clientset,
		config:     config,
		namespace:  opts.Namespace,
		severity:   opts.Severity,
		withRemedy: opts.WithRemedy,
		verbose:    opts.Verbose,
	}, nil
}

func (s *Scanner) ScanCluster(ctx context.Context) ([]finding.Finding, error) {
	var findings []finding.Finding

	if s.verbose {
		fmt.Println("Connecting to cluster...")
	}

	// Test connection
	version, err := s.clientset.Discovery().ServerVersion()
	if err != nil {
		return nil, fmt.Errorf("cluster connection failed: %w", err)
	}
	if s.verbose {
		fmt.Printf("Connected to Kubernetes v%s\n", version.GitVersion)
	}

	// Scan pods
	podFindings, err := s.scanPods(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to scan pods: %w", err)
	}
	findings = append(findings, podFindings...)

	// Scan deployments
	deployFindings, err := s.scanDeployments(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to scan deployments: %w", err)
	}
	findings = append(findings, deployFindings...)

	// Scan RBAC
	 rbacFindings, err := s.scanRBAC(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to scan RBAC: %w", err)
	}
	findings = append(findings, rbacFindings...)

	// Scan NetworkPolicies
	networkFindings, err := s.scanNetworkPolicies(ctx)
	if err != nil {
		// NetworkPolicy is optional - may not be available
		if s.verbose {
			fmt.Printf("Warning: NetworkPolicy scan failed: %v\n", err)
		}
	} else {
		findings = append(findings, networkFindings...)
	}

	// Scan CIS Benchmarks (requires node access, optional)
	cisFindings, err := s.scanCIS(ctx)
	if err != nil {
		if s.verbose {
			fmt.Printf("Warning: CIS scan failed: %v\n", err)
		}
	} else {
		findings = append(findings, cisFindings...)
	}

	return s.filterBySeverity(findings), nil
}

func (s *Scanner) ScanManifest(ctx context.Context, manifestPath string) ([]finding.Finding, error) {
	var findings []finding.Finding

	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read manifest: %w", err)
	}

	// Parse YAML (basic - would need multi-doc support for production)
	docs := strings.Split(string(data), "---")

	for _, doc := range docs {
		doc = strings.TrimSpace(doc)
		if doc == "" {
			continue
		}

		obj := &metav1.Unstructured{}
		// Simple unstructured parse - would use proper YAML decoder in production
		// For now, skip manifest scanning
		_ = obj
	}

	_ = ctx

	return findings, fmt.Errorf("manifest scanning not yet implemented")
}

func (s *Scanner) filterBySeverity(findings []finding.Finding) []finding.Finding {
	if s.severity == "" {
		return findings
	}

	var filtered []finding.Finding
	for _, f := range findings {
		if shouldInclude(f.Severity, s.severity) {
			filtered = append(filtered, f)
		}
	}
	return filtered
}

func shouldInclude(findingSev, filterSev string) bool {
	severityOrder := map[string]int{
		finding.Critical: 4,
		finding.High:     3,
		finding.Medium:   2,
		finding.Low:      1,
		finding.Info:     0,
	}

	return severityOrder[findingSev] >= severityOrder[filterSev]
}

// GetClientset returns the kubernetes clientset
func (s *Scanner) GetClientset() *kubernetes.Clientset {
	return s.clientset
}

// CheckPod runs security checks on a single pod (public API)
func (s *Scanner) CheckPod(pod *corev1.Pod) []finding.Finding {
	return s.checkPodSecurity(pod)
}

// Interface compliance
var _ informers.SharedInformerFactory = nil
var _ runtime.Object = (*corev1.Pod)(nil)
