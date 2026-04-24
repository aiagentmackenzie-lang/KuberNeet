package scanner

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/raphael/kuberneet/pkg/finding"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/yaml"
)

type Options struct {
	Kubeconfig string
	Context    string
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

	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	if opts.Kubeconfig != "" {
		loadingRules.ExplicitPath = opts.Kubeconfig
	}

	configOverrides := &clientcmd.ConfigOverrides{}
	if opts.Context != "" {
		configOverrides.CurrentContext = opts.Context
	}

	config, err = clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		loadingRules,
		configOverrides,
	).ClientConfig()

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
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read manifest: %w", err)
	}

	var findings []finding.Finding

	// Split multi-document YAML
	docs := strings.Split(string(data), "---")

	for _, doc := range docs {
		doc = strings.TrimSpace(doc)
		if doc == "" {
			continue
		}

		// Parse into unstructured to determine kind
		var obj map[string]interface{}
		if err := yaml.Unmarshal([]byte(doc), &obj); err != nil {
			if s.verbose {
				fmt.Printf("Warning: failed to parse manifest document: %v\n", err)
			}
			continue
		}

		kind, _ := obj["kind"].(string)

		switch kind {
		case "Pod":
			var pod corev1.Pod
			if err := yaml.Unmarshal([]byte(doc), &pod); err != nil {
				continue
			}
			if pod.Namespace == "" {
				pod.Namespace = "default"
			}
			findings = append(findings, s.checkPodSecurity(&pod)...)
		case "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet":
			var deploy appsv1.Deployment
			if err := yaml.Unmarshal([]byte(doc), &deploy); err != nil {
				// Try other workload kinds
				continue
			}
			if deploy.Namespace == "" {
				deploy.Namespace = "default"
			}
			findings = append(findings, s.checkDeploymentSecurity(&deploy)...)
		}
	}

	_ = ctx

	return s.filterBySeverity(findings), nil
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

// kubernetesClientsetFromConfig creates an anonymous clientset for CIS checks.
func kubernetesClientsetFromConfig(config *rest.Config, anonymous bool) (*kubernetes.Clientset, error) {
	if anonymous {
		anonConfig := rest.CopyConfig(config)
		anonConfig.BearerToken = ""
		anonConfig.Username = ""
		anonConfig.Password = ""
		return kubernetes.NewForConfig(anonConfig)
	}
	return kubernetes.NewForConfig(config)
}

// OPAEngine interface for OPA policy evaluation.
// Defined here to avoid circular import between scanner and opa packages.

type OPAEvaluator interface {
	ScanResource(ctx context.Context, resource map[string]interface{}) ([]finding.Finding, error)
}

// ScanWithOPA runs OPA/Rego policy evaluation alongside the built-in scanner.
func (s *Scanner) ScanWithOPA(ctx context.Context, evaluator OPAEvaluator) ([]finding.Finding, error) {
	var findings []finding.Finding

	// Scan pods with OPA
	pods, err := s.clientset.CoreV1().Pods(s.namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list pods for OPA scan: %w", err)
	}

	for _, pod := range pods.Items {
		// Convert pod to map for OPA evaluation
		podMap, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&pod)
		if err != nil {
			if s.verbose {
				fmt.Printf("Warning: failed to convert pod %s: %v\n", pod.Name, err)
			}
			continue
		}
		opaFindings, err := evaluator.ScanResource(ctx, podMap)
		if err != nil {
			if s.verbose {
				fmt.Printf("Warning: OPA evaluation failed for pod %s: %v\n", pod.Name, err)
			}
			continue
		}
		findings = append(findings, opaFindings...)
	}

	return s.filterBySeverity(findings), nil
}
