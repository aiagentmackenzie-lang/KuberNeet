package federation

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/raphael/kuberneet/pkg/finding"
	"github.com/raphael/kuberneet/pkg/scanner"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

// ClusterConfig holds kubeconfig path and context for a single cluster
type ClusterConfig struct {
	Name       string
	Kubeconfig string
	Context    string
}

// MultiClusterScanner scans multiple clusters
type MultiClusterScanner struct {
	clusters []ClusterConfig
}

// NewMultiClusterScanner creates a scanner for multiple clusters
func NewMultiClusterScanner() *MultiClusterScanner {
	return &MultiClusterScanner{
		clusters: []ClusterConfig{},
	}
}

// AddCluster registers a cluster to scan
func (m *MultiClusterScanner) AddCluster(name, kubeconfig, context string) {
	m.clusters = append(m.clusters, ClusterConfig{
		Name:       name,
		Kubeconfig: kubeconfig,
		Context:    context,
	})
}

// AddClusterFromKubeconfig adds all contexts from a kubeconfig
func (m *MultiClusterScanner) AddClusterFromKubeconfig(kubeconfigPath string) error {
	kubeconfig := kubeconfigPath
	if kubeconfig == "" {
		home := homedir.HomeDir()
		kubeconfig = filepath.Join(home, ".kube", "config")
	}

	config, err := clientcmd.LoadFromFile(kubeconfig)
	if err != nil {
		return fmt.Errorf("failed to load kubeconfig: %w", err)
	}

	for contextName := range config.Contexts {
		// Get cluster info
		ctx := config.Contexts[contextName]
		if ctx == nil {
			continue
		}

		clusterName := ctx.Cluster
		if clusterName == "" {
			clusterName = contextName
		}

		m.AddCluster(clusterName, kubeconfig, contextName)
	}

	return nil
}

// ScanResult aggregates findings from one cluster
type ScanResult struct {
	Cluster   string
	Findings  []finding.Finding
	NodeCount int
	Error     error
}

// ScanAll scans all registered clusters
func (m *MultiClusterScanner) ScanAll(ctx context.Context) ([]ScanResult, error) {
	var results []ScanResult

	for _, cluster := range m.clusters {
		result := m.scanCluster(ctx, cluster)
		results = append(results, result)
	}

	return results, nil
}

func (m *MultiClusterScanner) scanCluster(ctx context.Context, config ClusterConfig) ScanResult {
	// Create scanner for this cluster
	s, err := scanner.New(scanner.Options{
		Kubeconfig: config.Kubeconfig,
		Context:    config.Context,
		Verbose:    false,
	})

	if err != nil {
		return ScanResult{
			Cluster: config.Name,
			Error:   fmt.Errorf("failed to create scanner: %w", err),
		}
	}

	// Get cluster stats
	// nodes, _ := s.GetClientset().CoreV1().Nodes().List(ctx, metav1.ListOptions{})

	// Run scan
	findings, err := s.ScanCluster(ctx)

	result := ScanResult{
		Cluster:  config.Name,
		Findings: findings,
	}

	if err != nil {
		result.Error = err
	}

	return result
}

// AggregateResults combines all findings across clusters
type AggregateResult struct {
	TotalClusters   int
	TotalFindings   int
	ClustersScanned int
	ClustersFailed  int
	BySeverity      map[string]int
	ByCluster       map[string][]finding.Finding
}

// Aggregate creates a summary of all scan results
func Aggregate(results []ScanResult) *AggregateResult {
	agg := &AggregateResult{
		TotalClusters:   len(results),
		ClustersScanned: 0,
		ClustersFailed:  0,
		BySeverity:      make(map[string]int),
		ByCluster:       make(map[string][]finding.Finding),
	}

	for _, result := range results {
		if result.Error != nil {
			agg.ClustersFailed++
			continue
		}

		agg.ClustersScanned++
		agg.TotalFindings += len(result.Findings)
		agg.ByCluster[result.Cluster] = result.Findings

		for _, f := range result.Findings {
			agg.BySeverity[f.Severity]++
		}
	}

	return agg
}

// GetClusterNames returns names of all registered clusters
func (m *MultiClusterScanner) GetClusterNames() []string {
	names := []string{}
	for _, c := range m.clusters {
		names = append(names, c.Name)
	}
	return names
}

// PrintSummary outputs a formatted summary
func (a *AggregateResult) PrintSummary() {
	fmt.Println("╔═══════════════════════════════════════════════════════════════╗")
	fmt.Println("║              Multi-Cluster Security Summary                   ║")
	fmt.Println("╠═══════════════════════════════════════════════════════════════╣")
	fmt.Printf("║  Total Clusters: %-4d  Scanned: %-4d  Failed: %-4d         ║\n",
		a.TotalClusters, a.ClustersScanned, a.ClustersFailed)
	fmt.Println("╠═══════════════════════════════════════════════════════════════╣")
	fmt.Printf("║  Critical: %-4d  High: %-4d  Medium: %-4d  Low: %-4d       ║\n",
		a.BySeverity["CRITICAL"], a.BySeverity["HIGH"],
		a.BySeverity["MEDIUM"], a.BySeverity["LOW"])
	fmt.Println("╚═══════════════════════════════════════════════════════════════╝")
	fmt.Println()

	for cluster, findings := range a.ByCluster {
		fmt.Printf("\n▶ %s (%d findings)\n", cluster, len(findings))
		critical := 0
		high := 0
		for _, f := range findings {
			if f.Severity == "CRITICAL" {
				critical++
			}
			if f.Severity == "HIGH" {
				high++
			}
		}
		if critical > 0 {
			fmt.Printf("  ⚠ CRITICAL: %d\n", critical)
		}
		if high > 0 {
			fmt.Printf("  ⚠ HIGH: %d\n", high)
		}
	}
}
