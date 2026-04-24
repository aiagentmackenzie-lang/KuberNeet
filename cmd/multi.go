package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/fatih/color"
	"github.com/raphael/kuberneet/pkg/finding"
	"github.com/raphael/kuberneet/pkg/federation"
	"github.com/spf13/cobra"
	"k8s.io/client-go/util/homedir"
)

var multiOpts = struct {
	kubeconfig string
	output     string
}{}

var multiCmd = &cobra.Command{
	Use:   "multi",
	Short: "Scan multiple Kubernetes clusters",
	Long: `Scan multiple Kubernetes clusters defined in kubeconfig contexts.

Aggregates findings across all clusters with summary reporting.

Examples:
  # Scan all clusters in default kubeconfig
  kuberneet multi

  # Scan specific kubeconfig
  kuberneet multi --kubeconfig ~/.kube/config

  # JSON output for aggregation
  kuberneet multi --output json`,
	RunE: runMultiCluster,
}

func init() {
	rootCmd.AddCommand(multiCmd)

	multiCmd.Flags().StringVarP(&multiOpts.kubeconfig, "kubeconfig", "k", "", "Path to kubeconfig file")
	multiCmd.Flags().StringVarP(&multiOpts.output, "output", "o", "table", "Output format: table|json")
}

func runMultiCluster(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	// Get kubeconfig
	kubeconfig := multiOpts.kubeconfig
	if kubeconfig == "" {
		if k := os.Getenv("KUBECONFIG"); k != "" {
			kubeconfig = k
		} else if home := homedir.HomeDir(); home != "" {
			kubeconfig = filepath.Join(home, ".kube", "config")
		}
	}

	fmt.Println(color.CyanString("▶ KuberNeet Multi-Cluster Scanner"))
	fmt.Printf("Kubeconfig: %s\n\n", kubeconfig)

	// Create multi-cluster scanner
	mcs := federation.NewMultiClusterScanner()
	
	if err := mcs.AddClusterFromKubeconfig(kubeconfig); err != nil {
		return fmt.Errorf("failed to load clusters from kubeconfig: %w", err)
	}

	// Need to expose Clusters field from MultiClusterScanner
	fmt.Printf("Found cluster(s) to scan...\n\n")

	// Run scans
	results, err := mcs.ScanAll(ctx)
	if err != nil {
		return fmt.Errorf("multi-cluster scan failed: %w", err)
	}

	// Aggregate results
	agg := federation.Aggregate(results)

	// Output
	switch multiOpts.output {
	case "json":
		return outputJSON(results)
	default:
		agg.PrintSummary()
	}

	return nil
}

func outputJSON(results []federation.ScanResult) error {
	type clusterOutput struct {
		Cluster   string            `json:"cluster"`
		Findings  []finding.Finding `json:"findings"`
		NodeCount int               `json:"node_count"`
		Error     string            `json:"error,omitempty"`
	}

	outputs := make([]clusterOutput, len(results))
	for i, r := range results {
		o := clusterOutput{
			Cluster:   r.Cluster,
			Findings:  r.Findings,
			NodeCount: r.NodeCount,
		}
		if r.Error != nil {
			o.Error = r.Error.Error()
		}
		outputs[i] = o
	}

	data, err := json.MarshalIndent(outputs, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(data))
	return nil
}
