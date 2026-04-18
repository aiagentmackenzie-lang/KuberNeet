package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/fatih/color"
	"github.com/raphael/kuberneet/pkg/graph"
	"github.com/raphael/kuberneet/pkg/scanner"
	"github.com/spf13/cobra"
	"k8s.io/client-go/util/homedir"
)

var graphOpts = struct {
	namespace string
	output    string
}{}

var graphCmd = &cobra.Command{
	Use:   "graph",
	Short: "Build attack graph and find attack paths",
	Long: `Build a graph of Kubernetes resources and identify attack paths.

Identifies:
- External-facing services (LoadBalancer, NodePort) that select privileged pods
- RBAC privilege escalation paths
- ServiceAccount to cluster-admin bindings
- Container escape opportunities

Examples:
  # Build graph for all namespaces
  kuberneet graph

  # Graph specific namespace
  kuberneet graph --namespace production

  # Export graph as JSON
  kuberneet graph --output graph.json`,
	RunE: runGraph,
}

func init() {
	rootCmd.AddCommand(graphCmd)

	graphCmd.Flags().StringVarP(&graphOpts.namespace, "namespace", "n", "", "Target namespace (default: all)")
	graphCmd.Flags().StringVarP(&graphOpts.output, "output", "o", "", "Export graph to JSON file")
}

func runGraph(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	// Get kubeconfig
	kubeconfig := ""
	if home := homedir.HomeDir(); home != "" {
		kubeconfig = filepath.Join(home, ".kube", "config")
	}
	if k := os.Getenv("KUBECONFIG"); k != "" {
		kubeconfig = k
	}

	// Initialize scanner
	s, err := scanner.New(scanner.Options{
		Kubeconfig: kubeconfig,
		Namespace:  graphOpts.namespace,
		Verbose:    verbose,
	})
	if err != nil {
		return fmt.Errorf("failed to initialize scanner: %w", err)
	}

	fmt.Println(color.CyanString("Building Kubernetes attack graph..."))

	result, err := s.ScanWithGraph(ctx)
	if err != nil {
		return fmt.Errorf("graph scan failed: %w", err)
	}

	// Print attack paths
	fmt.Println()
	if len(result.AttackPaths) == 0 {
		color.Green("✓ No attack paths identified")
	} else {
		color.Red("⚠ Found %d attack paths\n", len(result.AttackPaths))
		fmt.Println()
		for i, path := range result.AttackPaths {
			printAttackPath(i+1, path)
		}
	}

	// Print graph stats
	fmt.Printf("\n%s Graph stats:\n", color.CyanString("▶"))
	fmt.Printf("  Nodes: %d\n", len(result.Graph.Nodes))
	fmt.Printf("  Edges: %d\n", len(result.Graph.Edges))
	fmt.Printf("  Findings: %d\n", len(result.Findings))

	// Export if requested
	if graphOpts.output != "" {
		if err := s.ExportGraph(result, graphOpts.output); err != nil {
			return fmt.Errorf("failed to export graph: %w", err)
		}
		fmt.Printf("\n%s Exported graph to %s\n", color.GreenString("✓"), graphOpts.output)
	}

	return nil
}

func printAttackPath(index int, path graph.AttackPath) {
	fmt.Printf(color.RedString("═══ Attack Path %d ═══\n"), index)
	fmt.Printf("Technique: %s\n", color.YellowString(path.Technique))
	fmt.Printf("Tactic:    %s\n", path.Tactic)
	fmt.Printf("Risk:      %s\n", severityFromScore(path.RiskScore))
	fmt.Printf("Chain:     ")

	for i, node := range path.Path {
		if i > 0 {
			fmt.Print(color.WhiteString(" → "))
		}
		fmt.Printf("%s/%s", node.Type, color.CyanString(node.Name))
	}
	fmt.Println()
	fmt.Printf("\nDescription: %s\n\n", path.Description)
}

func severityFromScore(score float64) string {
	switch {
	case score >= 150:
		return color.RedString("CRITICAL (%.0f)", score)
	case score >= 100:
		return color.MagentaString("HIGH (%.0f)", score)
	case score >= 50:
		return color.YellowString("MEDIUM (%.0f)", score)
	default:
		return color.BlueString("LOW (%.0f)", score)
	}
}
