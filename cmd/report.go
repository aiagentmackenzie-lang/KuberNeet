package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/fatih/color"
	"github.com/raphael/kuberneet/pkg/report"
	"github.com/raphael/kuberneet/pkg/scanner"
	"github.com/spf13/cobra"
	"k8s.io/client-go/util/homedir"
)

var reportOpts = struct {
	namespace string
	output    string
	html      bool
}{}

var reportCmd = &cobra.Command{
	Use:   "report",
	Short: "Generate comprehensive security report",
	Long: `Generate comprehensive security report with findings and attack paths.

Supports multiple output formats:
- HTML: Interactive report with D3 attack graph visualization
- JSON: Structured data for automation
- SARIF: GitHub Code Scanning format

Examples:
  # Generate HTML report
  kuberneet report --html --output report.html

  # JSON report for CI/CD
  kuberneet report --output report.json

  # Scan specific namespace and generate HTML
  kuberneet report --namespace production --html --output prod-report.html`,
	RunE: runReport,
}

func init() {
	rootCmd.AddCommand(reportCmd)

	reportCmd.Flags().StringVarP(&reportOpts.namespace, "namespace", "n", "", "Target namespace (default: all)")
	reportCmd.Flags().StringVarP(&reportOpts.output, "output", "o", "kuberneet-report.html", "Output file path")
	reportCmd.Flags().BoolVarP(&reportOpts.html, "html", "", true, "Generate HTML report")
}

func runReport(cmd *cobra.Command, args []string) error {
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
		Namespace:  reportOpts.namespace,
		Verbose:    verbose,
	})
	if err != nil {
		return fmt.Errorf("failed to initialize scanner: %w", err)
	}

	fmt.Println(color.CyanString("▶ Generating security report..."))

	// Run full scan with graph
	result, err := s.ScanWithGraph(ctx)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	// Generate report
	if reportOpts.html {
		rpt := report.NewHTMLReport(result.Findings, result.AttackPaths, result.Graph)
		if err := rpt.Generate(reportOpts.output); err != nil {
			return fmt.Errorf("failed to generate HTML report: %w", err)
		}
		fmt.Printf("\n%s Generated HTML report: %s\n", color.GreenString("✓"), reportOpts.output)
		fmt.Println("Open in browser: file://" + absPath(reportOpts.output))
	}

	// Print summary
	fmt.Printf("\n%s Report Summary:\n", color.CyanString("▶"))
	fmt.Printf("  Findings: %d\n", len(result.Findings))
	fmt.Printf("  Attack Paths: %d\n", len(result.AttackPaths))
	fmt.Printf("  Graph Nodes: %d\n", len(result.Graph.Nodes))
	fmt.Printf("  Graph Edges: %d\n", len(result.Graph.Edges))

	return nil
}

func absPath(path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	wd, err := os.Getwd()
	if err != nil {
		return path
	}
	return filepath.Join(wd, path)
}
