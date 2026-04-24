package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/raphael/kuberneet/pkg/finding"
	"github.com/raphael/kuberneet/pkg/opa"
	"github.com/raphael/kuberneet/pkg/scanner"
	"github.com/spf13/cobra"
	"k8s.io/client-go/util/homedir"
)

type scanOptions struct {
	namespace    string
	manifest     string
	output       string
	outputFile   string
	severity     string
	withRemedy   bool
	opa          bool
	verbose      bool
}

var scanOpts = &scanOptions{}

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan Kubernetes resources for security issues",
	Long: `Scan Kubernetes cluster or local manifests for security vulnerabilities.

Examples:
  # Scan entire cluster
  kuberneet scan

  # Scan specific namespace
  kuberneet scan --namespace production

  # Scan local manifest
  kuberneet scan --manifest deployment.yaml

  # Output as JSON for CI/CD
  kuberneet scan --output json

  # Output as SARIF for GitHub Code Scanning
  kuberneet scan --output sarif

  # Show only critical findings
  kuberneet scan --severity CRITICAL`,
	RunE: runScan,
}

func init() {
	rootCmd.AddCommand(scanCmd)

	scanCmd.Flags().StringVarP(&scanOpts.namespace, "namespace", "n", "", "Target namespace (default: all)")
	scanCmd.Flags().StringVarP(&scanOpts.manifest, "manifest", "m", "", "Scan local YAML manifest")
	scanCmd.Flags().StringVarP(&scanOpts.output, "output", "o", "table", "Output format: table|json|yaml|sarif")
	scanCmd.Flags().StringVarP(&scanOpts.outputFile, "output-file", "f", "", "Write output to file (required for sarif)")
	scanCmd.Flags().StringVarP(&scanOpts.severity, "severity", "s", "", "Filter by severity: CRITICAL|HIGH|MEDIUM|LOW")
	scanCmd.Flags().BoolVarP(&scanOpts.withRemedy, "remediate", "r", false, "Include remediation YAML in output")
	scanCmd.Flags().BoolVarP(&scanOpts.opa, "opa", "", false, "Include OPA/Rego policy evaluation")
}

func runScan(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	// Setup kubeconfig path
	kubeconfig := ""
	if home := homedir.HomeDir(); home != "" {
		kubeconfig = filepath.Join(home, ".kube", "config")
	}
	if k := os.Getenv("KUBECONFIG"); k != "" {
		kubeconfig = k
	}

	// Initialize scanner
	s, err := scanner.New(scanner.Options{
		Kubeconfig:   kubeconfig,
		Namespace:    scanOpts.namespace,
		Severity:     scanOpts.severity,
		WithRemedy:   scanOpts.withRemedy,
		Verbose:      verbose,
	})
	if err != nil {
		return fmt.Errorf("failed to initialize scanner: %w", err)
	}

	// Determine scan mode
	var findings []finding.Finding
	var scanType string

	if scanOpts.manifest != "" {
		// Offline manifest scan
		scanType = fmt.Sprintf("manifest: %s", scanOpts.manifest)
		findings, err = s.ScanManifest(ctx, scanOpts.manifest)
		if err != nil {
			return fmt.Errorf("manifest scan failed: %w", err)
		}
	} else {
		// Live cluster scan
		if scanOpts.namespace != "" {
			scanType = fmt.Sprintf("cluster (namespace: %s)", scanOpts.namespace)
		} else {
			scanType = "cluster (all namespaces)"
		}
		findings, err = s.ScanCluster(ctx)
		if err != nil {
			return fmt.Errorf("cluster scan failed: %w", err)
		}
	}

	// Optional OPA/Rego evaluation
	if scanOpts.opa {
		opaEngine, err := opa.NewEngine(ctx)
		if err != nil {
			if verbose {
				fmt.Fprintf(os.Stderr, "Warning: OPA engine failed: %v\n", err)
			}
		} else {
			opaFindings, err := s.ScanWithOPA(ctx, opaEngine)
			if err != nil {
				if verbose {
					fmt.Fprintf(os.Stderr, "Warning: OPA scan failed: %v\n", err)
				}
			} else {
				findings = append(findings, opaFindings...)
			}
		}
	}

	// Output results
	if err := outputResults(findings, scanOpts.output, scanOpts.withRemedy, scanOpts.outputFile, scanType); err != nil {
		return fmt.Errorf("output failed: %w", err)
	}

	return nil
}

func outputResults(findings []finding.Finding, format string, withRemedy bool, outputFile string, scanType string) error {
	switch format {
	case "json":
		if outputFile != "" {
			return finding.JSONFile(findings, withRemedy, outputFile)
		}
		return finding.JSONOutput(findings, withRemedy)
	case "yaml":
		return finding.YAMLOutput(findings, withRemedy)
	case "sarif":
		if outputFile != "" {
			return finding.SARIFFile(findings, "0.1.0", outputFile)
		}
		return finding.SARIFOutput(findings, withRemedy)
	default:
		return tableOutput(findings, withRemedy, scanType)
	}
}

func tableOutput(findings []finding.Finding, withRemedy bool, scanType string) error {
	// Print header
	fmt.Printf("\n%s %s\n", color.CyanString("▶"), color.CyanString("KuberNeet Security Scan"))
	fmt.Printf("  Target: %s\n  Time:   %s\n\n", scanType, time.Now().Format("2006-01-02 15:04:05"))

	if len(findings) == 0 {
		color.Green("✓ No security issues found")
		return nil
	}

	// Summary by severity
	critical := 0
	high := 0
	medium := 0
	low := 0
	for _, f := range findings {
		switch f.Severity {
		case finding.Critical:
			critical++
		case finding.High:
			high++
		case finding.Medium:
			medium++
		case finding.Low:
			low++
		}
	}

	fmt.Printf("  Summary: ")
	if critical > 0 {
		fmt.Printf(color.RedString("CRITICAL: %d  "), critical)
	}
	if high > 0 {
		fmt.Printf(color.MagentaString("HIGH: %d  "), high)
	}
	if medium > 0 {
		fmt.Printf(color.YellowString("MEDIUM: %d  "), medium)
	}
	if low > 0 {
		fmt.Printf(color.BlueString("LOW: %d"), low)
	}
	fmt.Println()
	fmt.Println()

	// Print table header
	fmt.Printf("%-12s %-10s %-30s %-20s %-50s\n", "SEVERITY", "ID", "RESOURCE", "NAMESPACE", "ISSUE")
	fmt.Println(strings.Repeat("-", 122))

	for _, f := range findings {
		sevStr := getSeverityString(f.Severity)
		resName := f.ResourceName
		if len(resName) > 28 {
			resName = resName[:25] + "..."
		}
		issue := f.Message
		if len(issue) > 48 {
			issue = issue[:45] + "..."
		}
		ns := f.Namespace
		if ns == "" {
			ns = "-"
		}
		if len(ns) > 18 {
			ns = ns[:15] + "..."
		}

		fmt.Printf("%-12s %-10s %-30s %-20s %-50s\n", sevStr, f.ID, resName, ns, issue)
	}

	fmt.Printf("\nTotal: %d findings\n", len(findings))

	// Print details if verbose
	if verbose || withRemedy {
		fmt.Println()
		for i, f := range findings {
			if i > 0 {
				fmt.Println(strings.Repeat("-", 80))
			}
			printFindingDetail(f)
		}
	}

	return nil
}

func printFindingDetail(f finding.Finding) {
	sevColor := getSeverityColor(f.Severity)
	fmt.Printf("\n%s [%s] %s\n", sevColor(strings.ToUpper(f.Severity)), color.WhiteString(f.ID), color.CyanString(f.ResourceName))
	fmt.Printf("  Kind:      %s\n", f.ResourceKind)
	if f.Namespace != "" {
		fmt.Printf("  Namespace: %s\n", f.Namespace)
	}
	fmt.Printf("  Issue:     %s\n", f.Message)
	if f.CWE != "" {
		fmt.Printf("  CWE:       %s\n", f.CWE)
	}
	if f.MITRE != "" {
		fmt.Printf("  MITRE:     %s\n", f.MITRE)
	}
	if f.Description != "" {
		fmt.Printf("\n  Description:\n    %s\n", f.Description)
	}
	if f.Remediation != "" {
		fmt.Printf("\n  Remediation:\n%s\n", formatYAML(f.Remediation))
	}
}

func formatYAML(yaml string) string {
	lines := strings.Split(yaml, "\n")
	var formatted []string
	for _, line := range lines {
		if line == "" {
			formatted = append(formatted, "")
		} else {
			formatted = append(formatted, "    "+line)
		}
	}
	return strings.Join(formatted, "\n")
}

func getSeverityString(sev string) string {
	switch sev {
	case finding.Critical:
		return color.RedString("CRITICAL")
	case finding.High:
		return color.MagentaString("HIGH")
	case finding.Medium:
		return color.YellowString("MEDIUM")
	case finding.Low:
		return color.BlueString("LOW")
	default:
		return color.WhiteString(sev)
	}
}

func getSeverityColor(sev string) func(string, ...interface{}) string {
	switch sev {
	case finding.Critical:
		return color.RedString
	case finding.High:
		return color.MagentaString
	case finding.Medium:
		return color.YellowString
	case finding.Low:
		return color.BlueString
	default:
		return color.WhiteString
	}
}
