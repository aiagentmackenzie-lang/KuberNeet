package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/fatih/color"
	"github.com/raphael/kuberneet/pkg/admission"
	"github.com/raphael/kuberneet/pkg/scanner"
	"github.com/spf13/cobra"
)

var webhookOpts = struct {
	port     int
	certFile string
	keyFile  string
	mutate   bool
}{}

var webhookCmd = &cobra.Command{
	Use:   "webhook",
	Short: "Run admission webhook server",
	Long: `Run as a Kubernetes admission webhook to enforce security policies.

Blocks creation of pods/deployments that violate security policies,
or auto-fixes issues if --mutate is enabled.

Examples:
  # Run validation webhook only
  kuberneet webhook --cert server.crt --key server.key

  # Run with auto-mutation (fixes issues automatically)
  kuberneet webhook --mutate --cert server.crt --key server.key

  # Test with self-signed certs
  kuberneet webhook --port 8443`,
	RunE: runWebhook,
}

func init() {
	rootCmd.AddCommand(webhookCmd)

	webhookCmd.Flags().IntVarP(&webhookOpts.port, "port", "p", 8443, "Webhook server port")
	webhookCmd.Flags().StringVarP(&webhookOpts.certFile, "cert", "c", "", "TLS certificate file")
	webhookCmd.Flags().StringVarP(&webhookOpts.keyFile, "key", "k", "", "TLS key file")
	webhookCmd.Flags().BoolVarP(&webhookOpts.mutate, "mutate", "m", false, "Enable mutation (auto-fix) mode")
}

func runWebhook(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\nShutting down webhook server...")
		cancel()
	}()

	// Initialize scanner
	s, err := scanner.New(scanner.Options{
		Verbose: verbose,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to connect to cluster for scanner: %v\n", err)
		fmt.Fprintln(os.Stderr, "Webhook will run in validate-only mode (no inline policy checks)")
	}

	fmt.Println(color.CyanString("▶ KuberNeet Admission Webhook"))
	fmt.Printf("Port: %d\n", webhookOpts.port)
	fmt.Printf("Mutation: %v\n", webhookOpts.mutate)
	
	if webhookOpts.certFile != "" {
		fmt.Printf("TLS: %s / %s\n", webhookOpts.certFile, webhookOpts.keyFile)
	}
	fmt.Println()

	// Start server
	server := admission.NewServer(
		webhookOpts.port,
		webhookOpts.certFile,
		webhookOpts.keyFile,
		s,
		webhookOpts.mutate,
	)

	return server.Start(ctx)
}
