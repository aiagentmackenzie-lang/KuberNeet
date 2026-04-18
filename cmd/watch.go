package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/fatih/color"
	"github.com/raphael/kuberneet/pkg/scanner"
	"github.com/spf13/cobra"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/homedir"
	corev1 "k8s.io/api/core/v1"
)

var watchOpts = struct {
	namespace string
	severity  string
}{}

var watchCmd = &cobra.Command{
	Use:   "watch",
	Short: "Watch cluster in real-time for security issues",
	Long: `Watch Kubernetes cluster resources and report security issues in real-time.

Uses client-go Informers for efficient event-driven scanning (no polling).

Examples:
  # Watch all namespaces
  kuberneet watch

  # Watch specific namespace
  kuberneet watch --namespace production

  # Watch only critical findings
  kuberneet watch --severity CRITICAL`,
	RunE: runWatch,
}

func init() {
	rootCmd.AddCommand(watchCmd)

	watchCmd.Flags().StringVarP(&watchOpts.namespace, "namespace", "n", "", "Target namespace (default: all)")
	watchCmd.Flags().StringVarP(&watchOpts.severity, "severity", "s", "", "Filter by severity: CRITICAL|HIGH|MEDIUM|LOW")
}

func runWatch(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\nStopping watch...")
		cancel()
	}()

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
		Namespace:  watchOpts.namespace,
		Severity:   watchOpts.severity,
		Verbose:    verbose,
	})
	if err != nil {
		return fmt.Errorf("failed to initialize scanner: %w", err)
	}

	fmt.Println(color.CyanString("▶ KuberNeet Watch Mode"))
	fmt.Println("Watching for security issues in real-time...")
	fmt.Println("Press Ctrl+C to stop\n")

	// Run informer-based watch
	return runInformerWatch(ctx, s)
}

func runInformerWatch(ctx context.Context, s *scanner.Scanner) error {
	// Create SharedInformerFactory
	factory := informers.NewSharedInformerFactory(s.GetClientset(), 0)

	// Add pod informer
	podInformer := factory.Core().V1().Pods().Informer()
	podInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			pod := obj.(*corev1.Pod)
			checkResource(pod, "ADDED", s)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			pod := newObj.(*corev1.Pod)
			checkResource(pod, "MODIFIED", s)
		},
		DeleteFunc: func(obj interface{}) {
			pod := obj.(*corev1.Pod)
			fmt.Printf("[%s] %s/%s deleted\n",
				time.Now().Format("15:04:05"),
				pod.Namespace, pod.Name)
		},
	})

	// Start informers
	factory.Start(ctx.Done())

	// Wait for cache sync
	if !cache.WaitForCacheSync(ctx.Done(), podInformer.HasSynced) {
		return fmt.Errorf("failed to sync caches")
	}

	fmt.Println("Caches synced. Watching for changes...")

	// Wait for context cancellation
	<-ctx.Done()
	return nil
}

func checkResource(pod *corev1.Pod, eventType string, s *scanner.Scanner) {
	// Check pod security
	findings := s.CheckPod(pod)

	if len(findings) == 0 {
		return
	}

	timestamp := time.Now().Format("15:04:05")

	for _, f := range findings {
		sevColor := getSeverityColor(f.Severity)
		fmt.Printf("[%s] %s [%s] %s/%s: %s [%.12s]\n",
			timestamp,
			color.YellowString(eventType),
			sevColor(f.Severity),
			pod.Namespace,
			pod.Name,
			f.Message,
			f.ID,
		)
	}
}
