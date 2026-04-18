package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/raphael/kuberneet/pkg/finding"
	"github.com/raphael/kuberneet/pkg/graph"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// GraphScanResult includes findings and attack paths
type GraphScanResult struct {
	Findings    []finding.Finding `json:"findings"`
	AttackPaths []graph.AttackPath `json:"attack_paths"`
	Graph       *graph.Graph       `json:"graph"`
}

// ScanWithGraph performs scanning and builds the attack graph
func (s *Scanner) ScanWithGraph(ctx context.Context) (*GraphScanResult, error) {
	// Get findings first
	findings, err := s.ScanCluster(ctx)
	if err != nil {
		return nil, err
	}

	// Build the graph
	builder := graph.NewBuilder()

	// Get all namespaces
	namespaces := []string{s.namespace}
	if s.namespace == "" {
		nsList, err := s.clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, fmt.Errorf("failed to list namespaces: %w", err)
		}
		namespaces = []string{}
		for _, ns := range nsList.Items {
			namespaces = append(namespaces, ns.Name)
		}
	}

	// Build nodes and edges for each namespace
	for _, ns := range namespaces {
		if err := s.buildNamespaceGraph(ctx, ns, builder); err != nil {
			continue
		}
	}

	g := builder.GetGraph()

	// Find attack paths
	pathFinder := graph.NewPathFinder(g)
	attackPaths := pathFinder.FindAttackPaths()

	return &GraphScanResult{
		Findings:    findings,
		AttackPaths: attackPaths,
		Graph:       g,
	}, nil
}

func (s *Scanner) buildNamespaceGraph(ctx context.Context, ns string, builder *graph.Builder) error {
	// Build services
	services, err := s.clientset.CoreV1().Services(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}
	for _, svc := range services.Items {
		builder.BuildService(svc.Name, svc.Namespace, svc.Spec.Selector, string(svc.Spec.Type))
	}

	// Build pods
	pods, err := s.clientset.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}
	for _, pod := range pods.Items {
		privileged := false
		for _, c := range pod.Spec.Containers {
			if c.SecurityContext != nil && c.SecurityContext.Privileged != nil && *c.SecurityContext.Privileged {
				privileged = true
				break
			}
		}

		saName := pod.Spec.ServiceAccountName
		if saName == "" {
			saName = "default"
		}

		builder.BuildPod(pod.Name, pod.Namespace, saName, pod.Spec.NodeName, pod.Labels, privileged)
	}

	// Build ServiceAccounts
	sas, err := s.clientset.CoreV1().ServiceAccounts(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}
	for _, sa := range sas.Items {
		sa := sa // Copy for pointer
		nodeID := graph.NodeID("serviceaccount", sa.Namespace, sa.Name)
		builder.GetGraph().AddNode(&graph.Node{
			ID:        nodeID,
			Type:      graph.NodeTypeServiceAccount,
			Name:      sa.Name,
			Namespace: sa.Namespace,
		})
	}

	// Build Roles
	roles, err := s.clientset.RbacV1().Roles(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}
	for _, role := range roles.Items {
		rules := []map[string]interface{}{}
		for _, rule := range role.Rules {
			rules = append(rules, map[string]interface{}{
				"apiGroups": rule.APIGroups,
				"resources": rule.Resources,
				"verbs":     rule.Verbs,
			})
		}
		builder.BuildRole(role.Name, role.Namespace, false, rules)
	}

	// Build RoleBindings
	bindings, err := s.clientset.RbacV1().RoleBindings(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}
	for _, binding := range bindings.Items {
		subjects := []map[string]interface{}{}
		for _, subj := range binding.Subjects {
			subjects = append(subjects, map[string]interface{}{
				"kind":      subj.Kind,
				"name":      subj.Name,
				"namespace": subj.Namespace,
			})
		}
		builder.BuildBinding(binding.Name, binding.Namespace, false, binding.RoleRef.Kind, binding.RoleRef.Name, subjects)
	}

	return nil
}

// ExportGraph saves the graph as JSON
func (s *Scanner) ExportGraph(result *GraphScanResult, filepath string) error {
	data, err := json.MarshalIndent(result.Graph, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal graph: %w", err)
	}
	return os.WriteFile(filepath, data, 0644)
}

// GenerateAttackPathReport creates a detailed text report
func (s *Scanner) GenerateAttackPathReport(result *GraphScanResult) string {
	if len(result.AttackPaths) == 0 {
		return "No attack paths identified."
	}

	var report string
	report += fmt.Sprintf("Identified %d attack paths:\n\n", len(result.AttackPaths))

	for i, path := range result.AttackPaths {
		report += fmt.Sprintf("═══ Attack Path %d ═══\n", i+1)
		report += fmt.Sprintf("Technique: %s\n", path.Technique)
		report += fmt.Sprintf("Tactic:    %s\n", path.Tactic)
		report += fmt.Sprintf("Risk Score: %.0f\n", path.RiskScore)
		report += fmt.Sprintf("Description: %s\n", path.Description)
		report += "Chain: "
		for j, node := range path.Path {
			if j > 0 {
				report += " → "
			}
			report += fmt.Sprintf("%s/%s", node.Type, node.Name)
		}
		report += "\n\n"
	}

	return report
}
