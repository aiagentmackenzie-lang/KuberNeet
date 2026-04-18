package scanner

import (
	"context"
	"fmt"

	"github.com/raphael/kuberneet/pkg/finding"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// scanNetworkPolicies analyzes NetworkPolicy configurations
func (s *Scanner) scanNetworkPolicies(ctx context.Context) ([]finding.Finding, error) {
	var findings []finding.Finding

	namespaces := []string{s.namespace}
	if s.namespace == "" {
		nsList, err := s.clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, err
		}
		namespaces = []string{}
		for _, ns := range nsList.Items {
			namespaces = append(namespaces, ns.Name)
		}
	}

	for _, ns := range namespaces {
		policies, err := s.clientset.NetworkingV1().NetworkPolicies(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			// NetworkPolicy might not be available in this cluster
			continue
		}

		// Check for default-deny policy
		hasDefaultDeny := hasDefaultDenyPolicy(policies.Items)

		if !hasDefaultDeny {
			findings = append(findings, finding.Finding{
				ID:           "NET-001",
				Severity:     finding.High,
				Title:        "Missing default-deny NetworkPolicy",
				Message:      fmt.Sprintf("Namespace '%s' lacks default-deny NetworkPolicy", ns),
				Description:  "Without a default-deny policy, all pods in the namespace can communicate freely with each other and external resources",
				ResourceKind: "Namespace",
				ResourceName: ns,
				CWE:          "CWE-284",
				Remediation: fmt.Sprintf(`apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: %s
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress`, ns),
			})
		}

		// Check individual policies for issues
		for _, policy := range policies.Items {
			findings = append(findings, s.checkNetworkPolicy(&policy)...)
		}
	}

	return findings, nil
}

// checkNetworkPolicy analyzes a single NetworkPolicy
func (s *Scanner) checkNetworkPolicy(policy *networkingv1.NetworkPolicy) []finding.Finding {
	var findings []finding.Finding
	ns := policy.Namespace
	if ns == "" {
		ns = "default"
	}

	// Check for overly permissive ingress
	for _, rule := range policy.Spec.Ingress {
		// Check for 0.0.0.0/0 or empty namespaceSelector (allows all)
		for _, from := range rule.From {
			// IPBlock with 0.0.0.0/0
			if from.IPBlock != nil && from.IPBlock.CIDR == "0.0.0.0/0" {
				findings = append(findings, finding.Finding{
					ID:           "NET-002",
					Severity:     finding.Critical,
					Title:        "NetworkPolicy allows traffic from 0.0.0.0/0",
					Message:      fmt.Sprintf("NetworkPolicy '%s' allows ingress from any IP", policy.Name),
					Description:  "CIDR 0.0.0.0/0 allows traffic from any source on the internet",
					ResourceKind: "NetworkPolicy",
					ResourceName: policy.Name,
					Namespace:    ns,
					CWE:          "CWE-284",
				})
			}
		}
	}

	// Check for empty pod selector (applies to all pods) without explicit deny
	if len(policy.Spec.PodSelector.MatchLabels) == 0 && len(policy.Spec.PodSelector.MatchExpressions) == 0 {
		// This is fine if it's a default-deny, but risky if it allows traffic
		if len(policy.Spec.Ingress) > 0 || len(policy.Spec.Egress) > 0 {
			// Check if it's actually allowing traffic broadly
			for _, rule := range policy.Spec.Ingress {
				if len(rule.From) == 0 || isBroadAllow(rule) {
					findings = append(findings, finding.Finding{
						ID:           "NET-003",
						Severity:     finding.Medium,
						Title:        "Broad NetworkPolicy applies to all pods",
						Message:      fmt.Sprintf("NetworkPolicy '%s' applies to all pods with broad rules", policy.Name),
						Description:  "Empty podSelector with permissive rules applies to every pod in the namespace",
						ResourceKind: "NetworkPolicy",
						ResourceName: policy.Name,
						Namespace:    ns,
						CWE:          "CWE-284",
					})
				}
			}
		}
	}

	// Check for missing egress policies
	if len(policy.Spec.PolicyTypes) == 1 && policy.Spec.PolicyTypes[0] == networkingv1.PolicyTypeIngress {
		// Only ingress policy - egress is unrestricted
		findings = append(findings, finding.Finding{
			ID:           "NET-004",
			Severity:     finding.Medium,
			Title:        "Egress traffic unrestricted",
			Message:      fmt.Sprintf("NetworkPolicy '%s' only restricts ingress, egress is open", policy.Name),
			Description:  "Without egress policies, compromised pods can communicate with external C2 servers",
			ResourceKind: "NetworkPolicy",
			ResourceName: policy.Name,
			Namespace:    ns,
			CWE:          "CWE-284",
			Remediation: `  policyTypes:
  - Ingress
  - Egress
  egress:
  - to:
    - namespaceSelector:
        matchLabels:
          name: kube-system
    ports:
    - protocol: UDP
      port: 53`,
		})
	}

	return findings
}

// hasDefaultDenyPolicy checks if namespace has a default-deny policy
func hasDefaultDenyPolicy(policies []networkingv1.NetworkPolicy) bool {
	for _, policy := range policies {
		// Check for empty podSelector (matches all)
		if len(policy.Spec.PodSelector.MatchLabels) == 0 && len(policy.Spec.PodSelector.MatchExpressions) == 0 {
			// Check if it's a deny-all
			for _, policyType := range policy.Spec.PolicyTypes {
				if policyType == networkingv1.PolicyTypeIngress && len(policy.Spec.Ingress) == 0 {
					return true
				}
			}
		}
	}
	return false
}

// isBroadAllow checks if a rule allows broad access
func isBroadAllow(rule networkingv1.NetworkPolicyIngressRule) bool {
	// Empty From allows from everywhere
	if len(rule.From) == 0 {
		return true
	}

	// Check for namespaceSelector that allows all
	for _, from := range rule.From {
		if from.NamespaceSelector != nil {
			if len(from.NamespaceSelector.MatchLabels) == 0 && len(from.NamespaceSelector.MatchExpressions) == 0 {
				return true
			}
		}
	}

	return false
}
