package scanner

import (
	"context"
	"fmt"
	"strings"

	"github.com/raphael/kuberneet/pkg/finding"
	appsv1 "k8s.io/api/apps/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// scanDeployments scans all deployments for security issues
func (s *Scanner) scanDeployments(ctx context.Context) ([]finding.Finding, error) {
	var findings []finding.Finding

	deployments, err := s.clientset.AppsV1().Deployments(s.namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	for _, deploy := range deployments.Items {
		findings = append(findings, s.checkDeploymentSecurity(&deploy)...)
	}

	return findings, nil
}

func (s *Scanner) checkDeploymentSecurity(deploy *appsv1.Deployment) []finding.Finding {
	var findings []finding.Finding
	ns := deploy.Namespace
	if ns == "" {
		ns = "default"
	}

	// Use the pod spec from template
	spec := deploy.Spec.Template.Spec

	// Check privileged containers
	for _, c := range spec.Containers {
		if c.SecurityContext != nil && c.SecurityContext.Privileged != nil && *c.SecurityContext.Privileged {
			findings = append(findings, finding.Finding{
				ID:           "DEP-001",
				Severity:     finding.Critical,
				Message:      fmt.Sprintf("Privileged container '%s' in deployment", c.Name),
				Description:  "Privileged containers can escape to host and compromise the entire node",
				ResourceKind: "Deployment",
				ResourceName: deploy.Name,
				Namespace:    ns,
				CWE:          "CWE-250",
				MITRE:        "T1611",
			})
		}
	}

	// Check host namespaces
	if spec.HostPID || spec.HostIPC || spec.HostNetwork {
		findings = append(findings, finding.Finding{
			ID:           "DEP-002",
			Severity:     finding.High,
			Message:      "Deployment uses host namespaces",
			Description:  "Host namespace sharing breaks container isolation",
			ResourceKind: "Deployment",
			ResourceName: deploy.Name,
			Namespace:    ns,
		})
	}

	// Check security context
	for _, c := range spec.Containers {
		if c.SecurityContext == nil {
			findings = append(findings, finding.Finding{
				ID:           "DEP-003",
				Severity:     finding.Medium,
				Message:      fmt.Sprintf("Container '%s' lacks securityContext", c.Name),
				Description:  "SecurityContext should be defined for all containers",
				ResourceKind: "Deployment",
				ResourceName: deploy.Name,
				Namespace:    ns,
			})
		}
	}

	return findings
}

// scanRBAC scans RBAC resources for security issues
func (s *Scanner) scanRBAC(ctx context.Context) ([]finding.Finding, error) {
	var findings []finding.Finding

	// Scan ClusterRoles
	clusterRoles, err := s.clientset.RbacV1().ClusterRoles().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	for _, cr := range clusterRoles.Items {
		findings = append(findings, s.checkClusterRole(&cr)...)
	}

	// Scan Roles
	namespaces := []string{s.namespace}
	if s.namespace == "" {
		nsList, err := s.clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, err
		}
		for _, ns := range nsList.Items {
			namespaces = append(namespaces, ns.Name)
		}
	}

	for _, ns := range namespaces {
		roles, err := s.clientset.RbacV1().Roles(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}
		for _, role := range roles.Items {
			findings = append(findings, s.checkRole(&role, ns)...)
		}
	}

	// Scan ClusterRoleBindings
	crbs, err := s.clientset.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	for _, crb := range crbs.Items {
		findings = append(findings, s.checkClusterRoleBinding(&crb)...)
	}

	// Scan RoleBindings
	for _, ns := range namespaces {
		rbs, err := s.clientset.RbacV1().RoleBindings(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}
		for _, rb := range rbs.Items {
			findings = append(findings, s.checkRoleBinding(&rb, ns)...)
		}
	}

	return findings, nil
}

func (s *Scanner) checkClusterRole(cr *rbacv1.ClusterRole) []finding.Finding {
	var findings []finding.Finding

	hasWildcard := false
	for _, rule := range cr.Rules {
		for _, verb := range rule.Verbs {
			if verb == "*" {
				hasWildcard = true
			}
		}
		for _, resource := range rule.Resources {
			if resource == "*" {
				hasWildcard = true
			}
		}
	}

	if hasWildcard {
		findings = append(findings, finding.Finding{
			ID:           "RBAC-001",
			Severity:     finding.High,
			Message:      fmt.Sprintf("ClusterRole '%s' uses wildcard (*) permissions", cr.Name),
			Description:  "Wildcard permissions grant unrestricted access and violate principle of least privilege",
			ResourceKind: "ClusterRole",
			ResourceName: cr.Name,
			CWE:          "CWE-250",
			MITRE:        "T1098",
		})
	}

	return findings
}

func (s *Scanner) checkRole(role *rbacv1.Role, ns string) []finding.Finding {
	var findings []finding.Finding

	hasWildcard := false
	for _, rule := range role.Rules {
		for _, verb := range rule.Verbs {
			if verb == "*" {
				hasWildcard = true
			}
		}
		for _, resource := range rule.Resources {
			if resource == "*" {
				hasWildcard = true
			}
		}
	}

	if hasWildcard {
		findings = append(findings, finding.Finding{
			ID:           "RBAC-002",
			Severity:     finding.High,
			Message:      fmt.Sprintf("Role '%s' in '%s' uses wildcard (*) permissions", role.Name, ns),
			Description:  "Wildcard permissions grant unrestricted access within namespace",
			ResourceKind: "Role",
			ResourceName: role.Name,
			Namespace:    ns,
		})
	}

	return findings
}

func (s *Scanner) checkClusterRoleBinding(crb *rbacv1.ClusterRoleBinding) []finding.Finding {
	var findings []finding.Finding

	isClusterAdmin := false
	if crb.RoleRef.Name == "cluster-admin" {
		isClusterAdmin = true
	}

	if !isClusterAdmin {
		return findings
	}

	for _, subject := range crb.Subjects {
		if subject.Kind == "ServiceAccount" && subject.Name == "default" {
			findings = append(findings, finding.Finding{
				ID:           "RBAC-003",
				Severity:     finding.Critical,
				Message:      fmt.Sprintf("Cluster-admin bound to default SA: %s/namespace %s", subject.Name, subject.Namespace),
				Description:  "Binding cluster-admin to default ServiceAccount allows any pod in namespace full cluster access",
				ResourceKind: "ClusterRoleBinding",
				ResourceName: crb.Name,
				CWE:          "CWE-250",
				MITRE:        "T1098",
			})
		}

		if subject.Kind == "ServiceAccount" && strings.Contains(strings.ToLower(crb.Name), "system") {
			findings = append(findings, finding.Finding{
				ID:           "RBAC-004",
				Severity:     finding.Medium,
				Message:      fmt.Sprintf("System ClusterRoleBinding found: %s", crb.Name),
				Description:  "Review system bindings for excessive permissions",
				ResourceKind: "ClusterRoleBinding",
				ResourceName: crb.Name,
			})
		}
	}

	return findings
}

func (s *Scanner) checkRoleBinding(rb *rbacv1.RoleBinding, ns string) []finding.Finding {
	var findings []finding.Finding

	for _, subject := range rb.Subjects {
		if subject.Kind == "ServiceAccount" && subject.Name == "default" {
			findings = append(findings, finding.Finding{
				ID:           "RBAC-005",
				Severity:     finding.Medium,
				Message:      fmt.Sprintf("Role '%s' bound to default SA in '%s'", rb.RoleRef.Name, ns),
				Description:  "Default ServiceAccount should not have custom role bindings",
				ResourceKind: "RoleBinding",
				ResourceName: rb.Name,
				Namespace:    ns,
			})
		}
	}

	return findings
}
