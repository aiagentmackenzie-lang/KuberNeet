package scanner

import (
	"context"
	"fmt"
	"strings"

	"github.com/raphael/kuberneet/pkg/finding"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// capInfo maps dangerous capabilities to severity, description, and MITRE technique.
var capInfo = map[string]struct {
	severity string
	desc    string
	mitre   string
}{
	"SYS_ADMIN":       {finding.Critical, "CAP_SYS_ADMIN allows mount, namespace manipulation, and privilege escalation. Equivalent to root in many configurations.", "T1068"},
	"SYS_PTRACE":      {finding.High, "CAP_SYS_PTRACE allows process inspection and memory manipulation of other processes, enabling credential theft and injection.", "T1056"},
	"SYS_MODULE":      {finding.Critical, "CAP_SYS_MODULE allows loading kernel modules, which can compromise the entire node.", "T1547"},
	"NET_ADMIN":       {finding.High, "CAP_NET_ADMIN allows network configuration changes, enabling traffic interception and DNS spoofing.", "T1557"},
	"SYS_RAWIO":       {finding.Critical, "CAP_SYS_RAWIO allows direct hardware access, bypassing kernel protections.", "T1068"},
	"SYS_BOOT":        {finding.High, "CAP_SYS_BOOT allows rebooting the node, enabling denial of service.", "T1529"},
	"SYS_TIME":        {finding.Medium, "CAP_SYS_TIME allows changing system time, which can break TLS certificates and audit logs.", ""},
	"DAC_READ_SEARCH": {finding.Medium, "CAP_DAC_READ_SEARCH bypasses file permission checks for reading and searching directories.", ""},
	"LINUX_IMMUTABLE":  {finding.Medium, "CAP_LINUX_IMMUTABLE allows setting file immutability flags, which can prevent forensic analysis.", ""},
}

// scanPods scans all pods for security issues
func (s *Scanner) scanPods(ctx context.Context) ([]finding.Finding, error) {
	var findings []finding.Finding

	pods, err := s.clientset.CoreV1().Pods(s.namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	for _, pod := range pods.Items {
		findings = append(findings, s.checkPodSecurity(&pod)...)
	}

	return findings, nil
}

// checkPodSecurity runs all security checks on a single pod
func (s *Scanner) checkPodSecurity(pod *corev1.Pod) []finding.Finding {
	var findings []finding.Finding

	findings = append(findings, s.checkPrivilegedContainers(pod)...)
	findings = append(findings, s.checkHostNamespaces(pod)...)
	findings = append(findings, s.checkHostPathMounts(pod)...)
	findings = append(findings, s.checkSeccompProfile(pod)...)
	findings = append(findings, s.checkCapabilities(pod)...)
	findings = append(findings, s.checkSecurityContext(pod)...)
	findings = append(findings, s.checkServiceAccount(pod)...)

	return findings
}

// checkPrivilegedContainers - POD-001
func (s *Scanner) checkPrivilegedContainers(pod *corev1.Pod) []finding.Finding {
	var findings []finding.Finding
	ns := pod.Namespace
	if ns == "" {
		ns = "default"
	}

	for _, c := range pod.Spec.Containers {
		if c.SecurityContext != nil && c.SecurityContext.Privileged != nil && *c.SecurityContext.Privileged {
			remediation := fmt.Sprintf(`apiVersion: v1
kind: Pod
metadata:
  name: %s
  namespace: %s
spec:
  containers:
  - name: %s
    securityContext:
      privileged: false
      allowPrivilegeEscalation: false
      capabilities:
        drop:
        - ALL`, pod.Name, ns, c.Name)

			if !s.withRemedy {
				remediation = ""
			}

			findings = append(findings, finding.Finding{
				ID:           "POD-001",
				Severity:     finding.Critical,
				Message:      fmt.Sprintf("Privileged container '%s' can escape to host via nsenter", c.Name),
				Description:  "Privileged containers have full access to host resources and can escape to the host system using nsenter or by accessing /proc/1/root",
				ResourceKind: "Pod",
				ResourceName: pod.Name,
				Namespace:    ns,
				CWE:          "CWE-250",
				MITRE:        "T1611",
				Remediation:  remediation,
			})
		}
	}

	for _, c := range pod.Spec.InitContainers {
		if c.SecurityContext != nil && c.SecurityContext.Privileged != nil && *c.SecurityContext.Privileged {
			findings = append(findings, finding.Finding{
				ID:           "POD-001",
				Severity:     finding.Critical,
				Message:      fmt.Sprintf("Privileged init container '%s' found", c.Name),
				Description:  "Privileged init containers have full access to host resources",
				ResourceKind: "Pod",
				ResourceName: pod.Name,
				Namespace:    ns,
				CWE:          "CWE-250",
				MITRE:        "T1611",
			})
		}
	}

	return findings
}

// checkHostNamespaces - POD-002, POD-003, POD-004
func (s *Scanner) checkHostNamespaces(pod *corev1.Pod) []finding.Finding {
	var findings []finding.Finding
	ns := pod.Namespace
	if ns == "" {
		ns = "default"
	}

	if pod.Spec.HostPID {
		findings = append(findings, finding.Finding{
			ID:           "POD-002",
			Severity:     finding.High,
			Message:      "hostPID=true shares host's PID namespace",
			Description:  "hostPID allows the container to access host processes via /proc, enabling process injection and secret theft",
			ResourceKind: "Pod",
			ResourceName: pod.Name,
			Namespace:    ns,
			CWE:          "CWE-284",
			MITRE:        "T1055",
		})
	}

	if pod.Spec.HostNetwork {
		findings = append(findings, finding.Finding{
			ID:           "POD-003",
			Severity:     finding.High,
			Message:      "hostNetwork=true shares host's network namespace",
			Description:  "hostNetwork allows access to cloud metadata endpoints (169.254.169.254) and host network interfaces",
			ResourceKind: "Pod",
			ResourceName: pod.Name,
			Namespace:    ns,
			CWE:          "CWE-284",
			MITRE:        "T1550.005",
		})
	}

	if pod.Spec.HostIPC {
		findings = append(findings, finding.Finding{
			ID:           "POD-004",
			Severity:     finding.High,
			Message:      "hostIPC=true shares host's IPC namespace",
			Description:  "hostIPC allows shared memory access with host processes",
			ResourceKind: "Pod",
			ResourceName: pod.Name,
			Namespace:    ns,
			CWE:          "CWE-284",
		})
	}

	return findings
}

// checkHostPathMounts - POD-005
func (s *Scanner) checkHostPathMounts(pod *corev1.Pod) []finding.Finding {
	var findings []finding.Finding
	ns := pod.Namespace
	if ns == "" {
		ns = "default"
	}

	dangerousPaths := []string{
		"/proc",
		"/sys",
		"/var/run/docker.sock",
		"/var/run/crio/crio.sock",
		"/var/run/containerd/containerd.sock",
		"/etc/kubernetes",
		"/root/.kube",
		"/var/lib/kubelet",
	}

	for _, vol := range pod.Spec.Volumes {
		if vol.HostPath == nil {
			continue
		}

		for _, dangerous := range dangerousPaths {
			if strings.HasPrefix(vol.HostPath.Path, dangerous) {
				findings = append(findings, finding.Finding{
					ID:           "POD-005",
					Severity:     finding.Critical,
					Message:      fmt.Sprintf("Dangerous hostPath mount: %s", vol.HostPath.Path),
					Description:  fmt.Sprintf("Mounting %s can lead to container escape or access to sensitive host data", vol.HostPath.Path),
					ResourceKind: "Pod",
					ResourceName: pod.Name,
					Namespace:    ns,
					CWE:          "CWE-552",
					MITRE:        "T1611",
				})
			}
		}
	}

	return findings
}

// checkSeccompProfile - POD-006
func (s *Scanner) checkSeccompProfile(pod *corev1.Pod) []finding.Finding {
	var findings []finding.Finding
	ns := pod.Namespace
	if ns == "" {
		ns = "default"
	}

	// Check pod-level seccomp
	if pod.Spec.SecurityContext == nil || pod.Spec.SecurityContext.SeccompProfile == nil {
		// Check container-level seccomp
		hasProfile := false
		for _, c := range pod.Spec.Containers {
			if c.SecurityContext != nil && c.SecurityContext.SeccompProfile != nil {
				hasProfile = true
				break
			}
		}

		if !hasProfile {
			findings = append(findings, finding.Finding{
				ID:           "POD-006",
				Severity:     finding.Medium,
				Message:      "Missing seccomp profile",
				Description:  "Seccomp profiles restrict syscalls available to containers, reducing attack surface for privilege escalation",
				ResourceKind: "Pod",
				ResourceName: pod.Name,
				Namespace:    ns,
				CWE:          "CWE-284",
				Remediation: `spec:
  securityContext:
    seccompProfile:
      type: RuntimeDefault`,
			})
		}
	}

	return findings
}

// checkCapabilities - POD-007, POD-008
func (s *Scanner) checkCapabilities(pod *corev1.Pod) []finding.Finding {
	var findings []finding.Finding
	ns := pod.Namespace
	if ns == "" {
		ns = "default"
	}

	for _, c := range pod.Spec.Containers {
		if c.SecurityContext == nil || c.SecurityContext.Capabilities == nil {
			continue
		}

		// POD-007: Check for dangerous capabilities
		for _, cap := range c.SecurityContext.Capabilities.Add {
			info, known := capInfo[strings.ToUpper(string(cap))]
			if !known {
				continue
			}
			findings = append(findings, finding.Finding{
				ID:           "POD-007",
				Severity:     info.severity,
				Message:      fmt.Sprintf("Dangerous capability '%s' added to container '%s'", cap, c.Name),
				Description:  info.desc,
				ResourceKind: "Pod",
				ResourceName: pod.Name,
				Namespace:    ns,
				CWE:          "CWE-250",
				MITRE:        info.mitre,
			})
		}

		// POD-008: Check for DROP ALL
		allDropped := false
		for _, dropCap := range c.SecurityContext.Capabilities.Drop {
			if strings.EqualFold(string(dropCap), "ALL") {
				allDropped = true
				break
			}
		}

		if !allDropped {
			findings = append(findings, finding.Finding{
				ID:           "POD-008",
				Severity:     finding.High,
				Message:      fmt.Sprintf("Container '%s' missing 'drop: ALL' capabilities", c.Name),
				Description:  "All capabilities should be dropped by default and only specific required capabilities added",
				ResourceKind: "Pod",
				ResourceName: pod.Name,
				Namespace:    ns,
				Remediation: fmt.Sprintf(`
containers:
- name: %s
  securityContext:
    capabilities:
      drop:
      - ALL`, c.Name),
			})
		}
	}

	return findings
}

// checkSecurityContext - POD-009, POD-010, POD-011
func (s *Scanner) checkSecurityContext(pod *corev1.Pod) []finding.Finding {
	var findings []finding.Finding
	ns := pod.Namespace
	if ns == "" {
		ns = "default"
	}

	for _, c := range pod.Spec.Containers {
		if c.SecurityContext == nil {
			findings = append(findings, finding.Finding{
				ID:           "POD-009",
				Severity:     finding.Medium,
				Message:      fmt.Sprintf("Container '%s' has no securityContext", c.Name),
				Description:  "SecurityContext should define runAsNonRoot, runAsUser, and capability settings",
				ResourceKind: "Pod",
				ResourceName: pod.Name,
				Namespace:    ns,
			})
			continue
		}

		// POD-010: Check allowPrivilegeEscalation
		if c.SecurityContext.AllowPrivilegeEscalation == nil || *c.SecurityContext.AllowPrivilegeEscalation {
			findings = append(findings, finding.Finding{
				ID:           "POD-010",
				Severity:     finding.High,
				Message:      fmt.Sprintf("Container '%s' allows privilege escalation", c.Name),
				Description:  "allowPrivilegeEscalation: true permits processes to gain more privileges than their parent",
				ResourceKind: "Pod",
				ResourceName: pod.Name,
				Namespace:    ns,
				Remediation: fmt.Sprintf(`
containers:
- name: %s
  securityContext:
    allowPrivilegeEscalation: false`, c.Name),
			})
		}

		// POD-011: Check runAsRoot
		if c.SecurityContext.RunAsNonRoot == nil || !*c.SecurityContext.RunAsNonRoot {
			if c.SecurityContext.RunAsUser == nil || *c.SecurityContext.RunAsUser == 0 {
				findings = append(findings, finding.Finding{
					ID:           "POD-011",
					Severity:     finding.Medium,
					Message:      fmt.Sprintf("Container '%s' may run as root", c.Name),
					Description:  "Containers should run as non-root user to limit damage from compromise",
					ResourceKind: "Pod",
					ResourceName: pod.Name,
					Namespace:    ns,
					Remediation: fmt.Sprintf(`
containers:
- name: %s
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000`, c.Name),
				})
			}
		}
	}

	return findings
}

// checkServiceAccount - POD-012, POD-013
func (s *Scanner) checkServiceAccount(pod *corev1.Pod) []finding.Finding {
	var findings []finding.Finding
	ns := pod.Namespace
	if ns == "" {
		ns = "default"
	}

	// POD-012: Check default serviceaccount
	if pod.Spec.ServiceAccountName == "default" || pod.Spec.ServiceAccountName == "" {
		findings = append(findings, finding.Finding{
			ID:           "POD-012",
			Severity:     finding.Medium,
			Message:      "Pod uses default ServiceAccount",
			Description:  "Default ServiceAccount may have broader permissions than necessary. Use dedicated ServiceAccounts per workload.",
			ResourceKind: "Pod",
			ResourceName: pod.Name,
			Namespace:    ns,
		})
	}

	// POD-013: Check automount
	if pod.Spec.AutomountServiceAccountToken == nil || *pod.Spec.AutomountServiceAccountToken {
		findings = append(findings, finding.Finding{
			ID:           "POD-013",
			Severity:     finding.High,
			Message:      "Token automounting enabled",
			Description:  "Service account tokens can be stolen if container is compromised, allowing API server access",
			ResourceKind: "Pod",
			ResourceName: pod.Name,
			Namespace:    ns,
			MITRE:        "T1528",
		})
	}

	return findings
}