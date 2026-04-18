package kuberneet.pod

import future.keywords.if
import future.keywords.contains

# Privileged container escape
violation contains {
    "id": "POD-001",
    "severity": "CRITICAL", 
    "title": "Privileged container detected",
    "description": "Privileged containers can escape to host via nsenter or by accessing /proc/1/root",
    "cwe": "CWE-250",
    "mitre": "T1611",
    "message": sprintf("Privileged container '%s' can escape to host via nsenter", [container.name]),
    "remediation": "Remove privileged: true, use capabilities instead"
} if {
    some container in input.spec.containers
    container.securityContext.privileged
}

violation contains {
    "id": "POD-001",
    "severity": "CRITICAL",
    "title": "Privileged init container detected", 
    "description": "Privileged init containers can escape to host during startup",
    "cwe": "CWE-250",
    "mitre": "T1611",
    "message": sprintf("Privileged init container '%s' found", [container.name]),
    "remediation": "Remove privileged: true from init containers"
} if {
    some container in input.spec.initContainers
    container.securityContext.privileged
}

# hostPID namespace abuse
violation contains {
    "id": "POD-002",
    "severity": "HIGH",
    "title": "hostPID namespace shared",
    "description": "hostPID allows container to access host processes via /proc, enabling process injection",
    "cwe": "CWE-284",
    "mitre": "T1055",
    "message": "hostPID=true shares host's PID namespace",
    "remediation": "Use hostPID: false or dedicated monitoring namespace"
} if {
    input.spec.hostPID
}

# hostNetwork + metadata endpoint
violation contains {
    "id": "POD-003",
    "severity": "HIGH",
    "title": "hostNetwork namespace shared",
    "description": "hostNetwork allows access to cloud metadata (169.254.169.254) and host network interfaces",
    "cwe": "CWE-284", 
    "mitre": "T1550.005",
    "message": "hostNetwork=true shares host's network namespace",
    "remediation": "Use NetworkPolicy to block 169.254.169.254 + Workload Identity"
} if {
    input.spec.hostNetwork
}

# hostIPC namespace
violation contains {
    "id": "POD-004", 
    "severity": "HIGH",
    "title": "hostIPC namespace shared",
    "description": "hostIPC allows shared memory access with host processes",
    "cwe": "CWE-284",
    "message": "hostIPC=true shares host's IPC namespace",
    "remediation": "Remove hostIPC requirement if not absolutely necessary"
} if {
    input.spec.hostIPC
}

# Dangerous hostPath mounts
dangerous_paths := ["/proc", "/sys", "/var/run/docker.sock", "/var/run/crio/crio.sock", "/etc/kubernetes", "/root/.kube"]

violation contains {
    "id": "POD-005",
    "severity": "CRITICAL",
    "title": "Dangerous hostPath mount",
    "description": sprintf("Mounting %s can lead to container escape or data access", [volume.hostPath.path]),
    "cwe": "CWE-552",
    "mitre": "T1611",
    "message": sprintf("Dangerous hostPath mount: %s", [volume.hostPath.path]),
    "remediation": "Remove mount or use readOnly: true with strict validation"
} if {
    some volume in input.spec.volumes
    volume.hostPath
    some dangerous in dangerous_paths
    startswith(volume.hostPath.path, dangerous)
}

# SYS_ADMIN capability
violation contains {
    "id": "POD-007",
    "severity": "CRITICAL",
    "title": "Dangerous capability SYS_ADMIN",
    "description": "CAP_SYS_ADMIN allows mount, namespace manipulation, and privilege escalation",
    "cwe": "CWE-250",
    "mitre": "T1068",
    "message": sprintf("Dangerous capability 'SYS_ADMIN' added to container '%s'", [container.name]),
    "remediation": "Drop ALL capabilities and add only required ones"
} if {
    some container in input.spec.containers
    some cap in container.securityContext.capabilities.add
    upper(cap) == "SYS_ADMIN"
}

# allowPrivilegeEscalation
violation contains {
    "id": "POD-010",
    "severity": "HIGH",
    "title": "Privilege escalation allowed",
    "description": "allowPrivilegeEscalation: true permits processes to gain more privileges",
    "cwe": "CWE-250",
    "message": sprintf("Container '%s' allows privilege escalation", [container.name]),
    "remediation": "Set allowPrivilegeEscalation: false"
} if {
    some container in input.spec.containers
    not container.securityContext.allowPrivilegeEscalation == false
}

# automountServiceAccountToken
violation contains {
    "id": "POD-013",
    "severity": "HIGH",
    "title": "Service account token automounting",
    "description": "Service account tokens can be stolen if container compromised, allowing API access",
    "mitre": "T1528",
    "message": "Token automounting enabled",
    "remediation": "Set automountServiceAccountToken: false"
} if {
    not input.spec.automountServiceAccountToken == false
}
