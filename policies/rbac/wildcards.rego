package kuberneet.rbac

import future.keywords.if
import future.keywords.contains

# ClusterRole with wildcard verbs or resources
violation contains {
    "id": "RBAC-001",
    "severity": "HIGH",
    "title": "ClusterRole wildcard permissions",
    "description": "Wildcard permissions grant unrestricted access and violate least privilege",
    "cwe": "CWE-250",
    "mitre": "T1098",
    "message": sprintf("ClusterRole '%s' uses wildcard (*) permissions", [input.metadata.name]),
    "remediation": "Replace * with explicit verbs and resources"
} if {
    input.kind == "ClusterRole"
    some rule in input.rules
    rule_verbs_has_wildcard(rule)
}

violation contains {
    "id": "RBAC-001a",
    "severity": "CRITICAL",
    "title": "ClusterRole full wildcard",
    "description": "Wildcards on both verbs and resources grants full cluster access",
    "cwe": "CWE-250",
    "mitre": "T1098",
    "message": sprintf("ClusterRole '%s' grants wildcard (*) on verbs AND resources", [input.metadata.name]),
    "remediation": "Explicitly define required verbs and resources"
} if {
    input.kind == "ClusterRole"
    some rule in input.rules
    rule_verbs_has_wildcard(rule)
    rule_resources_has_wildcard(rule)
}

# Role with wildcard permissions
violation contains {
    "id": "RBAC-002",
    "severity": "HIGH",
    "title": "Role wildcard permissions",
    "description": "Wildcard permissions within namespace still grant excessive access",
    "cwe": "CWE-250",
    "message": sprintf("Role '%s' uses wildcard (*) permissions", [input.metadata.name]),
    "remediation": "Replace * with explicit verbs and resources"
} if {
    input.kind == "Role"
    some rule in input.rules
    rule_verbs_has_wildcard(rule)
}

# cluster-admin bound to default ServiceAccount
violation contains {
    "id": "RBAC-003",
    "severity": "CRITICAL",
    "title": "cluster-admin bound to default ServiceAccount",
    "description": "Binding cluster-admin to default SA allows any pod in namespace full cluster access",
    "cwe": "CWE-250",
    "mitre": "T1098",
    "message": sprintf("Cluster-admin bound to default SA in namespace '%s'", [subject.namespace]),
    "remediation": "Create dedicated ServiceAccount with minimal permissions"
} if {
    input.kind == "ClusterRoleBinding"
    input.roleRef.name == "cluster-admin"
    some subject in input.subjects
    subject.kind == "ServiceAccount"
    subject.name == "default"
}

# Dangerous secrets access
violation contains {
    "id": "RBAC-006",
    "severity": "HIGH",
    "title": "Broad secrets access",
    "description": "Access to all secrets enables credential theft from any namespace",
    "mitre": "T1552",
    "message": sprintf("Role '%s' grants access to secrets", [input.metadata.name]),
    "remediation": "Limit to specific secret names or use separate secret management"
} if {
    input.kind == "Role"
    some rule in input.rules
    "secrets" in rule.resources
    "*" in rule.verbs
}

# Helper functions
rule_verbs_has_wildcard(rule) if "*" in rule.verbs

rule_resources_has_wildcard(rule) if "*" in rule.resources

# Pod/exec permission (code execution)
violation contains {
    "id": "RBAC-007",
    "severity": "HIGH",
    "title": "Pod/exec permission granted",
    "description": "pods/exec permission allows arbitrary command execution in containers",
    "mitre": "T1609",
    "message": sprintf("Role '%s' grants pods/exec permission", [input.metadata.name]),
    "remediation": "Remove pods/exec and use read-only monitoring instead"
} if {
    input.kind == "Role"
    some rule in input.rules
    "pods/exec" in rule.resources
    "create" in rule.verbs
}
