package kuberneet

import future.keywords.if
import data.kuberneet.pod
import data.kuberneet.rbac

# Main entry point - combine all violations
violation contains pod_violation if {
    some pod_violation in pod.violation
    pod_violation
}

violation contains rbac_violation if {
    some rbac_violation in rbac.violation
    rbac_violation
}

# Metadata extraction
metadata := {
    "name": input.metadata.name,
    "namespace": object.get(input.metadata, "namespace", "cluster-wide"),
    "kind": input.kind,
    "uid": input.metadata.uid,
}

# Check if resource has violations
has_violations if {
    count(violation) > 0
}

# Risk scoring
risk_score := base_score + severity_score if {
    base_score := count(violation) * 10
    severity_score := sum([score |
        some v in violation
        score := severity_weight(v.severity)
    ])
}

severity_weight(severity) := 40 if severity == "CRITICAL"
severity_weight(severity) := 20 if severity == "HIGH"
severity_weight(severity) := 10 if severity == "MEDIUM"
severity_weight(severity) := 5 if severity == "LOW"
severity_weight(severity) := 0 if not severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
