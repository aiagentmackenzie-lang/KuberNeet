# KuberNeet 🔍

A Kubernetes security scanner with educational DNA. Explains WHY something is insecure, maps findings to attack paths, and generates exact remediation YAML.

```
██╗  ██╗██╗   ██╗██████╗ ███████╗██████╗ ███╗   ██╗███████╗███████╗████████╗
██║ ██╔╝██║   ██║██╔══██╗██╔════╝██╔══██╗████╗  ██║██╔════╝██╔════╝╚══██╔══╝
█████╔╝ ██║   ██║██████╔╝█████╗  ██████╔╝██╔██╗ ██║█████╗  █████╗     ██║   
██╔═██╗ ██║   ██║██╔══██╗██╔══╝  ██╔══██╗██║╚██╗██║██╔══╝  ██╔══╝     ██║   
██║  ██╗╚██████╔╝██████╔╝███████╗██║  ██║██║ ╚████║███████╗███████╗   ██║   
╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝   ╚═╝   
```

## Why KuberNeet?

| Tool | Philosophy | Output |
|------|-----------|--------|
| Kubescape | Compliance/Enterprise | Risk scores (0-100) |
| kube-bench | Checklist/Verification | Pass/Fail |
| **KuberNeet** | **Education + Action** | **Attack paths + remediation** |

## Quick Start

```bash
# Clone and build
git clone https://github.com/raphael/kuberneet.git
cd kuberneet
make build

# Or with go directly
go build -o bin/kuberneet ./cmd/kuberneet

# Scan entire cluster
./bin/kuberneet scan

# Scan specific namespace
./bin/kuberneet scan --namespace production

# Scan local manifest (offline)
./bin/kuberneet scan --manifest deployment.yaml

# JSON output for CI/CD
./bin/kuberneet scan --output json

# SARIF output for GitHub Code Scanning
./bin/kuberneet scan --output sarif --output-file results.sarif

# Include remediation YAML in output
./bin/kuberneet scan --remediate

# Include OPA/Rego policy evaluation
./bin/kuberneet scan --opa

# Show only critical findings
./bin/kuberneet scan --severity CRITICAL

# Build attack graph
./bin/kuberneet graph

# Export graph as JSON
./bin/kuberneet graph --output kuberneet-graph.json

# Real-time watch mode
./bin/kuberneet watch

# Generate HTML report
./bin/kuberneet report --html --output security-report.html

# Multi-cluster scan
./bin/kuberneet multi

# Run admission webhook
./bin/kuberneet webhook --cert server.crt --key server.key

# Auto-mutation mode
./bin/kuberneet webhook --cert server.crt --key server.key --mutate
```

## Security Checks

### Container Security (13 checks)

| ID | Check | Severity | CWE | MITRE |
|----|-------|----------|-----|-------|
| POD-001 | Privileged containers | CRITICAL | CWE-250 | T1611 |
| POD-002 | hostPID namespace | HIGH | CWE-284 | T1055 |
| POD-003 | hostNetwork namespace | HIGH | CWE-284 | T1550.005 |
| POD-004 | hostIPC namespace | HIGH | CWE-284 | — |
| POD-005 | Dangerous hostPath mounts | CRITICAL | CWE-552 | T1611 |
| POD-006 | Missing seccomp profile | MEDIUM | CWE-284 | — |
| POD-007 | Dangerous capabilities | CRITICAL/HIGH/MEDIUM | CWE-250 | T1068, T1056, T1547 |
| POD-008 | Missing DROP ALL capabilities | HIGH | CWE-250 | — |
| POD-009 | No securityContext | MEDIUM | CWE-284 | — |
| POD-010 | allowPrivilegeEscalation | HIGH | CWE-250 | — |
| POD-011 | runAsRoot allowed | MEDIUM | CWE-250 | — |
| POD-012 | Default ServiceAccount | MEDIUM | CWE-284 | — |
| POD-013 | Token automount enabled | HIGH | CWE-284 | T1528 |

POD-007 detects all 9 dangerous capabilities with differentiated severity:
- **CRITICAL**: SYS_ADMIN, SYS_MODULE, SYS_RAWIO
- **HIGH**: SYS_PTRACE, NET_ADMIN, SYS_BOOT
- **MEDIUM**: SYS_TIME, DAC_READ_SEARCH, LINUX_IMMUTABLE

### RBAC Security (5 checks)

| ID | Check | Severity | CWE | MITRE |
|----|-------|----------|-----|-------|
| RBAC-001 | ClusterRole wildcard | HIGH | CWE-250 | T1098 |
| RBAC-002 | Role wildcard | HIGH | CWE-250 | — |
| RBAC-003 | cluster-admin → default SA | CRITICAL | CWE-250 | T1098 |
| RBAC-004 | System ClusterRoleBinding | MEDIUM | CWE-284 | — |
| RBAC-005 | Role bound to default SA | MEDIUM | CWE-284 | — |

### Deployment Security (3 checks)

| ID | Check | Severity | CWE | MITRE |
|----|-------|----------|-----|-------|
| DEP-001 | Privileged container in deployment | CRITICAL | CWE-250 | T1611 |
| DEP-002 | Host namespaces in deployment | HIGH | CWE-284 | — |
| DEP-003 | Missing securityContext | MEDIUM | CWE-284 | — |

### NetworkPolicy Security (4 checks)

| ID | Check | Severity | CWE |
|----|-------|----------|-----|
| NET-001 | Missing default-deny | HIGH | CWE-284 |
| NET-002 | Allows 0.0.0.0/0 | CRITICAL | CWE-284 |
| NET-003 | Broad rules on all pods | MEDIUM | CWE-284 |
| NET-004 | Unrestricted egress | MEDIUM | CWE-284 |

### CIS Benchmarks (8 checks)

| ID | Check | Severity |
|----|-------|----------|
| CIS-1.2.1 | Anonymous auth disabled | CRITICAL |
| CIS-1.2.6 | RBAC authorization | CRITICAL |
| CIS-1.2.16 | Audit log path | HIGH |
| CIS-1.2.25 | Request timeout | MEDIUM |
| CIS-4.2.1 | Kubelet anonymous auth | CRITICAL |
| CIS-4.2.2 | Kubelet authorization mode | CRITICAL |
| CIS-4.2.4 | Kubelet read-only port | HIGH |
| CIS-4.2.14 | Kubelet TLS ciphers | MEDIUM |

> **Note:** CIS-1.2.16, 1.2.25, 4.2.2, 4.2.4, and 4.2.14 require node-level access to verify and report "manual verification required" when cluster access is insufficient. CIS-1.2.1 makes a live anonymous API request to verify configuration.

### OPA/Rego Policies (7 additional checks)

When using `--opa`, embedded Rego policies add these checks on top of the Go scanner:

| ID | Check | Severity | Source |
|----|-------|----------|--------|
| POD-001 | Privileged container (Rego) | CRITICAL | escapes.rego |
| POD-002 | hostPID (Rego) | HIGH | escapes.rego |
| POD-003 | hostNetwork (Rego) | HIGH | escapes.rego |
| POD-004 | hostIPC (Rego) | HIGH | escapes.rego |
| POD-005 | Dangerous hostPath (Rego) | CRITICAL | escapes.rego |
| POD-007 | SYS_ADMIN capability (Rego) | CRITICAL | escapes.rego |
| POD-010 | allowPrivilegeEscalation (Rego) | HIGH | escapes.rego |
| POD-013 | Token automount (Rego) | HIGH | escapes.rego |
| RBAC-001 | ClusterRole wildcard (Rego) | HIGH | wildcards.rego |
| RBAC-001a | ClusterRole full wildcard | CRITICAL | wildcards.rego |
| RBAC-002 | Role wildcard (Rego) | HIGH | wildcards.rego |
| RBAC-003 | cluster-admin → default SA (Rego) | CRITICAL | wildcards.rego |
| RBAC-006 | Broad secrets access | HIGH | wildcards.rego |
| RBAC-007 | pods/exec permission | HIGH | wildcards.rego |

**Total: 35 Go checks + 14 Rego policies = 49 security rules**

## Example Output

```
▶ KuberNeet Security Scan
  Target: cluster (all namespaces)
  Time:   2026-04-24 20:45:23

  Summary: CRITICAL: 2  HIGH: 5  MEDIUM: 12

SEVERITY     ID         RESOURCE                       NAMESPACE            ISSUE
------------------------------------------------------------------------------------------
CRITICAL     POD-001    nginx-deployment               production           Privileged container 'nginx' can escape to host via nsenter
CRITICAL     POD-005    api-gateway                    default              Dangerous hostPath mount: /var/run/docker.sock
HIGH         POD-008    frontend-app                   staging              Container 'app' missing 'drop: ALL' capabilities
HIGH         POD-002    monitoring-daemon              kube-system          hostPID=true shares host's PID namespace
HIGH         RBAC-001    cluster-admin-role             —                    ClusterRole 'admin-all' uses wildcard (*) permissions
MEDIUM       POD-006    web-app                        default              Missing seccomp profile
...

Total: 19 findings
```

## Architecture

```
┌──────────────────────────────────────────────┐
│ CLI (Cobra + Viper)                          │
│ ├── scan    — cluster/manifest scanning      │
│ ├── graph   — attack path analysis          │
│ ├── watch   — real-time informer monitoring │
│ ├── report  — HTML report generation         │
│ ├── multi   — multi-cluster federation      │
│ ├── webhook — admission controller          │
│ └── version — version info                  │
├──────────────────────────────────────────────┤
│ Scanner (client-go)                          │
│ ├── Pod security (13 checks)                 │
│ ├── RBAC analysis (5 checks)                │
│ ├── Deployment security (3 checks)          │
│ ├── NetworkPolicy (4 checks)               │
│ ├── CIS Benchmarks (8 checks)               │
│ └── Manifest scanning (offline)             │
├──────────────────────────────────────────────┤
│ Policy Engine (OPA/Rego, --opa flag)         │
│ ├── policies/pod/escapes.rego               │
│ ├── policies/rbac/wildcards.rego            │
│ └── policies/bundle.rego                    │
├──────────────────────────────────────────────┤
│ Attack Graph Engine                          │
│ ├── Service → Pod → SA → Role graph         │
│ ├── Path finding (BFS)                      │
│ └── Risk scoring algorithm                  │
├──────────────────────────────────────────────┤
│ Admission Webhook                            │
│ ├── Validation mode (block violations)       │
│ └── Mutation mode (auto-fix issues)         │
└──────────────────────────────────────────────┘
```

## Testing

```bash
make test    # Run all 23 unit tests
make vet     # Run go vet
make build   # Build binary
```

Tests cover: privileged containers, host namespaces, all 9 dangerous capabilities, hostPath mounts, security context, severity filtering, remediation filtering, scan IDs, JSON/SARIF output, graph construction, selector matching, and attack path detection.

## CI/CD Integration

### GitHub Actions

```yaml
name: CI
on: [push, pull_request]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version-file: go.mod
      - run: go mod download
      - run: go build -o bin/kuberneet ./cmd/kuberneet
      - run: go vet ./...
      - run: go test ./...

  manifest-scan:
    needs: build
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/download-artifact@v4
        with:
          name: kuberneet-linux-amd64
      - run: chmod +x kuberneet
      - run: ./kuberneet scan --manifest deploy/admission-webhook.yaml --output json
```

## Admission Webhook

Deploy the admission controller to enforce security policies:

```bash
# Deploy webhook (replace TLS placeholders)
env TLS_CRT_B64=$(base64 < server.crt) \
  TLS_KEY_B64=$(base64 < server.key) \
  CA_BUNDLE_B64=$(base64 < ca.crt) \
  envsubst < deploy/admission-webhook.yaml | kubectl apply -f -

# Run webhook locally (for testing)
kuberneet webhook --cert server.crt --key server.key --mutate
```

### Auto-Mutation Mode

When `--mutate` is enabled, the webhook automatically patches pods with security defaults:

```yaml
# Automatically applied:
spec:
  securityContext:
    seccompProfile:
      type: RuntimeDefault
  containers:
  - securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      runAsNonRoot: true
      capabilities:
        drop: ["ALL"]
  automountServiceAccountToken: false
```

## Multi-Cluster Scanning

```bash
# Scan all clusters in kubeconfig
kuberneet multi

# Specific kubeconfig
kuberneet multi --kubeconfig ~/.kube/config

# JSON output
kuberneet multi --output json
```

## Feature Matrix

| Feature | CLI | Webhook | Status |
|---------|-----|---------|--------|
| Pod Security | ✅ | ✅ | 13 checks |
| RBAC Analysis | ✅ | ❌ | 5 checks |
| Deployment Security | ✅ | ✅ | 3 checks |
| NetworkPolicy | ✅ | ❌ | 4 checks |
| CIS Benchmarks | ✅ | ❌ | 8 checks (3 live, 5 manual) |
| OPA/Rego | ✅ | ❌ | 14 policies (--opa flag) |
| Attack Graph | ✅ | ❌ | BFS path finding |
| Real-time Watch | ✅ | ❌ | Informer-based |
| Multi-cluster | ✅ | ❌ | Kubeconfig federation |
| Auto-mutation | ❌ | ✅ | Pod security defaults |
| Manifest Scan | ✅ | ❌ | Offline YAML |
| HTML Report | ✅ | ❌ | D3 visualization |
| SARIF Output | ✅ | ❌ | GitHub Code Scanning |

## Project Stats

- **25 Go source files** (~4,900 LOC)
- **23 unit tests** (scanner: 10, finding: 5, graph: 8)
- **35 Go security checks** + **14 Rego policies**
- **8 CLI commands** (scan, graph, watch, report, multi, webhook, version)
- **CWE + MITRE ATT&CK** mapping on every finding

## License

MIT

---
*Built by Agent Mackenzie + Raphael | Security Apps • KuberNeet v0.1.0*