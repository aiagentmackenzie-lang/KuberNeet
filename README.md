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
cd Security\ Apps/KuberNeet
go build -o bin/kuberneet ./cmd/kuberneet

# Scan entire cluster
./bin/kuberneet scan

# Scan specific namespace
./bin/kuberneet scan --namespace production

# JSON output for CI/CD
./bin/kuberneet scan --output json

# Show details with remediation
./bin/kuberneet scan --remediate

# Build attack graph
./bin/kuberneet graph

# Export graph as JSON
./bin/kuberneet graph --output kuberneet-graph.json

# Real-time watch mode (informers)
./bin/kuberneet watch
```

## Security Checks (Phase 1)

### Container Security
| ID | Check | Severity | CWE | MITRE |
|----|-------|----------|-----|-------|
| POD-001 | Privileged containers | CRITICAL | CWE-250 | T1611 |
| POD-002 | hostPID namespace | HIGH | CWE-284 | T1055 |
| POD-003 | hostNetwork namespace | HIGH | CWE-284 | T1550.005 |
| POD-004 | hostIPC namespace | HIGH | CWE-284 | - |
| POD-005 | Dangerous hostPath mounts | CRITICAL | CWE-552 | T1611 |
| POD-006 | Missing seccomp profile | MEDIUM | CWE-284 | - |
| POD-007 | Dangerous capabilities | CRITICAL | CWE-250 | T1068 |
| POD-008 | Missing DROP ALL capabilities | HIGH | CWE-250 | - |
| POD-009 | No securityContext | MEDIUM | CWE-284 | - |
| POD-010 | allowPrivilegeEscalation | HIGH | CWE-250 | - |
| POD-011 | runAsRoot allowed | MEDIUM | CWE-250 | - |
| POD-012 | Default ServiceAccount | MEDIUM | CWE-284 | - |
| POD-013 | Token automount enabled | HIGH | CWE-284 | T1528 |

### RBAC Security
| ID | Check | Severity | CWE | MITRE |
|----|-------|----------|-----|-------|
| RBAC-001 | ClusterRole wildcard | HIGH | CWE-250 | T1098 |
| RBAC-002 | Role wildcard | HIGH | CWE-250 | - |
| RBAC-003 | cluster-admin → default SA | CRITICAL | CWE-250 | T1098 |
| RBAC-005 | Role bound to default SA | MEDIUM | CWE-284 | - |

## Example Output

```
▶ KuberNeet Security Scan
  Target: cluster (all namespaces)
  Time:   2026-04-18 17:45:23

  Summary: CRITICAL: 2  HIGH: 5  MEDIUM: 12

SEVERITY     ID         RESOURCE                       NAMESPACE            ISSUE
-----------------------------------------------------------------------------------------
CRITICAL     POD-001    nginx-deployment               production           Privileged container 'nginx' can escape...
CRITICAL     POD-005    api-gateway                    default              Dangerous hostPath mount: /var/run/docker.sock
HIGH         POD-008    frontend-app                   staging              Container 'app' missing 'drop: ALL'...
...

Total: 19 findings
```

## Architecture

```
┌──────────────────────────────────────────────┐
│ CLI (Cobra + Viper)                          │
│ ├── scan - cluster/manifest scanning         │
│ ├── graph - attack path analysis             │
│ └── watch - real-time informer monitoring    │
├──────────────────────────────────────────────┤
│ Scanner (client-go Informers)                │
│ ├── Pod security checks                      │
│ ├── RBAC analysis                            │
│ └── Real-time event streaming                │
├──────────────────────────────────────────────┤
│ Policy Engine (OPA/Rego)                     │
│ ├── policies/pod/escapes.rego                │
│ ├── policies/rbac/wildcards.rego             │
│ └── Risk scoring (CWE/MITRE)                 │
├──────────────────────────────────────────────┤
│ Attack Graph Engine                          │
│ ├── Service → Pod → SA → Role graph          │
│ ├── Path finding (BFS)                       │
│ └── Risk scoring algorithm                   │
└──────────────────────────────────────────────┘
```

## Roadmap

**Phase 1** ✅ DONE
- Core CLI with Cobra
- HTML report with D3 visualization
- Prometheus metrics

## Development

```bash
# Build
go build -o bin/kuberneet ./cmd/kuberneet

# Test
go test ./...

# Run locally
./bin/kuberneet scan --verbose
```

## License

MIT

---
*Built by Agent Mackenzie + Raphael | Security Apps • KuberNeet v0.1.0*

## Roadmap

All phases complete.

**Phase 1** ✅ Core scanner with 15+ checks
**Phase 2** ✅ OPA/Rego engine + attack graph
**Phase 3** ✅ NetworkPolicy + CIS + CI/CD + HTML reports


### NetworkPolicy Security (Phase 3)
| ID | Check | Severity | CWE |
|----|-------|----------|-----|
| NET-001 | Missing default-deny | HIGH | CWE-284 |
| NET-002 | Allows 0.0.0.0/0 | CRITICAL | CWE-284 |
| NET-003 | Broad rules on all pods | MEDIUM | CWE-284 |
| NET-004 | Unrestricted egress | MEDIUM | CWE-284 |

### CIS Benchmarks (Phase 3)
| ID | Check | Severity |
|----|-------|----------|
| CIS-1.2.1 | Anonymous auth disabled | CRITICAL |
| CIS-1.2.6 | RBAC authorization | CRITICAL |
| CIS-4.2.1 | Kubelet anonymous auth | CRITICAL |

## CI/CD Integration

### GitHub Actions

Create `.github/workflows/security.yml`:

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Run KuberNeet
        run: |
          curl -L https://github.com/raphael/kuberneet/releases/download/v0.1.0/kuberneet-linux-amd64 -o kuberneet
          chmod +x kuberneet
          ./kuberneet scan --output sarif --output-file results.sarif
          
      - name: Upload to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

## kubectl Plugin

Install via krew:

```bash
kubectl krew index add raphael https://github.com/raphael/kuberneet
kubectl krew install raphael/kuberneet
kubectl kuberneet scan
kubectl kuberneet graph
```

## Generate HTML Report

```bash
# Interactive HTML report with D3 visualization
kuberneet report --html --output security-report.html

# Open in browser
open security-report.html
```

