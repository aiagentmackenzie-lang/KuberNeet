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
┌─────────────────────────────────────────┐
│ CLI (Cobra + Viper)                     │
├─────────────────────────────────────────┤
│ Scanner (client-go)                       │
│ ├── Pod checks                          │
│ ├── Deployment checks                   │
│ └── RBAC analysis                       │
├─────────────────────────────────────────┤
│ Policy Engine (OPA/Rego → Phase 2)        │
├─────────────────────────────────────────┤
│ Output: Table | JSON | YAML               │
└─────────────────────────────────────────┘
```

## Roadmap

**Phase 1** ✅ DONE
- Core CLI with Cobra
- Client-go cluster scanning
- 15+ security checks
- JSON/YAML output
- CWE/MITRE mappings
- Remediation generation

**Phase 2** (TODO)
- OPA/Rego policy engine
- Informers for real-time scanning
- Attack path graph generation
- NetworkPolicy analysis
- CIS v1.12 controls

**Phase 3** (TODO)
- kubectl plugin
- CI/CD integrations (GitHub Actions)
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
