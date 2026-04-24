# KuberNeet (formerly KubePulse) — Technical Specification v2.0

> **Note:** This project was renamed from KubePulse to KuberNeet during development. All code and docs use the KuberNeet name.

**Date:** April 18, 2026  
**Research Status:** ✅ Deep dive complete (client-go informers, OPA/Rego, container escapes, CIS v1.12, MITRE ATT&CK)  
**Author:** Agent Mackenzie + Raphael  
**Status:** Architecture Complete → Ready for Implementation  

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Threat Model](#threat-model)
3. [System Architecture](#system-architecture)
4. [Client-Go Deep Dive](#client-go-deep-dive)
5. [Security Check Engine](#security-check-engine)
6. [Attack Path Analysis](#attack-path-analysis)
7. [Implementation Phases](#implementation-phases)
8. [Appendices](#appendices)

---

## Executive Summary

### The Problem

Kubescape (11k stars) is enterprise-grade but **opaque** — 600+ controls, complex scoring, hard to learn from. Security engineers need a tool that:
- Explains **why** something is insecure (not just "CIS-5.2.3 failed")
- Maps findings to **attack paths** (not isolated issues)
- Generates **exact remediation** YAML (not vague advice)
- Teaches **Kubernetes security concepts** while scanning

### The Solution

**KubePulse** — A Kubernetes security scanner with educational DNA:
- **CLI-first** (like your other projects: WebBreaker, DEADDROP)
- **Real-time scanning** using client-go Informers (not polling)
- **OPA/Rego policy engine** (same as Kubescape)
- **Attack path graph** (service → pod → privileged pod → host escape)
- **Learning mode** explains CWE, container escape techniques, RBAC risks

### Differentiation

| Dimension | Kubescape | kube-bench | KubePulse |
|-----------|-----------|------------|-----------|
| **Philosophy** | Compliance/Enterprise | Checklist/Verification | Education + Action |
| **Output** | Risk scores (0-100) | Pass/Fail | Attack paths + remediation |
| **Engine** | OPA/Rego | Shell scripts | OPA/Rego + Go checks |
| **Remediation** | Auto-patch | Manual | Generated YAML |
| **RBAC Analysis** | Basic | None | Deep graph analysis |
| **Container Security** | Some | None | Deep escape detection |
| **Learning Mode** | No | No | Yes (CWE + techniques) |

---

## Threat Model

### Container Escape Techniques to Detect

Based on research of real-world escape techniques (Stormbane Security, CVE databases):

#### 1. Privileged Container Escape
**Technique:** `securityContext.privileged: true` removes ALL isolation
**Attack:**
```bash
# In privileged container
nsenter -t 1 -m -u -i -n -p -- bash
# Now root on host
```
**Detection:** Check `spec.containers[*].securityContext.privileged == true`
**Remediation:** Remove privilege, add specific capabilities

#### 2. hostPID Namespace Abuse
**Technique:** `hostPID: true` shares host's PID namespace
**Attack:**
```bash
# Access any host process
/proc/[HOST_PID]/environ  # Steal secrets
/proc/1/root              # Host filesystem
```
**Detection:** `spec.hostPID == true` AND container can access /proc
**Remediation:** Use `hostPID: false` or dedicated monitoring namespace

#### 3. hostNetwork + Metadata Endpoint
**Technique:** `hostNetwork: true` puts container in host network namespace
**Attack:**
```bash
# Access cloud metadata
169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token
```
**Detection:** `spec.hostNetwork == true` on cloud provider
**Remediation:** NetworkPolicy blocking 169.254.169.254 + Workload Identity

#### 4. hostPath Mounts
**Dangerous mounts:**
- `/var/run/docker.sock` → Docker escape
- `/proc` → Host process access
- `/sys` → Kernel control
- `/etc` → Host config tampering

**Attack:**
```bash
docker run --rm -v /:/host alpine chroot /host
```

**Detection:**
```rego
violation[msg] {
    volume := input.spec.volumes[_].hostPath
    dangerous_paths := ["/proc", "/sys", "/var/run/docker.sock", "/etc"]
    startswith(volume.path, dangerous_paths[_])
    msg := sprintf("Dangerous hostPath mount: %s", [volume.path])
}
```

#### 5. Dangerous Capabilities
**Critical capabilities:**
- `CAP_SYS_ADMIN` → mount, namespace manipulation
- `CAP_SYS_PTRACE` → process injection
- `CAP_SYS_MODULE` → kernel module loading
- `CAP_NET_ADMIN` → network manipulation
- `CAP_CHOWN/CAP_FOWNER` → permission bypass

**Detection:** Check `securityContext.capabilities.add` for these

### RBAC Attack Paths

#### Privilege Escalation via Wildcards
```yaml
# DANGEROUS: Allows all verbs on all secrets
rules:
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["*"]
```

#### Token Theft via automount
```yaml
# Pods get default SA token automatically
spec:
  automountServiceAccountToken: true  # Default is true!
```
**Attack:** If compromised, attacker calls K8s API with pod's permissions

#### Cluster-Admin Binding
```yaml
# DANGEROUS
subjects:
- kind: ServiceAccount
  name: default
  namespace: default
roleRef:
  kind: ClusterRole
  name: cluster-admin  # Full cluster admin!
```

---

## System Architecture

### Component Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                        KubePulse CLI                          │
│  (Cobra + Viper + Rich terminal UI)                         │
└────────────────────┬────────────────────────────────────────┘
                     │ kubeconfig
┌────────────────────▼────────────────────────────────────────┐
│                Client-Go Interface                          │
│  ┌─────────────────────────────────────────────────────┐  │
│  │  Discovery Client (API Resource Detection)        │  │
│  └────────────────────┬────────────────────────────────  │
│                      │                                     │
│  ┌───────────────────▼───────────────────────────────┐  │
│  │   SharedInformerFactory (Dynamic Informers)       │  │
│  │   ┌──────────┐ ┌──────────┐ ┌──────────┐        │  │
│  │   │ Pod      │ │ Deploy   │ │ RBAC     │ ...    │  │
│  │   │ Informer │ │ Informer │ │ Informer │        │  │
│  │   └────┬─────┘ └────┬─────┘ └────┬─────┘        │  │
│  │        └─────────────┴──────────┘              │  │
│  │                     │                            │  │
│  │   ┌─────────────────▼────────────────┐          │  │
│  │   │ DeltaFIFO (Event Queue)          │          │  │
│  │   │ - ADDED                          │          │  │
│  │   │ - MODIFIED                       │          │  │
│  │   │ - DELETED                        │          │  │
│  │   └─────────────────┬────────────────┘          │  │
│  └─────────────────────┬─────────────────────────────┘  │
│                        │                                   │
│  ┌───────────────────▼────────────────┐                │
│  │ ThreadSafeStore (Local Cache)      │                │
│  │ + Custom Indexers                  │                │
│  └───────────────────┬────────────────┘                │
└────────────────────┬──────────────────────────────────────┘
                     │ events (add/update/delete)
┌────────────────────▼────────────────────────────────────────┐
│                 Policy Engine (OPA/Rego)                    │
│  ┌────────────────────────────────────────────────────┐  │
│  │ Policy Bundle (.tar.gz or filesystem)              │  │
│  │ ├── pod_security.rego       (escapes)              │  │
│  │ ├── rbac_security.rego      (privilege elevation)  │  │
│  │ ├── network_policies.rego   (missing deny-all)     │  │
│  │ └── cis_controls.rego       (CIS v1.12)            │  │
│  └──────────────────────────┬─────────────────────────────┘  │
│                             │ OPA Query API                   │
│  ┌─────────────────────────▼──────────────────────────┐  │
│  │ OPA SDK (github.com/open-policy-agent/opa/sdk)    │  │
│  │ - Compile Rego → WASM                             │  │
│  │ - Evaluate against input (K8s resource)         │  │
│  └─────────────────────────┬──────────────────────────┘  │
│                             │ violations                    │
└─────────────────────────────┼───────────────────────────────┘
                              │
┌─────────────────────────────▼───────────────────────────────┐
│                    Analysis Engine (Go)                      │
│  ┌────────────────────────────────────────────────────────┐ │
│  │  Attack Path Builder                                   │ │
│  │  ┌────────────────┐ ┌────────────────┐              │ │
│  │  │ Service → Pod  │ │ Pod → Privileged │              │ │
│  │  │ Mapping        │ │ → Host           │              │ │
│  │  └────────────────┘ └────────────────┘              │ │
│  └────────────────────────────────────────────────────────┘ │
│                                                                │
│  ┌────────────────────────────────────────────────────────┐ │
│  │  Remediation Generator                                 │ │
│  │  - Patch JSON for kubectl                              │ │
│  │  - Kubernetes manifest fixes                           │ │
│  │  - Kustomize overlays                                    │ │
│  └────────────────────────────────────────────────────────┘ │
└───────────────────────────────────────────────────────────────┘

Persistence Layer (SQLite/PostgreSQL):
- resource_snapshots
- findings
- attack_paths
- remediation_templates
```

### Data Flow

```
1. CLI: kubepulse scan --namespace production --depth deep

2. Discovery: Enumerate all GVRs (GroupVersionResource) in cluster
   - core/v1/pods
   - rbac.authorization.k8s.io/v1/roles
   - networking.k8s.io/v1/networkpolicies
   - ...

3. InformerFactory.Start() → DeltaFIFO receives events

4. WaitForCacheSync() → Local cache has all current state

5. For each resource type:
   a. List ALL from cache (no API server load)
   b. Convert to map[string]interface{} (unstructured)
   c. Run OPA query: data.kubepulse.violation
   d. Collect violations with metadata

6. Attack Path Analysis:
   a. Build Service → Pod graph
   b. Calculate risk scores (privilege × exposure)
   c. Identify lateral movement paths

7. Remediation Generation:
   a. Fetch template for violation type
   b. Fill in resource-specific values
   c. Validate YAML

8. Output:
   - Terminal: Rich table with severity
   - JSON: Full details for CI/CD
   - HTML: Interactive attack graph
   - SARIF: GitHub Code Scanning upload
```

---

## Client-Go Deep Dive

### Why Informers Matter

**Wrong approach (polling):**
```go
// DON'T DO THIS
for {
    pods, _ := clientset.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
    // Check security... 
    time.Sleep(30 * time.Second)  // High API server load
}
```

**Correct approach (List-Watch pattern):**
```go
// DO THIS: Single HTTP streaming connection
informerFactory := informers.NewSharedInformerFactory(clientset, 0)
podInformer := informerFactory.Core().V1().Pods()

// Register callback: invoked on every change
podInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
    AddFunc: func(obj interface{}) {
        pod := obj.(*corev1.Pod)
        scanner.ScanPod(pod)
    },
    UpdateFunc: func(oldObj, newObj interface{}) {
        pod := newObj.(*corev1.Pod)
        scanner.ScanPod(pod)
    },
    DeleteFunc: func(obj interface{}) {
        // Cleanup findings for deleted resource
    },
})

informerFactory.Start(ctx.Done())
```

### SharedIndexInformer Internals

```go
// Internal architecture (simplified)
type sharedIndexInformer struct {
    // 1. Reflector: List-Watch to API server
    reflector *Reflector
    
    // 2. DeltaFIFO: Queue of add/update/delete events
    fifo *DeltaFIFO
    
    // 3. Indexer: Local cache + custom indexes
    indexer Indexer
    
    // 4. Event handlers: Your security checks
    handlers []ResourceEventHandler
}
```

### Custom Indexers for Security

```go
// Index pods by node name (for node compromise scenarios)
nodeNameIndexFunc := func(obj interface{}) ([]string, error) {
    pod := obj.(*corev1.Pod)
    return []string{pod.Spec.NodeName}, nil
}

informer := cache.NewSharedIndexInformer(
    &cache.ListWatch{
        ListFunc:   listFunc,
        WatchFunc:  watchFunc,
    },
    &corev1.Pod{},
    0, // No resync needed for security scanning
    cache.Indexers{
        "namespace": cache.MetaNamespaceIndexFunc,
        "node":      nodeNameIndexFunc,
        "sa":        serviceAccountIndexFunc,  // Custom: index by SA
    },
)

// Query: Find all pods using compromised ServiceAccount
saPods, _ := informer.GetIndexer().ByIndex("sa", "default")
```

### Dynamic Informers (for CRDs)

```go
// Discovery: Find all available resources
discoveryClient := clientset.Discovery()
apiResourceList, _ := discoveryClient.ServerResources()

// For each resource with "list" + "watch" verbs:
dynamicClient := dynamic.NewForConfig(config)
factory := dynamicinformer.NewDynamicSharedInformerFactory(dynamicClient, 0)

for _, gvr := range securityRelevantGVRs {
    informer := factory.ForResource(gvr)
    informer.Informer().AddEventHandler(handler)
}
```

---

## Security Check Engine

### Rego Policy Structure

```rego
# policies/pod_security.rego
package kubepulse

import future.keywords.if
import future.keywords.contains

# Default deny
violation[{"msg": msg, "id": id, "severity": severity}] {
    check_privileged
    msg := "Privileged container detected"
    id := "POD-001"
    severity := "CRITICAL"
}

violation[{"msg": msg, "id": id, "severity": severity}] {
    check_hostpid_no_seccomp
    msg := "hostPID=true without seccomp"
    id := "POD-002"
    severity := "HIGH"
}

# --- Helper Checks ---

check_privileged if {
    input.spec.containers[_].securityContext.privileged
}

check_privileged if {
    input.spec.initContainers[_].securityContext.privileged
}

check_hostpid_no_seccomp if {
    input.spec.hostPID == true
    input.spec.securityContext.seccompProfile.type == "Unconfined"
}

# Metadata extraction
resource := {
    "name": input.metadata.name,
    "namespace": input.metadata.namespace,
    "kind": input.kind,
}
```

### Go Integration (OPA SDK)

```go
package scanner

import (
    "context"
    "embed"
    
    "github.com/open-policy-agent/opa/sdk"
)

//go:embed policies/*.rego
var policyFS embed.FS

type OPAScanner struct {
    opa *sdk.OPA
}

func NewOPAScanner(ctx context.Context) (*OPAScanner, error) {
    config := []byte(`{
        "services": {
            "policies": {
                "url": "file://./policies"
            }
        },
        "bundles": {
            "kubepulse": {
                "service": "policies",
                "resource": "bundle.tar.gz"
            }
        }
    }`)
    
    opa, err := sdk.New(ctx, sdk.Options{
        ID:     "kubepulse-scanner",
        Config: bytes.NewReader(config),
    })
    if err != nil {
        return nil, err
    }
    
    return &OPAScanner{opa: opa}, nil
}

func (s *OPAScanner) ScanPod(ctx context.Context, pod map[string]interface{}) ([]Finding, error) {
    result, err := s.opa.Decision(ctx, sdk.DecisionOptions{
        Path:  "/kubepulse/violation",
        Input: pod,
    })
    if err != nil {
        return nil, err
    }
    
    // Parse violations from result
    var findings []Finding
    for _, v := range result.Result.([]interface{}) {
        findings = append(findings, Finding{
            ID:       v.(map[string]interface{})["id"].(string),
            Msg:      v.(map[string]interface{})["msg"].(string),
            Severity: v.(map[string]interface{})["severity"].(string),
        })
    }
    return findings, nil
}
```

---

## Attack Path Analysis

### Graph Model

```go
// Node types
const (
    NodeTypeService   = "service"
    NodeTypePod       = "pod"
    NodeTypeSA        = "serviceaccount"
    NodeTypeRBAC      = "rbac"
    NodeTypeNode      = "node"
)

// Edge types
const (
    EdgeTypeExposes      = "exposes"       // Service → Pod
    EdgeTypeUses         = "uses"          // Pod → SA
    EdgeTypeCanAssume    = "can_assume"    // SA → Role
    EdgeTypeRunsOn       = "runs_on"       // Pod → Node
    EdgeTypeAllowsEscalation = "escalation" // Privileged
)

// AttackPath represents a chain of exploitation
type AttackPath struct {
    Start       *Node
    End         *Node
    RiskScore   float64
    Technique   string
    Description string
    Path        []*Node
}
```

### Attack Path Example: External → Host Root

```
Internet
    │
    ▼
┌─────────────┐  LoadBalancer Service (exposed to 0.0.0.0/0)
│  Service    │─────────────────┐
└─────────────┘                 │
    │                           │
    │ selector: app=web         │
    ▼                           │
┌─────────────┐                 │
│  Pod        │                 │
│  - nginx    │                 │
│  - privileged: false          │
└─────────────┘                 │
    │                           │
    │ mounts /var/run/docker.sock │
    ▼                           │
┌─────────────┐                 │
│  Escape via │                 │
│  Docker API │                 │
└─────────────┘                 │
    │                           │
    ▼                           │
┌─────────────┐                │
│  Host Root  │◄───────────────┘
└─────────────┘

Score: CRITICAL (external exposure + container escape)
```

### Calculating Risk

```go
func (ap *AttackPath) CalculateRisk() {
    baseScore := 0.0
    
    // Exposure factor
    if ap.Start.IsExternallyExposed() {
        baseScore += 10.0
    }
    
    // Privilege escalation
    for _, node := range ap.Path {
        if node.Type == NodeTypePod && node.HasPrivilegedContainer() {
            baseScore += 8.0
        }
        if node.Type == NodeTypeSA && node.HasWildcardPermissions() {
            baseScore += 6.0
        }
    }
    
    // Chain length (shorter = higher impact)
    if len(ap.Path) <= 2 {
        baseScore *= 1.5
    }
    
    ap.RiskScore = baseScore
}
```

---

## Implementation Phases

### Phase 1: Core Infrastructure (Week 1-2)

**Goal:** Go CLI with pod security scanning

#### Task 1.1: Project Scaffold
- [ ] Initialize Go module: `go mod init github.com/raphael/kubepulse`
- [ ] Cobra CLI framework with subcommands:
  - `kubepulse scan` — Run security scan
  - `kubepulse scan --namespace [ns]` — Scoped scan
  - `kubepulse scan --manifest [file.yaml]` — Offline scan
  - `kubepulse version` — Display version
- [ ] Viper configuration management (~/.kubepulse/config.yaml)
- [ ] Rich terminal UI (progress bars, tables, colors)
- [ ] Structured logging (slog)

**Acceptance:**
```bash
$ kubepulse version
KubePulse v0.1.0
Go: 1.24
Client-go: v0.28.x

$ kubepulse scan --help
Scan Kubernetes resources for security issues

Usage:
  kubepulse scan [flags]

Flags:
  -n, --namespace string    Target namespace (default: all)
  -m, --manifest string     Scan local YAML manifest
  -o, --output string       Output format: table|json|sarif (default: table)
  -v, --verbose             Enable verbose logging
```

#### Task 1.2: Client-Go Integration
- [ ] kubeconfig loading (standard paths + KUBECONFIG env)
- [ ] Cluster connectivity test
- [ ] Resource discovery (identify what's in the cluster)
- [ ] SharedInformerFactory for:
  - Pods
  - Deployments
  - ServiceAccounts
  - Roles/ClusterRoles
  - RoleBindings/ClusterRoleBindings
  - NetworkPolicies
- [ ] Local cache with SQLite persistence

**Key Code:**
```go
// Informers for core security resources
func (s *Scanner) setupInformers(factory informers.SharedInformerFactory) {
    // Pods
    podInformer := factory.Core().V1().Pods().Informer()
    podInformer.AddEventHandler(cache.FilteringResourceEventHandler{
        FilterFunc: func(obj interface{}) bool {
            // Only security-relevant pods
            return true
        },
        Handler: cache.ResourceEventHandlerFuncs{
            AddFunc:    s.handlePodAdd,
            UpdateFunc: s.handlePodUpdate,
            DeleteFunc: s.handlePodDelete,
        },
    })
    
    // RBAC resources
    // ... similar for Roles, RoleBindings, etc.
}
```

#### Task 1.3: 10 Core Security Checks (Go)

Implement WITHOUT OPA first (simpler, faster):

1. **Privileged containers**
   ```go
   if pod.Spec.Containers[i].SecurityContext != nil &&
      *pod.Spec.Containers[i].SecurityContext.Privileged {
      findings = append(findings, Finding{
          ID: "POD-001",
          Severity: "CRITICAL",
          CWE: "CWE-250",
          Description: "Privileged container can escape to host via nsenter",
          Remediation: "Remove privileged: true, use capabilities instead",
          CodeSnippet: generateFix(pod, "privileged"),
      })
   }
   ```

2. **hostPID/IPC/Network**
3. **hostPath mounts** (dangerous paths)
4. **ServiceAccount automount** (automountServiceAccountToken)
5. **Default ServiceAccount usage**
6. **Missing NetworkPolicies**
7. **RunAsRoot allowed**
8. **allowPrivilegeEscalation: true**
9. **Missing seccomp profile**
10. **Missing drop ALL capabilities**

**Acceptance:**
- Scan 100 pods in < 10 seconds
- 0 false positives on standard templates

### Phase 2: Policy Engine + RBAC (Week 3-4)

**Goal:** OPA integration, deep RBAC analysis

#### Task 2.1: OPA/Rego Integration
- [ ] OPA SDK setup (embedded, not sidecar)
- [ ] Policy bundle structure
- [ ] Rego compilation caching
- [ ] Convert 10 Go checks → Rego policies

**Policy Bundle Structure:**
```
policies/
├── bundle.rego          # Entry point
├── pod/
│   ├── escapes.rego     # Container escape checks
│   ├── security_context.rego
│   └── capabilities.rego
├── rbac/
│   ├── escalation.rego    # Privilege escalation
│   ├── wildcards.rego     # * in verbs/resources
│   └── service_accounts.rego
├── network/
│   └── policies.rego      # Missing deny-all
└── cis/
    └── v1.12/
        ├── master.rego
        └── worker.rego
```

#### Task 2.2: RBAC Security Analysis
- [ ] Parse Role/ClusterRole bindings
- [ ] Detect wildcard permissions
- [ ] Identify cluster-admin bindings
- [ ] ServiceAccount token exposure detection
- [ ] Dangerous RoleBindings (default SA + cluster-admin)

**Example Finding:**
```yaml
Finding ID: RBAC-007
Severity: CRITICAL
Description: ClusterRole 'cluster-admin' bound to ServiceAccount 'default' in namespace 'production'

Attack Path:
1. Compromise any pod in 'production' namespace
2. Token is mounted at /var/run/secrets/kubernetes.io/serviceaccount/token
3. Token has cluster-admin = full cluster compromise

Remediation:
```
apiVersion: v1
kind: ServiceAccount
metadata:
  name: production-app
  namespace: production
automountServiceAccountToken: false
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: limited-role
  namespace: production
rules:
- apiGroups: [""]
  resources: ["configmaps"]
  verbs: ["get", "list"]
```
```

#### Task 2.3: Attack Path Engine
- [ ] Graph construction (Service → Pod → SA → Role)
- [ ] BFS path finding
- [ ] Risk scoring algorithm
- [ ] Export to GraphJSON for visualization

### Phase 3: Remediation + Output (Week 5-6)

**Goal:** Actionable output, not just findings

#### Task 3.1: Remediation Generator
- [ ] Patch generation (kubectl patch)
- [ ] Manifest fixes (clean YAML)
- [ ] Kustomize overlay generation
- [ ] Policy-as-code (Kyverno/OPA Gatekeeper)

#### Task 3.2: Output Formats
- [ ] Terminal: Rich tables with colors
- [ ] JSON: Structured for automation
- [ ] SARIF: GitHub Code Scanning integration
- [ ] HTML: Interactive attack path visualization (D3.js)
- [ ] PDF: Compliance reports

#### Task 3.3: CLI Improvements
- [ ] Watch mode (continuous scanning)
- [ ] Severity filtering (--severity CRITICAL)
- [ ] Namespace filtering
- [ ] Exclusion patterns

### Phase 4: Advanced Features (Week 7-8)

**Goal:** Production readiness

#### Task 4.1: Performance
- [ ] Worker pool for parallel scanning
- [ ] Rate limiting for API server
- [ ] Incremental scanning (only changed resources)
- [ ] Memory optimization for large clusters (1000+ pods)

#### Task 4.2: Integration
- [ ] kubectl plugin (krew)
- [ ] GitHub Action
- [ ] Tekton Task
- [ ] Helm chart
- [ ] Prometheus metrics

#### Task 4.3: CIS v1.12 Coverage
- [ ] Implement 50+ CIS controls
- [ ] Mapping to MITRE ATT&CK
- [ ] Compliance scoring

---

## Appendices

### Appendix A: Container Escape Detection Script

```bash
#!/bin/bash
# deepce.sh equivalent — detection from inside container

echo "[*] KubePulse Container Escape Detection"

# Check for privileged
cat /proc/1/status 2>/dev/null | grep -q "CapEff:\s*0000003fffffffff" && {
    echo "[!] PRIVILEGED: Full capability set detected"
}

# Check for hostPID
ls -la /proc/1/ns/pid 2>/dev/null | grep -q "net:\[" && {
    echo "[!] HOSTPID: /proc/1 visible"
}

# Check for hostNetwork
ip addr | grep -q "docker0\|cni0" && {
    echo "[!] HOSTNETWORK: Host network interfaces visible"
}

# Check for dangerous mounts
for path in /var/run/docker.sock /proc /sys /etc; do
    if mount | grep -q "on $path"; then
        echo "[!] DANGEROUS MOUNT: $path"
    fi
done

echo "[*] Scan complete"
```

### Appendix B: Rego Policy Examples

**RBAC Wildcard Detection:**
```rego
package kubepulse.rbac

violation[{"msg": msg, "id": id}] {
    role := input
    rule := role.rules[_]
    rule.verbs[_] == "*"
    msg := sprintf("Role %s grants wildcard (*) verbs", [role.metadata.name])
    id := "RBAC-003"
}

violation[{"msg": msg, "id": id}] {
    role := input
    rule := role.rules[_]
    rule.resources[_] == "*"
    rule.verbs[_] == "*"
    msg := sprintf("Role %s grants wildcard (*) on resources", [role.metadata.name])
    id := "RBAC-004"
}
```

**NetworkPolicy Default Deny Check:**
```rego
package kubepulse.network

# Check if namespace has default-deny NetworkPolicy
has_default_deny if {
    np := input.networkpolicies[_]
    np.spec.podSelector == {}  # Matches all pods
    np.spec.policyTypes[_] == "Ingress"
    count(np.spec.ingress) == 0  # No ingress rules
}

violation[{"msg": msg, "id": id}] {
    not has_default_deny
    msg := "Namespace lacks default-deny NetworkPolicy"
    id := "NET-001"
}
```

### Appendix C: CIS v1.12 Priority Controls

**Master Node (API Server):**
- 1.2.1: anonymous-auth = false
- 1.2.6: authorization-mode ≠ AlwaysAllow
- 1.2.7-8: authorization-mode includes Node/RBAC
- 1.2.16: audit-log-path set
- 1.2.25: client-ca-file set

**Worker Node (Kubelet):**
- 4.2.1: anonymous-auth = false
- 4.2.2: authorization-mode ≠ AlwaysAllow
- 4.2.4: readOnlyPort = 0
- 4.2.14: seccomp-default = true

**Policies:**
- 5.1.3: Minimize wildcards in Roles
- 5.2.1: Container privilege restrictions
- 5.3.2: NetworkPolicies for namespaces

### Appendix D: MITRE ATT&CK Mapping

| KubePulse Finding | MITRE Technique | ID |
|-------------------|-----------------|-----|
| Privileged Container | Exploitation for Privilege Escalation | T1068 |
| hostPID Abuse | Process Injection | T1055 |
| hostNetwork + Metadata | Cloud Metadata API | T1550.005 |
| ServiceAccount Token | Steal Application Access Token | T1528 |
| RBAC Wildcards | Account Manipulation | T1098 |
| hostPath Escape | Container Escape | T1611 |
| Missing NetworkPolicy | Unsecured Credentials | T1552 |

---

## Success Metrics

- [ ] **Performance:** Scan 1000 pods in < 30 seconds
- [ ] **Accuracy:** < 5% false positive rate
- [ ] **Coverage:** 50+ security checks
- [ ] **Integration:** kubectl plugin, GitHub Action
- [ ] **Documentation:** Every finding has CWE, MITRE, remediation

---

*Spec complete. Ready for implementation. Save to `/Users/main/Security Apps/KubePulse/SPEC.md`?*