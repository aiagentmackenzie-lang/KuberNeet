# KuberNeet Bug Catalog

**Date:** 2026-05-17
**Auditor:** Agent Mackenzie (Lead Code Quality Checker)
**Baseline:** Tests 23/23 passing, go vet clean, staticcheck finds 5 issues

---

## Summary

| Severity | Count |
|----------|-------|
| HIGH     | 3     |
| MEDIUM   | 11    |
| LOW      | 2     |
| **Total** | **16** |

---

## HIGH

### H-01: Webhook scanner nil → blocks all deployments
**File:** `cmd/webhook.go`, `pkg/admission/server.go`
**Issue:** When scanner.New() fails (no kubeconfig), scanner is nil. validatePod/validateDeployment return 503 "Scanner unavailable: cannot validate pod security", blocking ALL pod/deployment creation, even benign ones. Should allow through with a warning when scanner is unavailable.
**Fix:** Return `Allowed: true` with a warning message when scanner is nil.

### H-02: Admission webhook uses string literals for severity comparison
**File:** `pkg/admission/server.go`
**Issue:** Compares `f.Severity == "CRITICAL"` and `f.Severity == "HIGH"` as string literals instead of using `finding.Critical`/`finding.High` constants. Fragile and inconsistent.
**Fix:** Import and use `finding.Critical` and `finding.High`.

### H-03: HTML report XSS vulnerability
**File:** `pkg/report/html.go`
**Issue:** Findings JSON is injected into HTML via `string(graphJSON)` etc. without escaping. Kubernetes resource names or finding messages containing `<script>` or `"` would execute in the browser.
**Fix:** Use `json.Marshal` with HTML-safe escaping or use `html.EscapeString` on injected values. Use template.HTML for safe embedding.

---

## MEDIUM

### M-04: OPA engine uses deprecated packages
**File:** `pkg/opa/engine.go`
**Issue:** Uses deprecated `github.com/open-policy-agent/opa/ast` and `github.com/open-policy-agent/opa/rego`. Should migrate to `github.com/open-policy-agent/opa/v1` equivalents.
**Fix:** Migrate imports to OPA v1 API.

### M-05: Unused helper functions in scanner_test.go
**File:** `pkg/scanner/scanner_test.go`
**Issue:** `intPtr` and `strPtr` are unused (flagged by staticcheck).
**Fix:** Remove unused functions.

### M-06: Unused verbose field in scanOptions
**File:** `cmd/scan.go`
**Issue:** `scanOptions.verbose` field is set by cobra but never read (the global `verbose` from root.go is used instead).
**Fix:** Remove the field from scanOptions struct.

### M-07: shouldInclude drops unknown severities
**File:** `pkg/scanner/scanner.go`
**Issue:** If a finding has severity not in the map (typo or new level), `shouldInclude` returns `0 >= threshold` which is false for any threshold, silently dropping the finding.
**Fix:** Default unknown severities to "always include" or map them to a minimum level.

### M-08: CompilePoliciesToDisk misses subdirectory policies
**File:** `pkg/opa/engine.go`
**Issue:** `CompilePoliciesToDisk` only iterates top-level `policies/` entries, not `policies/pod/` or `policies/rbac/`. Most Rego policies (escapes.rego, wildcards.rego) are silently dropped.
**Fix:** Add subdirectory iteration matching the `NewEngine` pattern.

### M-09: Federation NodeCount never populated
**File:** `pkg/federation/federation.go`
**Issue:** `scanCluster` creates `ScanResult` but never sets `NodeCount`. The field is always 0 and is exposed in JSON output.
**Fix:** Populate `NodeCount` from cluster node list.

### M-10: Watch mode only watches pods
**File:** `cmd/watch.go`
**Issue:** Only pod informer is set up. README advertises real-time watch but no deployment, RBAC, or network policy watching.
**Fix:** Add deployment and RBAC informers (at minimum). Mark as partial fix — network policy informer is future work.

### M-11: BuildService doesn't create edges to pods
**File:** `pkg/graph/graph.go`
**Issue:** `BuildService` creates the service node but never adds edges from service to pods matching its selector. The `traceToPrivilegedPod` method tries to match by labels but there's no edge to follow.
**Fix:** After building all pods and services, add edges from services to matching pods.

### M-12: Admission webhook missing size limit on request body
**File:** `pkg/admission/server.go`
**Issue:** `io.ReadAll(r.Body)` without size limit. A malicious request could send an enormous body, causing OOM.
**Fix:** Use `io.LimitReader(r.Body, maxBodySize)` with a 1MB limit.

### M-13: SARIFOutput ignores withRemedy parameter
**File:** `pkg/finding/sarif.go`
**Issue:** `SARIFOutput` accepts `withRemedy` but never uses it. Remediation data is always included in help text.
**Fix:** Conditionally include remediation based on `withRemedy`.

### M-14: Report --html flag defaults to true, can't be disabled
**File:** `cmd/report.go`
**Issue:** `--html` defaults to `true`, making it impossible to generate a non-HTML report via the flag. The `report` command should support format selection.
**Fix:** Change to a `--format` string flag supporting `html` and `json`.

---

## LOW

### L-15: README source file count inaccuracy
**File:** `README.md`
**Issue:** Says "25 Go source files" but there are 24. Says "~4,900 LOC" which is accurate at 4,909.
**Fix:** Update to "24 Go source files".

### L-16: getSeverityColor return type inconsistency
**File:** `cmd/scan.go`
**Issue:** `getSeverityColor` returns `func(string, ...interface{}) string` but is only used with a single string argument. Works but unusual.
**Fix:** Simplify to return `func(...interface{}) string` matching the color package API. No functional impact.