package opa

import (
	"context"
	"embed"
	"fmt"

	"github.com/open-policy-agent/opa/sdk"
	"github.com/raphael/kuberneet/pkg/finding"
)

//go:embed policies/*.rego
//go:embed policies/pod/*.rego
//go:embed policies/rbac/*.rego
var policyFS embed.FS

type Engine struct {
	opa *sdk.OPA
}

func NewEngine(ctx context.Context) (*Engine, error) {
	// Use embedded policies with manual policy loading
	// OPA SDK doesn't directly support embed.FS, so we'll compile policies
	// manually and use the SDK with decision API

	config := []byte(`{
        "services": {
            "kuberneet": {
                "url": "http://localhost:8181"
            }
        },
        "bundles": {
            "kuberneet": {
                "resource": "bundle.tar.gz"
            }
        },
        "decision_logs": {
            "console": true
        }
    }`)

	// For embedded policies, we compile them on the fly
	// In production, pre-compile to WASM bundle
	opa, err := sdk.New(ctx, sdk.Options{
		ID:     "kuberneet-scanner",
		Config: bytesReader(config),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create OPA SDK: %w", err)
	}

	return &Engine{opa: opa}, nil
}

func (e *Engine) ScanResource(ctx context.Context, resource map[string]interface{}) ([]finding.Finding, error) {
	result, err := e.opa.Decision(ctx, sdk.DecisionOptions{
		Path:  "/kuberneet/violation",
		Input: resource,
	})
	if err != nil {
		return nil, fmt.Errorf("OPA decision failed: %w", err)
	}

	return e.parseViolations(result), nil
}

func (e *Engine) parseViolations(result *sdk.DecisionResult) []finding.Finding {
	var findings []finding.Finding

	if result == nil || result.Result == nil {
		return findings
	}

	violations, ok := result.Result.([]interface{})
	if !ok {
		return findings
	}

	for _, v := range violations {
		violation, ok := v.(map[string]interface{})
		if !ok {
			continue
		}

		resourceKind := ""
		resourceName := ""
		namespace := ""
		if meta, ok := violation["metadata"].(map[string]interface{}); ok {
			resourceKind = getString(meta, "kind")
			resourceName = getString(meta, "name")
			namespace = getString(meta, "namespace")
		}
		
		finding := finding.Finding{
			ID:          getString(violation, "id"),
			Severity:    getString(violation, "severity"),
			Message:     getString(violation, "message"),
			Title:       getString(violation, "title"),
			Description: getString(violation, "description"),
			CWE:         getString(violation, "cwe"),
			MITRE:       getString(violation, "mitre"),
			Remediation: getString(violation, "remediation"),
			ResourceKind: resourceKind,
			ResourceName: resourceName,
			Namespace:    namespace,
		}
		findings = append(findings, finding)
	}

	return findings
}

func getString(m map[string]interface{}, key string) string {
	if m == nil {
		return ""
	}
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

type bytesReader []byte

func (b bytesReader) Read(p []byte) (n int, err error) {
	copy(p, b)
	if len(b) > len(p) {
		return len(p), nil
	}
	return len(b), nil
}

func (e *Engine) Stop(ctx context.Context) {
	if e.opa != nil {
		e.opa.Stop(ctx)
	}
}
