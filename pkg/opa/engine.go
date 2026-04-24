package opa

import (
	"context"
	"embed"
	"fmt"
	"os"
	"path/filepath"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/raphael/kuberneet/pkg/finding"
)

//go:embed policies/*.rego policies/pod/*.rego policies/rbac/*.rego
var policyFS embed.FS

// Engine evaluates OPA/Rego policies against Kubernetes resources.
type Engine struct {
	preparedQueries map[string]*rego.PreparedEvalQuery
}

// NewEngine creates an OPA engine with embedded Rego policies compiled at init time.
func NewEngine(ctx context.Context) (*Engine, error) {
	e := &Engine{
		preparedQueries: make(map[string]*rego.PreparedEvalQuery),
	}

	// Read all embedded Rego files
	entries, err := policyFS.ReadDir("policies")
	if err != nil {
		return nil, fmt.Errorf("failed to read embedded policies: %w", err)
	}

	var modulePaths []string
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) == ".rego" {
			modulePaths = append(modulePaths, filepath.Join("policies", entry.Name()))
		}
	}

	// Also read subdirectories
	subDirs := []string{"policies/pod", "policies/rbac"}
	for _, dir := range subDirs {
		entries, err := policyFS.ReadDir(dir)
		if err != nil {
			// Subdirectory may not exist — skip
			continue
		}
		for _, entry := range entries {
			if filepath.Ext(entry.Name()) == ".rego" {
				modulePaths = append(modulePaths, filepath.Join(dir, entry.Name()))
			}
		}
	}

	// Build compiler with all modules
	modules := map[string]string{}
	for _, path := range modulePaths {
		data, err := policyFS.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("failed to read policy %s: %w", path, err)
		}
		modules[path] = string(data)
	}

	compiler, err := ast.CompileModules(modules)
	if err != nil {
		return nil, fmt.Errorf("failed to compile Rego policies: %w", err)
	}

	// Prepare the main violation query
	regoQuery := rego.New(
		rego.Query("data.kuberneet.violation"),
		rego.Compiler(compiler),
	)

	pq, err := regoQuery.PrepareForEval(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare OPA query: %w", err)
	}

	e.preparedQueries["violation"] = &pq
	return e, nil
}

// ScanResource evaluates all Rego policies against a Kubernetes resource.
func (e *Engine) ScanResource(ctx context.Context, resource map[string]interface{}) ([]finding.Finding, error) {
	pq, ok := e.preparedQueries["violation"]
	if !ok {
		return nil, fmt.Errorf("OPA engine not initialized")
	}

	rs, err := pq.Eval(ctx, rego.EvalInput(resource))
	if err != nil {
		return nil, fmt.Errorf("OPA evaluation failed: %w", err)
	}

	return e.parseViolations(rs), nil
}

// ScanManifest evaluates Rego policies against a raw YAML manifest string.
func (e *Engine) ScanManifest(ctx context.Context, manifestData map[string]interface{}) ([]finding.Finding, error) {
	return e.ScanResource(ctx, manifestData)
}

func (e *Engine) parseViolations(rs rego.ResultSet) []finding.Finding {
	var findings []finding.Finding

	for _, result := range rs {
		values, ok := result.Expressions[0].Value.([]interface{})
		if !ok {
			continue
		}

		for _, v := range values {
			violation, ok := v.(map[string]interface{})
			if !ok {
				continue
			}

			resourceKind := ""
			resourceName := ""
			namespace := ""
			if meta, ok := violation["metadata"].(map[string]interface{}); ok {
				resourceKind = getStringVal(meta, "kind")
				resourceName = getStringVal(meta, "name")
				namespace = getStringVal(meta, "namespace")
			}

			f := finding.Finding{
				ID:           getStringVal(violation, "id"),
				Severity:     getStringVal(violation, "severity"),
				Title:        getStringVal(violation, "title"),
				Message:      getStringVal(violation, "message"),
				Description:  getStringVal(violation, "description"),
				CWE:          getStringVal(violation, "cwe"),
				MITRE:        getStringVal(violation, "mitre"),
				Remediation:  getStringVal(violation, "remediation"),
				ResourceKind: resourceKind,
				ResourceName: resourceName,
				Namespace:    namespace,
			}
			findings = append(findings, f)
		}
	}

	return findings
}

func getStringVal(m map[string]interface{}, key string) string {
	if m == nil {
		return ""
	}
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

// Stop is a no-op for the compiled engine (satisfies interface expectations).
func (e *Engine) Stop(_ context.Context) {
	// Nothing to stop — we don't use a running OPA server anymore.
}

// PolicyFiles returns the list of embedded Rego policy file paths for diagnostics.
func (e *Engine) PolicyFiles() []string {
	entries, err := policyFS.ReadDir("policies")
	if err != nil {
		return nil
	}
	var files []string
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) == ".rego" {
			files = append(files, filepath.Join("policies", entry.Name()))
		}
	}
	for _, dir := range []string{"policies/pod", "policies/rbac"} {
		subEntries, err := policyFS.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range subEntries {
			if filepath.Ext(entry.Name()) == ".rego" {
				files = append(files, filepath.Join(dir, entry.Name()))
			}
		}
	}
	return files
}

// CompilePoliciesToDisk writes compiled policy bundles to a directory (for OPA SDK usage).
func CompilePoliciesToDisk(outputDir string) error {
	entries, err := policyFS.ReadDir("policies")
	if err != nil {
		return err
	}
	for _, entry := range entries {
		data, err := policyFS.ReadFile(filepath.Join("policies", entry.Name()))
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(outputDir, entry.Name()), data, 0644); err != nil {
			return err
		}
	}
	return nil
}