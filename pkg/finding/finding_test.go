package finding

import (
	"os"
	"testing"
)

func TestFilterRemediation(t *testing.T) {
	findings := []Finding{
		{ID: "POD-001", Severity: Critical, Message: "test", Remediation: "fix it"},
		{ID: "POD-002", Severity: High, Message: "test2", Remediation: "fix it 2"},
	}

	t.Run("withRemedy=true keeps remediation", func(t *testing.T) {
		result := filterRemediation(findings, true)
		if len(result) != 2 {
			t.Fatalf("expected 2 findings, got %d", len(result))
		}
		if result[0].Remediation != "fix it" {
			t.Errorf("expected remediation kept, got %q", result[0].Remediation)
		}
	})

	t.Run("withRemedy=false strips remediation", func(t *testing.T) {
		result := filterRemediation(findings, false)
		if len(result) != 2 {
			t.Fatalf("expected 2 findings, got %d", len(result))
		}
		if result[0].Remediation != "" {
			t.Errorf("expected empty remediation, got %q", result[0].Remediation)
		}
	})
}

func TestGenerateScanID(t *testing.T) {
	id1 := generateScanID()
	id2 := generateScanID()

	if id1 == "" {
		t.Error("scan ID should not be empty")
	}
	if id1 == id2 {
		t.Error("scan IDs should be unique")
	}
}

func TestBuildResult(t *testing.T) {
	findings := []Finding{
		{ID: "1", Severity: Critical},
		{ID: "2", Severity: Critical},
		{ID: "3", Severity: High},
		{ID: "4", Severity: Medium},
		{ID: "5", Severity: Low},
	}

	result := buildResult(findings)
	if result.TotalCount != 5 {
		t.Errorf("expected total 5, got %d", result.TotalCount)
	}
	if result.Critical != 2 {
		t.Errorf("expected 2 critical, got %d", result.Critical)
	}
	if result.High != 1 {
		t.Errorf("expected 1 high, got %d", result.High)
	}
	if result.Medium != 1 {
		t.Errorf("expected 1 medium, got %d", result.Medium)
	}
	if result.Low != 1 {
		t.Errorf("expected 1 low, got %d", result.Low)
	}
}

func TestJSONFile(t *testing.T) {
	tmpFile := t.TempDir() + "/test-output.json"
	findings := []Finding{
		{ID: "POD-001", Severity: Critical, Message: "test finding"},
	}

	err := JSONFile(findings, false, tmpFile)
	if err != nil {
		t.Fatalf("JSONFile failed: %v", err)
	}

	data, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("failed to read output file: %v", err)
	}

	if len(data) == 0 {
		t.Error("output file is empty")
	}
}

func TestSARIFFile(t *testing.T) {
	tmpFile := t.TempDir() + "/test-output.sarif"
	findings := []Finding{
		{ID: "POD-001", Severity: Critical, Message: "test finding", ResourceKind: "Pod", ResourceName: "nginx", CWE: "CWE-250"},
	}

	err := SARIFFile(findings, "0.1.0", tmpFile)
	if err != nil {
		t.Fatalf("SARIFFile failed: %v", err)
	}

	data, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("failed to read output file: %v", err)
	}

	if len(data) == 0 {
		t.Error("output file is empty")
	}
}