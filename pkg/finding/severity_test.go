package finding

import (
	"testing"
)

func TestSARIFOutput_WithRemedy(t *testing.T) {
	findings := []Finding{
		{ID: "POD-001", Severity: Critical, Message: "test finding", ResourceKind: "Pod", ResourceName: "nginx", Remediation: "fix it"},
		{ID: "POD-002", Severity: High, Message: "test finding 2", ResourceKind: "Pod", ResourceName: "app", Remediation: "fix it 2"},
	}

	t.Run("withRemedy=true includes remediation", func(t *testing.T) {
		sarif, err := ToSARIF(findings, "0.1.0")
		if err != nil {
			t.Fatalf("ToSARIF failed: %v", err)
		}
		if len(sarif.Runs) == 0 {
			t.Fatal("expected at least one run")
		}
		if len(sarif.Runs[0].Results) != 2 {
			t.Errorf("expected 2 results, got %d", len(sarif.Runs[0].Results))
		}
	})

	t.Run("withRemedy=false strips remediation before SARIF", func(t *testing.T) {
		filtered := filterRemediation(findings, false)
		sarif, err := ToSARIF(filtered, "0.1.0")
		if err != nil {
			t.Fatalf("ToSARIF failed: %v", err)
		}
		for _, rule := range sarif.Runs[0].Tool.Driver.Rules {
			if rule.Help.Text == "" {
				t.Error("rule help text should not be empty")
			}
		}
	})
}