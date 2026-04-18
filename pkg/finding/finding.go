package finding

import (
	"encoding/json"
	"fmt"

	"gopkg.in/yaml.v3"
)

const (
	Critical = "CRITICAL"
	High     = "HIGH"
	Medium   = "MEDIUM"
	Low      = "LOW"
	Info     = "INFO"
)

type Finding struct {
	ID            string                 `json:"id" yaml:"id"`
	Severity      string                 `json:"severity" yaml:"severity"`
	Message       string                 `json:"message" yaml:"message"`
	Description   string                 `json:"description,omitempty" yaml:"description,omitempty"`
	ResourceKind  string                 `json:"resource_kind" yaml:"resource_kind"`
	ResourceName  string                 `json:"resource_name" yaml:"resource_name"`
	Namespace     string                 `json:"namespace,omitempty" yaml:"namespace,omitempty"`
	CWE           string                 `json:"cwe,omitempty" yaml:"cwa,omitempty"`
	MITRE         string                 `json:"mitre,omitempty" yaml:"mitre,omitempty"`
	Remediation   string                 `json:"remediation,omitempty" yaml:"remediation,omitempty"`
	AttackPath    []string               `json:"attack_path,omitempty" yaml:"attack_path,omitempty"`
	RawResource   map[string]interface{} `json:"-" yaml:"-"`
}

type ScanResult struct {
	ScanID      string    `json:"scan_id" yaml:"scan_id"`
	Findings    []Finding `json:"findings" yaml:"findings"`
	TotalCount  int       `json:"total_count" yaml:"total_count"`
	Critical    int       `json:"critical" yaml:"critical"`
	High        int       `json:"high" yaml:"high"`
	Medium      int       `json:"medium" yaml:"medium"`
	Low         int       `json:"low" yaml:"low"`
	ScanTime    string    `json:"scan_time" yaml:"scan_time"`
	ClusterInfo string    `json:"cluster_info" yaml:"cluster_info"`
}

func JSONOutput(findings []Finding, withRemedy bool) error {
	result := buildResult(findings)
	output, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(output))
	return nil
}

func YAMLOutput(findings []Finding, withRemedy bool) error {
	result := buildResult(findings)
	output, err := yaml.Marshal(result)
	if err != nil {
		return err
	}
	fmt.Println(string(output))
	return nil
}

func buildResult(findings []Finding) ScanResult {
	result := ScanResult{
		Findings: findings,
		ScanID:   generateScanID(),
	}

	for _, f := range findings {
		result.TotalCount++
		switch f.Severity {
		case Critical:
			result.Critical++
		case High:
			result.High++
		case Medium:
			result.Medium++
		case Low:
			result.Low++
		}
	}

	return result
}

func generateScanID() string {
	return fmt.Sprintf("kuberneet-%d", len(findings)*1000+len(findings))
}

var findings []Finding
