package finding

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

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
	Title         string                 `json:"title,omitempty" yaml:"title,omitempty"`
	Message       string                 `json:"message" yaml:"message"`
	Description   string                 `json:"description,omitempty" yaml:"description,omitempty"`
	ResourceKind  string                 `json:"resource_kind" yaml:"resource_kind"`
	ResourceName  string                 `json:"resource_name" yaml:"resource_name"`
	Namespace     string                 `json:"namespace,omitempty" yaml:"namespace,omitempty"`
	CWE           string                 `json:"cwe,omitempty" yaml:"cwe,omitempty"`
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
	filtered := filterRemediation(findings, withRemedy)
	result := buildResult(filtered)
	result.ScanTime = time.Now().Format(time.RFC3339)
	output, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(output))
	return nil
}

// JSONFile writes scan results to a JSON file.
func JSONFile(findings []Finding, withRemedy bool, filepath string) error {
	filtered := filterRemediation(findings, withRemedy)
	result := buildResult(filtered)
	result.ScanTime = time.Now().Format(time.RFC3339)
	output, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath, output, 0644)
}

func YAMLOutput(findings []Finding, withRemedy bool) error {
	filtered := filterRemediation(findings, withRemedy)
	result := buildResult(filtered)
	result.ScanTime = time.Now().Format(time.RFC3339)
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
	return fmt.Sprintf("kuberneet-%d", time.Now().UnixNano())
}

// filterRemediation strips remediation fields unless requested.
func filterRemediation(findings []Finding, withRemedy bool) []Finding {
	if withRemedy {
		return findings
	}
	filtered := make([]Finding, len(findings))
	for i, f := range findings {
		f.Remediation = ""
		filtered[i] = f
	}
	return filtered
}
