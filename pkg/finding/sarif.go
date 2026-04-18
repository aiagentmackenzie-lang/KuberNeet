package finding

import (
	"encoding/json"
	"fmt"
	"os"
)

// SARIFDocument represents the SARIF output format for GitHub Code Scanning
type SARIFDocument struct {
	Schema  string `json:"$schema"`
	Version string `json:"version"`
	Runs    []Run  `json:"runs"`
}

type Run struct {
	Tool    Tool      `json:"tool"`
	Results []Result  `json:"results"`
}

type Tool struct {
	Driver DriverInfo `json:"driver"`
}

type DriverInfo struct {
	Name            string          `json:"name"`
	Version         string          `json:"version"`
	InformationURI  string          `json:"informationUri"`
	Rules           []SARIFRule     `json:"rules"`
}

type SARIFRule struct {
	ID   string      `json:"id"`
	Name string      `json:"name"`
	Help HelpInfo    `json:"help"`
	Properties Properties `json:"properties,omitempty"`
}

type HelpInfo struct {
	Text string `json:"text"`
	Markdown string `json:"markdown,omitempty"`
}

type Properties struct {
	CWE     string `json:"cwe,omitempty"`
	MITRE   string `json:"mitre,omitempty"`
	Severity string `json:"severity,omitempty"`
}

type Result struct {
	RuleID    string         `json:"ruleId"`
	Message   Message        `json:"message"`
	Locations []Location     `json:"locations"`
}

type Message struct {
	Text string `json:"text"`
}

type Location struct {
	PhysicalLocation PhysicalLocation `json:"physicalLocation"`
}

type PhysicalLocation struct {
	ArtifactLocation ArtifactLocation `json:"artifactLocation"`
	Region           Region           `json:"region"`
}

type ArtifactLocation struct {
	URI string `json:"uri"`
}

type Region struct {
	StartLine int `json:"startLine"`
}

// ToSARIF converts findings to SARIF format
func ToSARIF(findings []Finding, version string) (*SARIFDocument, error) {
	// Build unique rules
	ruleMap := make(map[string]SARIFRule)
	for _, f := range findings {
		ruleMap[f.ID] = SARIFRule{
			ID:   f.ID,
			Name: f.Title,
			Help: HelpInfo{
				Text:     f.Message + "\n\n" + f.Description,
				Markdown: "**" + f.Title + "**\n\n" + f.Message + "\n\n" + f.Description,
			},
			Properties: Properties{
				CWE:     f.CWE,
				MITRE:   f.MITRE,
				Severity: f.Severity,
			},
		}
	}

	// Convert to slice
	rules := []SARIFRule{}
	for _, rule := range ruleMap {
		rules = append(rules, rule)
	}

	// Build results
	results := []Result{}
	for _, f := range findings {
		results = append(results, Result{
			RuleID: f.ID,
			Message: Message{
				Text: f.Message,
			},
			Locations: []Location{{
				PhysicalLocation: PhysicalLocation{
					ArtifactLocation: ArtifactLocation{
						URI: fmt.Sprintf("k8s://%s/%s/%s", f.ResourceKind, f.Namespace, f.ResourceName),
					},
					Region: Region{StartLine: 1},
				},
			}},
		})
	}

	sarif := &SARIFDocument{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []Run{{
			Tool: Tool{
				Driver: DriverInfo{
					Name:           "KuberNeet",
					Version:        version,
					InformationURI: "https://github.com/raphael/kuberneet",
					Rules:          rules,
				},
			},
			Results: results,
		}},
	}

	return sarif, nil
}

// SARIFOutput exports findings to SARIF format (stdout)
func SARIFOutput(findings []Finding, withRemedy bool) error {
	sarif, err := ToSARIF(findings, "0.1.0")
	if err != nil {
		return err
	}

	data, err := json.MarshalIndent(sarif, "", "  ")
	if err != nil {
		return err
	}

	fmt.Printf("%s\n", data)
	return nil
}

// SARIFFile writes SARIF output to a file
func SARIFFile(findings []Finding, version, filepath string) error {
	sarif, err := ToSARIF(findings, version)
	if err != nil {
		return err
	}

	data, err := json.MarshalIndent(sarif, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filepath, data, 0644)
}
