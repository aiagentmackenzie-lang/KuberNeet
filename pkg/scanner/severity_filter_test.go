package scanner

import (
	"testing"

	"github.com/raphael/kuberneet/pkg/finding"
)

func TestShouldInclude(t *testing.T) {
	tests := []struct {
		findingSev string
		filterSev  string
		expected   bool
	}{
		{finding.Critical, finding.Critical, true},
		{finding.High, finding.Critical, false},
		{finding.High, finding.High, true},
		{finding.Medium, finding.High, false},
		{finding.Medium, finding.Medium, true},
		{finding.Low, finding.Medium, false},
		{finding.Low, finding.Low, true},
		{finding.Info, finding.Low, false},
		{finding.Info, finding.Info, true},
		// Unknown severity defaults to MEDIUM (2)
		{"UNKNOWN", finding.High, false},
		{"UNKNOWN", finding.Medium, true},
		{"UNKNOWN", finding.Low, true},
		// Unknown filter shows all
		{finding.Critical, "UNKNOWN", true},
		{finding.Low, "UNKNOWN", true},
		// Empty filter shows all
		{finding.Critical, "", true},
		{finding.Low, "", true},
	}

	for _, tt := range tests {
		t.Run(tt.findingSev+"_"+tt.filterSev, func(t *testing.T) {
			result := shouldInclude(tt.findingSev, tt.filterSev)
			if result != tt.expected {
				t.Errorf("shouldInclude(%s, %s) = %v, want %v", tt.findingSev, tt.filterSev, result, tt.expected)
			}
		})
	}
}