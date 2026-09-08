package output

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/sarnas-it/guardrail/internal/engine"
	"github.com/sarnas-it/guardrail/internal/rules"
)

func TestWriteJSON(t *testing.T) {
	fs := []engine.Finding{
		{RuleID: "aws_access_key", Category: rules.CategorySecret, Severity: rules.SeverityBlock, File: "a.txt", Line: 3, Value: "AKIAIOSFODNN7EXAMPLE", Fingerprint: "fp"},
	}
	var buf bytes.Buffer
	if err := WriteJSON(&buf, fs, false); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Findings []jsonFinding `json:"findings"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(doc.Findings))
	}
	if doc.Findings[0].Value == "AKIAIOSFODNN7EXAMPLE" {
		t.Fatal("json must be masked by default")
	}
	if doc.Findings[0].RuleID != "aws_access_key" {
		t.Fatalf("unexpected rule id %q", doc.Findings[0].RuleID)
	}
}
