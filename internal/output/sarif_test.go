package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/sarnas-it/guardrail/internal/engine"
	"github.com/sarnas-it/guardrail/internal/rules"
)

func TestWriteSARIFStructure(t *testing.T) {
	rs, err := rules.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	fs := []engine.Finding{
		{RuleID: "aws_access_key", Category: rules.CategorySecret, Severity: rules.SeverityBlock, File: "a.txt", Line: 3, Value: "AKIAIOSFODNN7EXAMPLE", Fingerprint: "fp"},
	}
	var buf bytes.Buffer
	if err := WriteSARIF(&buf, fs, rs, false); err != nil {
		t.Fatal(err)
	}
	var doc map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	runs := doc["runs"].([]interface{})
	if len(runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(runs))
	}
	run := runs[0].(map[string]interface{})
	results := run["results"].([]interface{})
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	res := results[0].(map[string]interface{})
	if res["ruleId"] != "aws_access_key" {
		t.Fatalf("unexpected ruleId %v", res["ruleId"])
	}
	if res["level"] != "error" {
		t.Fatalf("expected level error for block secret, got %v", res["level"])
	}
	msg := res["message"].(map[string]interface{})["text"].(string)
	if strings.Contains(msg, "AKIAIOSFODNN7EXAMPLE") {
		t.Fatal("SARIF message must not include raw secret")
	}
}
