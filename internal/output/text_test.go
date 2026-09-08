package output

import (
	"bytes"
	"strings"
	"testing"

	"github.com/sarnas-it/guardrail/internal/engine"
	"github.com/sarnas-it/guardrail/internal/rules"
)

func TestWriteTextCounts(t *testing.T) {
	fs := []engine.Finding{
		{RuleID: "aws_access_key", Category: rules.CategorySecret, Severity: rules.SeverityBlock, File: "a.txt", Line: 3, Value: "AKIAIOSFODNN7EXAMPLE", Fingerprint: "x"},
		{RuleID: "phone_ru", Category: rules.CategoryPII, Severity: rules.SeverityWarn, File: "a.txt", Line: 4, Value: "+7 999 123-45-67", Fingerprint: "y"},
	}
	var buf bytes.Buffer
	block, warn := WriteText(&buf, fs, false)
	if block != 1 || warn != 1 {
		t.Fatalf("expected block=1 warn=1, got block=%d warn=%d", block, warn)
	}
	out := buf.String()
	if strings.Contains(out, "AKIAIOSFODNN7EXAMPLE") {
		t.Fatal("secret must be masked in output")
	}
	if strings.Contains(out, "+7 999 123-45-67") {
		t.Fatal("PII must be masked in output")
	}
	if !strings.Contains(out, "aws_access_key") || !strings.Contains(out, "a.txt:3") {
		t.Fatalf("missing context in output:\n%s", out)
	}
}

func TestWriteTextReveal(t *testing.T) {
	fs := []engine.Finding{
		{RuleID: "aws_access_key", Category: rules.CategorySecret, Severity: rules.SeverityBlock, File: "a.txt", Line: 3, Value: "AKIAIOSFODNN7EXAMPLE", Fingerprint: "x"},
	}
	var buf bytes.Buffer
	WriteText(&buf, fs, true)
	if !strings.Contains(buf.String(), "AKIAIOSFODNN7EXAMPLE") {
		t.Fatal("reveal must print full value")
	}
}
