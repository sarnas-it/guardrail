package detect

import (
	"math"
	"testing"

	"github.com/sarnas-it/guardrail/internal/entropy"
	"github.com/sarnas-it/guardrail/internal/rules"
)

func loadDefault(t *testing.T) *rules.RuleSet {
	t.Helper()
	rs, err := rules.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	return rs
}

func TestLineFindsAWSKey(t *testing.T) {
	rs := loadDefault(t)
	line := `aws_access_key_id = "AKIAIOSFODNN7EXAMPLE"`
	ms := Line(rs, line)
	if len(ms) != 1 {
		t.Fatalf("expected 1 match, got %d: %+v", len(ms), ms)
	}
	if ms[0].Rule.ID != "aws_access_key" {
		t.Fatalf("unexpected rule %s", ms[0].Rule.ID)
	}
	if ms[0].Value != "AKIAIOSFODNN7EXAMPLE" {
		t.Fatalf("unexpected value %q", ms[0].Value)
	}
}

func TestLineEntropyFilterRejectsLowEntropy(t *testing.T) {
	rs := loadDefault(t)
	line := `token = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"`
	ms := Line(rs, line)
	for _, m := range ms {
		if m.Rule.ID == "generic_api_key" {
			t.Fatalf("generic_api_key should not match low entropy value")
		}
	}
}

func TestLineKeywordRequired(t *testing.T) {
	rs := loadDefault(t)
	// Высокоэнтропийный токен без ключевого слова рядом — не generic_api_key.
	line := `value := "GkY5tQ9wE1rT7yU2iOpAsDfGhJkLzXcVbN"` // entropy ~4.x
	ms := Line(rs, line)
	for _, m := range ms {
		if m.Rule.ID == "generic_api_key" {
			t.Fatalf("generic_api_key must require keyword context")
		}
	}
}

func TestLinePIIWarn(t *testing.T) {
	rs := loadDefault(t)
	line := `contact_phone = "+7 999 123-45-67"`
	ms := Line(rs, line)
	found := false
	for _, m := range ms {
		if m.Rule.ID == "phone_ru" && m.Rule.Severity == rules.SeverityWarn {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected phone_ru warn match in %q", line)
	}
}

func TestShannonImport(t *testing.T) {
	if got := entropy.Shannon("abc"); math.Abs(got-1.584962500721156) > 1e-9 {
		t.Fatalf("bad entropy value: %v", got)
	}
}
