package rules

import (
	"os"
	"path/filepath"
	"testing"
)

func writeRuleFile(t *testing.T, name, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestLoadFSAcceptsDictionaryRule(t *testing.T) {
	dir := writeRuleFile(t, "x.yaml", `
rules:
  - id: full_name_ru
    category: pii
    severity: warn
    description: Russian full name
    type: dictionary
`)
	rs, err := LoadFS(os.DirFS(dir))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	r, ok := rs.Get("full_name_ru")
	if !ok {
		t.Fatal("rule not loaded")
	}
	if r.Type != RuleTypeDictionary {
		t.Fatalf("expected dictionary type, got %q", r.Type)
	}
	if r.Regex != nil {
		t.Fatal("dictionary rule must not compile a regex")
	}
}

func TestLoadFSRejectsRegexOnDictionaryRule(t *testing.T) {
	dir := writeRuleFile(t, "x.yaml", `
rules:
  - id: bad
    category: pii
    severity: warn
    description: bad
    type: dictionary
    regex: "abc"
`)
	if _, err := LoadFS(os.DirFS(dir)); err == nil {
		t.Fatal("expected error for regex field on dictionary rule")
	}
}

func TestLoadFSRejectsBadType(t *testing.T) {
	dir := writeRuleFile(t, "x.yaml", `
rules:
  - id: bad
    category: pii
    severity: warn
    description: bad
    type: wizard
`)
	if _, err := LoadFS(os.DirFS(dir)); err == nil {
		t.Fatal("expected error for unknown type")
	}
}

func TestLoadFSRejectsBadSeverity(t *testing.T) {
	dir := writeRuleFile(t, "x.yaml", `
rules:
  - id: bad
    category: secret
    severity: nope
    regex: "abc"
`)
	rs, err := LoadFS(os.DirFS(dir))
	if err == nil {
		t.Fatal("expected error for invalid severity")
	}
	if rs != nil {
		t.Fatal("expected nil ruleset on error")
	}
}

func TestLoadFSRejectsBadRegex(t *testing.T) {
	dir := writeRuleFile(t, "x.yaml", `
rules:
  - id: badre
    category: secret
    severity: block
    regex: "(unclosed"
`)
	rs, err := LoadFS(os.DirFS(dir))
	if err == nil {
		t.Fatal("expected error for bad regex")
	}
	if rs != nil {
		t.Fatal("expected nil ruleset on error")
	}
}

func TestLoadFSCompilesRules(t *testing.T) {
	dir := writeRuleFile(t, "x.yaml", `
rules:
  - id: ok
    category: secret
    severity: block
    description: ok rule
    regex: "AKIA[0-9A-Z]{16}"
    keywords: [secret, token]
    entropy_min: 3.0
`)
	rs, err := LoadFS(os.DirFS(dir))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	r, ok := rs.Get("ok")
	if !ok {
		t.Fatal("rule ok not loaded")
	}
	if r.Category != CategorySecret || r.Severity != SeverityBlock {
		t.Fatalf("wrong meta: %+v", r)
	}
	if len(r.Keywords) != 2 || r.EntropyMin != 3.0 {
		t.Fatalf("wrong fields: %+v", r)
	}
	if r.Regex == nil || !r.Regex.MatchString("AKIAABCDEFGHIJKLMNOP") {
		t.Fatal("regex not compiled")
	}
}

func TestLoadDefaultHasSecretAndPIIRules(t *testing.T) {
	rs, err := LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := rs.Get("aws_access_key"); !ok {
		t.Fatal("secrets.yaml: aws_access_key missing")
	}
	if _, ok := rs.Get("phone_ru"); !ok {
		t.Fatal("pii.yaml: phone_ru missing")
	}
}
