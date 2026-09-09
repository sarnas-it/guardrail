package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sarnas-it/guardrail/internal/rules"
)

func rs(t *testing.T) *rules.RuleSet {
	t.Helper()
	r, err := rules.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestLoadMissingFileReturnsDefault(t *testing.T) {
	c, err := Load(filepath.Join(t.TempDir(), "nope.yml"), rs(t))
	if err != nil {
		t.Fatal(err)
	}
	if c == nil {
		t.Fatal("expected non-nil default config")
	}
}

func TestLoadUnknownKeyFails(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "guardrail.yml")
	os.WriteFile(path, []byte("nonsense_key: 1\n"), 0o644)
	if _, err := Load(path, rs(t)); err == nil {
		t.Fatal("expected error for unknown key")
	}
}

func TestLoadUnknownRuleInSeverityFails(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "guardrail.yml")
	os.WriteFile(path, []byte("severity:\n  no_such_rule: block\n"), 0o644)
	if _, err := Load(path, rs(t)); err == nil {
		t.Fatal("expected error for unknown rule")
	}
}

func TestLoadBadSeverityValueFails(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "guardrail.yml")
	os.WriteFile(path, []byte("severity:\n  aws_access_key: loud\n"), 0o644)
	if _, err := Load(path, rs(t)); err == nil {
		t.Fatal("expected error for bad severity value")
	}
}

func TestLoadInvalidUntilDateFails(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "guardrail.yml")
	content := `
ignore:
  matches:
    - rule: aws_access_key
      until: "2026-13-99"
      reason: "rotating"
`
	os.WriteFile(path, []byte(content), 0o644)
	if _, err := Load(path, rs(t)); err == nil {
		t.Fatal("expected error for invalid until date")
	}
}

func TestLoadValidUntilDateOK(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "guardrail.yml")
	content := `
ignore:
  matches:
    - rule: aws_access_key
      until: "2026-12-31"
      reason: "rotating"
`
	os.WriteFile(path, []byte(content), 0o644)
	if _, err := Load(path, rs(t)); err != nil {
		t.Fatal(err)
	}
}

func TestLoadEmptyFileReturnsDefault(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "guardrail.yml")
	os.WriteFile(path, []byte(""), 0o644)
	c, err := Load(path, rs(t))
	if err != nil {
		t.Fatal(err)
	}
	if c == nil || c.Severity == nil {
		t.Fatal("expected non-nil default config for empty file")
	}
}

func TestLoadCommentsOnlyReturnsDefault(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "guardrail.yml")
	os.WriteFile(path, []byte("# scaffold\n# enable guardrail later\n"), 0o644)
	c, err := Load(path, rs(t))
	if err != nil {
		t.Fatal(err)
	}
	if c == nil || c.Severity == nil {
		t.Fatal("expected non-nil default config for comments-only file")
	}
}

func TestLoadValidNamesSection(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "guardrail.yml")
	content := `
names:
  min_matches: 3
  window: 5
  surnames_file: data/surnames.txt
  given_names_file: data/given.txt
  patronymics_file: data/patronymics.txt
  exclusions_file: data/exclusions.txt
`
	os.WriteFile(path, []byte(content), 0o644)
	c, err := Load(path, rs(t))
	if err != nil {
		t.Fatal(err)
	}
	if c.Names.MinMatches != 3 || c.Names.Window != 5 {
		t.Fatalf("bad names cfg: %+v", c.Names)
	}
	if c.Names.SurnamesFile != "data/surnames.txt" {
		t.Fatal("surnames_file not parsed")
	}
}

func TestLoadNamesBadMinMatches(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "guardrail.yml")
	os.WriteFile(path, []byte("names:\n  min_matches: 1\n"), 0o644)
	if _, err := Load(path, rs(t)); err == nil {
		t.Fatal("expected error for min_matches 1")
	}
}

func TestLoadNamesUnknownKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "guardrail.yml")
	os.WriteFile(path, []byte("names:\n  full_names_file: x.txt\n"), 0o644)
	if _, err := Load(path, rs(t)); err == nil {
		t.Fatal("expected error for unknown names key")
	}
}

func TestLoadValid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "guardrail.yml")
	content := `
severity:
  aws_access_key: warn
ignore:
  paths:
    - "testdata/**"
  matches:
    - rule: phone_ru
      path: "internal/tests/fixtures.go"
      reason: "test fixtures"
scan:
  max_file_size_kb: 100
output:
  sarif_file: guardrail.sarif
  reveal: true
`
	os.WriteFile(path, []byte(content), 0o644)
	c, err := Load(path, rs(t))
	if err != nil {
		t.Fatal(err)
	}
	if c.Severity["aws_access_key"] != "warn" {
		t.Fatal("severity override not applied")
	}
	if len(c.Ignore.Paths) != 1 || len(c.Ignore.Matches) != 1 {
		t.Fatal("ignore not parsed")
	}
	if c.Scan.MaxFileSizeKB != 100 || !c.Output.Reveal || c.Output.SarifFile != "guardrail.sarif" {
		t.Fatalf("bad scan/output: %+v", c)
	}
}
