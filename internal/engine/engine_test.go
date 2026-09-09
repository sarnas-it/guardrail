package engine

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sarnas-it/guardrail/internal/config"
	"github.com/sarnas-it/guardrail/internal/git"
	"github.com/sarnas-it/guardrail/internal/names"
	"github.com/sarnas-it/guardrail/internal/rules"
)

func TestIsPathIgnored(t *testing.T) {
	cfg := config.Default()
	cfg.Ignore.Paths = []string{"vendor/**", "testdata/**"}
	cfg.Scan.ExtraIgnoredPaths = []string{"docs/private/**"}

	for _, p := range []string{"vendor/a/b.go", "testdata/fix.go", "docs/private/x.txt", "go.sum"} {
		if !IsPathIgnored(cfg, p) {
			t.Fatalf("expected %q ignored", p)
		}
	}
	for _, p := range []string{"src/main.go", "internal/x/y.go"} {
		if IsPathIgnored(cfg, p) {
			t.Fatalf("expected %q NOT ignored", p)
		}
	}
}

func TestAllowedMatch(t *testing.T) {
	cfg := config.Default()
	cfg.Ignore.Matches = []config.IgnoreMatch{
		{Rule: "phone_ru", Path: "internal/tests/fixtures.go", Line: 10, Reason: "fixture"},
	}
	fp := Fingerprint("phone_ru", "internal/tests/fixtures.go", "+7 999 123-45-67")
	f := Finding{RuleID: "phone_ru", File: "internal/tests/fixtures.go", Line: 10, Fingerprint: fp}

	if !IsAllowed(cfg, f) {
		t.Fatal("line+path match should be allowed")
	}
	f.Line = 11
	if IsAllowed(cfg, f) {
		t.Fatal("line 11 should NOT be allowed (allowlist on line 10)")
	}
}

func TestAllowedByFingerprint(t *testing.T) {
	cfg := config.Default()
	fp := Fingerprint("phone_ru", "internal/tests/fixtures.go", "+7 999 123-45-67")
	cfg.Ignore.Matches = []config.IgnoreMatch{
		{Rule: "phone_ru", Fingerprint: fp, Reason: "known test value"},
	}
	f := Finding{RuleID: "phone_ru", File: "internal/tests/fixtures.go", Line: 42, Fingerprint: fp}
	if !IsAllowed(cfg, f) {
		t.Fatal("fingerprint match should be allowed")
	}
}

func gitCmd(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return string(out)
}

func makeScanRepo(t *testing.T) (dir string, base, head string) {
	t.Helper()
	dir = t.TempDir()
	gitCmd(t, dir, "init", "-q")
	gitCmd(t, dir, "config", "user.email", "t@example.com")
	gitCmd(t, dir, "config", "user.name", "Test")
	gitCmd(t, dir, "config", "commit.gpgsign", "false")
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitCmd(t, dir, "add", ".")
	gitCmd(t, dir, "commit", "-qm", "base")
	base = strings.TrimSpace(gitCmd(t, dir, "rev-parse", "HEAD"))

	leaks := `aws = "AKIAIOSFODNN7EXAMPLE"
phone = "+7 999 123-45-67"
`
	if err := os.WriteFile(filepath.Join(dir, "leaks.txt"), []byte(leaks), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "go.sum"), []byte("noise==sha1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitCmd(t, dir, "add", ".")
	gitCmd(t, dir, "commit", "-qm", "leak")
	head = strings.TrimSpace(gitCmd(t, dir, "rev-parse", "HEAD"))
	return dir, base, head
}

func TestScanFindsSecretAndPII(t *testing.T) {
	dir, base, head := makeScanRepo(t)
	rs, err := rules.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	res, err := Scan(Options{RepoDir: dir, Base: base, Head: head, Cfg: config.Default(), RS: rs})
	if err != nil {
		t.Fatal(err)
	}
	var hasSecret, hasPII bool
	for _, f := range res.Findings {
		if f.RuleID == "aws_access_key" && f.Category == rules.CategorySecret {
			hasSecret = true
		}
		if f.RuleID == "phone_ru" && f.Category == rules.CategoryPII {
			hasPII = true
		}
		if f.File == "go.sum" {
			t.Fatalf("go.sum must be ignored, got finding %+v", f)
		}
	}
	if !hasSecret || !hasPII {
		t.Fatalf("expected secret and PII findings, got %+v", res.Findings)
	}
}

func TestScanSeverityOverrideToWarnAndAllowlist(t *testing.T) {
	dir, base, head := makeScanRepo(t)
	rs, err := rules.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Severity["aws_access_key"] = "warn"
	cfg.Ignore.Matches = []config.IgnoreMatch{
		{Rule: "phone_ru", Path: "leaks.txt", Line: 2, Reason: "fixture"},
	}
	res, err := Scan(Options{RepoDir: dir, Base: base, Head: head, Cfg: cfg, RS: rs})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range res.Findings {
		if f.RuleID == "aws_access_key" && f.Severity != rules.SeverityWarn {
			t.Fatalf("expected aws_access_key downgraded to warn, got %s", f.Severity)
		}
		if f.RuleID == "phone_ru" {
			t.Fatalf("phone_ru should be allowlisted, got %+v", f)
		}
	}
	if res.Allowed != 1 {
		t.Fatalf("expected 1 allowed finding, got %d", res.Allowed)
	}
}

func writeDicts(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestScanFindsFullNameWhenNamesConfigured(t *testing.T) {
	dir, base, head := makeScanRepo(t)
	// допишем в тот же репо строку с ФИО
	if err := os.WriteFile(filepath.Join(dir, "person.txt"), []byte("name = Иванов Иван Иванович\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitCmd(t, dir, "add", ".")
	gitCmd(t, dir, "commit", "-qm", "person")
	head = strings.TrimSpace(gitCmd(t, dir, "rev-parse", "HEAD"))

	rs, err := rules.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	ndir := writeDicts(t, map[string]string{
		"surnames.txt":    "иванов\n",
		"given.txt":       "иван\n",
		"patronymics.txt": "иванович\n",
	})
	ns, err := names.Load(ndir, "surnames.txt", "given.txt", "patronymics.txt", "", 2, 4)
	if err != nil {
		t.Fatal(err)
	}
	res, err := Scan(Options{RepoDir: dir, Base: base, Head: head, Cfg: config.Default(), RS: rs, Names: ns})
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, f := range res.Findings {
		if f.RuleID == "full_name_ru" && f.File == "person.txt" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected full_name_ru finding, got %+v", res.Findings)
	}
}

func TestScanNoFullNameWithoutNames(t *testing.T) {
	dir, base, head := makeScanRepo(t)
	if err := os.WriteFile(filepath.Join(dir, "person.txt"), []byte("name = Иванов Иван Иванович\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitCmd(t, dir, "add", ".")
	gitCmd(t, dir, "commit", "-qm", "person")
	head = strings.TrimSpace(gitCmd(t, dir, "rev-parse", "HEAD"))
	rs, err := rules.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	res, err := Scan(Options{RepoDir: dir, Base: base, Head: head, Cfg: config.Default(), RS: rs})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range res.Findings {
		if f.RuleID == "full_name_ru" {
			t.Fatalf("full_name_ru must not fire without names.Set, got %+v", f)
		}
	}
}

// TestScanRootCommit — секрет в КОРНЕВОМ коммите (base = EmptyTree) обязан
// находиться: EmptyTree-ветка диффа должна материализовать дерево и
// отдать все строки репозитория. Закрывает пустоту тестов Task 4.
func TestScanRootCommit(t *testing.T) {
	dir := t.TempDir()
	gitCmd(t, dir, "init", "-q")
	gitCmd(t, dir, "config", "user.email", "t@example.com")
	gitCmd(t, dir, "config", "user.name", "Test")
	gitCmd(t, dir, "config", "commit.gpgsign", "false")

	content := `aws = "AKIAIOSFODNN7EXAMPLE"
`
	if err := os.WriteFile(filepath.Join(dir, "config.yml"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	gitCmd(t, dir, "add", ".")
	gitCmd(t, dir, "commit", "-qm", "root")
	root := strings.TrimSpace(gitCmd(t, dir, "rev-parse", "HEAD"))

	rs, err := rules.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	res, err := Scan(Options{RepoDir: dir, Base: git.EmptyTree, Head: root, Cfg: config.Default(), RS: rs})
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, f := range res.Findings {
		if f.RuleID == "aws_access_key" && f.File == "config.yml" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected aws_access_key finding in root commit, got %+v", res.Findings)
	}
}
