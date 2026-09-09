package app

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

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

func leakRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	gitCmd(t, dir, "init", "-q")
	gitCmd(t, dir, "config", "user.email", "t@example.com")
	gitCmd(t, dir, "config", "user.name", "Test")
	gitCmd(t, dir, "config", "commit.gpgsign", "false")
	os.WriteFile(filepath.Join(dir, "a.txt"), []byte("hello\n"), 0o644)
	gitCmd(t, dir, "add", ".")
	gitCmd(t, dir, "commit", "-qm", "base")
	os.WriteFile(filepath.Join(dir, "a.txt"), []byte("hello\npassword = AKIAIOSFODNN7EXAMPLE\n"), 0o644)
	gitCmd(t, dir, "add", ".")
	gitCmd(t, dir, "commit", "-qm", "leak")
	return dir
}

func TestRunReturns1OnSecret(t *testing.T) {
	dir := leakRepo(t)
	code, err := Run(dir, "", "", "", "", "", false)
	if err != nil {
		t.Fatal(err)
	}
	if code != 1 {
		t.Fatalf("expected exit code 1, got %d", code)
	}
}

func TestRunReturns0OnClean(t *testing.T) {
	dir := t.TempDir()
	gitCmd(t, dir, "init", "-q")
	gitCmd(t, dir, "config", "user.email", "t@example.com")
	gitCmd(t, dir, "config", "user.name", "Test")
	gitCmd(t, dir, "config", "commit.gpgsign", "false")
	os.WriteFile(filepath.Join(dir, "a.txt"), []byte("just text\n"), 0o644)
	gitCmd(t, dir, "add", ".")
	gitCmd(t, dir, "commit", "-qm", "base")
	os.WriteFile(filepath.Join(dir, "a.txt"), []byte("just text\nmore text\n"), 0o644)
	gitCmd(t, dir, "add", ".")
	gitCmd(t, dir, "commit", "-qm", "more")

	code, err := Run(dir, "", "", "", "", "", false)
	if err != nil {
		t.Fatal(err)
	}
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}
}

func TestRunReturns2OnBrokenConfig(t *testing.T) {
	dir := leakRepo(t)
	cfgPath := filepath.Join(dir, "guardrail.yml")
	os.WriteFile(cfgPath, []byte("unknown: 1\n"), 0o644)
	code, err := Run(dir, "", "", cfgPath, "", "", false)
	if err == nil || code != 2 {
		t.Fatalf("expected error + code 2, got code=%d err=%v", code, err)
	}
}

func TestRunLoadsNamesFromConfigDir(t *testing.T) {
	dir := t.TempDir()
	gitCmd(t, dir, "init", "-q")
	gitCmd(t, dir, "config", "user.email", "t@example.com")
	gitCmd(t, dir, "config", "user.name", "Test")
	gitCmd(t, dir, "config", "commit.gpgsign", "false")
	os.WriteFile(filepath.Join(dir, "a.txt"), []byte("ok\n"), 0o644)
	gitCmd(t, dir, "add", ".")
	gitCmd(t, dir, "commit", "-qm", "base")

	// словари в подпапке data рядом с guardrail.yml
	dataDir := filepath.Join(dir, "data")
	os.MkdirAll(dataDir, 0o755)
	os.WriteFile(filepath.Join(dataDir, "surnames.txt"), []byte("иванов\n"), 0o644)
	os.WriteFile(filepath.Join(dataDir, "given.txt"), []byte("иван\n"), 0o644)
	os.WriteFile(filepath.Join(dataDir, "patronymics.txt"), []byte("иванович\n"), 0o644)
	cfg := "severity: {}\nignore: {}\nnames:\n  surnames_file: data/surnames.txt\n  given_names_file: data/given.txt\n  patronymics_file: data/patronymics.txt\n"
	os.WriteFile(filepath.Join(dir, "guardrail.yml"), []byte(cfg), 0o644)
	os.WriteFile(filepath.Join(dir, "a.txt"), []byte("ok\nname = Иванов Иван Иванович\n"), 0o644)
	gitCmd(t, dir, "add", ".")
	gitCmd(t, dir, "commit", "-qm", "person")

	code, err := Run(dir, "", "", filepath.Join(dir, "guardrail.yml"), "", "", false)
	if err != nil {
		t.Fatal(err)
	}
	if code != 0 {
		t.Fatalf("expected exit 0 (ФИО — warn), got %d", code)
	}
}

func TestRunWritesSarif(t *testing.T) {
	dir := leakRepo(t)
	sarif := filepath.Join(dir, "out.sarif")
	code, err := Run(dir, "", "", "", sarif, "", false)
	if err != nil {
		t.Fatal(err)
	}
	if code != 1 {
		t.Fatalf("expected code 1, got %d", code)
	}
	data, err := os.ReadFile(sarif)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "aws_access_key") {
		t.Fatal("sarif missing aws_access_key rule")
	}
}
