package git

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

func makeRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	gitCmd(t, dir, "init", "-q")
	gitCmd(t, dir, "config", "user.email", "t@example.com")
	gitCmd(t, dir, "config", "user.name", "Test")
	gitCmd(t, dir, "config", "commit.gpgsign", "false")
	if err := os.WriteFile(filepath.Join(dir, "ok.txt"), []byte("fine line\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitCmd(t, dir, "add", ".")
	gitCmd(t, dir, "commit", "-qm", "base")
	return dir
}

func TestAddedLines(t *testing.T) {
	dir := makeRepo(t)
	// Добавим секрет вторым коммитом.
	if err := os.WriteFile(filepath.Join(dir, "config.yml"), []byte("token: xoxb-1234567890-abcdef\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitCmd(t, dir, "add", ".")
	gitCmd(t, dir, "commit", "-qm", "leak")
	head := strings.TrimSpace(gitCmd(t, dir, "rev-parse", "HEAD"))
	base := strings.TrimSpace(gitCmd(t, dir, "rev-parse", "HEAD~1"))

	r := New(dir)
	lines, err := r.AddedLines(base, head)
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 1 {
		t.Fatalf("expected 1 added line, got %d: %+v", len(lines), lines)
	}
	if lines[0].Path != "config.yml" || lines[0].Line != 1 {
		t.Fatalf("bad added line: %+v", lines[0])
	}
	if got := lines[0].Text; got != "token: xoxb-1234567890-abcdef" {
		t.Fatalf("unexpected text %q", got)
	}
}

func TestBlobSizeAndRevExists(t *testing.T) {
	dir := makeRepo(t)
	r := New(dir)
	if !r.RevExists("HEAD") {
		t.Fatal("HEAD should exist")
	}
	if r.RevExists("deadbeef") {
		t.Fatal("deadbeef should not exist")
	}
	sz, err := r.BlobSize("HEAD", "ok.txt")
	if err != nil {
		t.Fatal(err)
	}
	if sz <= 0 {
		t.Fatalf("expected positive size, got %d", sz)
	}
}
