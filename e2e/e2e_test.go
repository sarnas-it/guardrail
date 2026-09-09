package e2e

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sarnas-it/guardrail/internal/config"
	"github.com/sarnas-it/guardrail/internal/engine"
	"github.com/sarnas-it/guardrail/internal/names"
	"github.com/sarnas-it/guardrail/internal/rules"
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

func initRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	gitCmd(t, dir, "init", "-q")
	gitCmd(t, dir, "config", "user.email", "t@example.com")
	gitCmd(t, dir, "config", "user.name", "Test")
	gitCmd(t, dir, "config", "commit.gpgsign", "false")
	return dir
}

func commitFile(t *testing.T, dir, name, content, msg string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	gitCmd(t, dir, "add", ".")
	gitCmd(t, dir, "commit", "-qm", msg)
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

func headSHA(t *testing.T, dir string) string {
	t.Helper()
	return strings.TrimSpace(gitCmd(t, dir, "rev-parse", "HEAD"))
}

const leaksFile = `// demo leaks — по одному образцу на каждое правило
aws = "AKIAIOSFODNN7EXAMPLE"
gcp = "AIzaAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
gh = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
slack = "xoxb-123456789012345678901234"
tg = "1234567890:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
pem = "-----BEGIN RSA PRIVATE KEY-----"
jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.signature1"
db = "postgres://admin:secret123@db.internal:5432/prod"
token = "sk_9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0"
phone = "+7 999 123-45-67"
email = "user@example.com"
inn = "ИНН 7707083893"
snils = "СНИЛС 123-456-789 01"
passport = "паспорт 4507 123456"
full_name = "Иванов Иван Иванович"
`

var expectedRuleIDs = map[string]bool{
	"aws_access_key": true, "google_api_key": true, "github_token": true,
	"slack_token": true, "telegram_bot_token": true, "private_key_pem": true,
	"jwt_token": true, "db_connection_string": true, "generic_api_key": true,
	"phone_ru": true, "email": true, "inn_ru": true, "snils_ru": true,
	"passport_ru": true, "full_name_ru": true,
}

func TestE2EAllRulesFound(t *testing.T) {
	dir := initRepo(t)
	commitFile(t, dir, "clean.txt", "just text\n", "base")

	ndir := writeDicts(t, map[string]string{
		"surnames.txt":    "иванов\n",
		"given.txt":       "иван\n",
		"patronymics.txt": "иванович\n",
	})
	cfg := config.Default()
	cfg.Names.SurnamesFile = filepath.Join(ndir, "surnames.txt")
	cfg.Names.GivenNamesFile = filepath.Join(ndir, "given.txt")
	cfg.Names.PatronymicsFile = filepath.Join(ndir, "patronymics.txt")

	commitFile(t, dir, "leaks.go", leaksFile, "leaks")
	head := headSHA(t, dir)
	base := strings.TrimSpace(gitCmd(t, dir, "rev-parse", "HEAD~1"))

	rs, err := rules.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	ns, err := names.Load(ndir, "surnames.txt", "given.txt", "patronymics.txt", "", 2, 4)
	if err != nil {
		t.Fatal(err)
	}

	res, err := engine.Scan(engine.Options{RepoDir: dir, Base: base, Head: head, Cfg: cfg, RS: rs, Names: ns})
	if err != nil {
		t.Fatal(err)
	}

	found := map[string]bool{}
	for _, f := range res.Findings {
		found[f.RuleID] = true
		if f.RuleID != "full_name_ru" {
			want := rules.CategorySecret
			if _, ok := map[string]bool{"phone_ru": true, "email": true, "inn_ru": true, "snils_ru": true, "passport_ru": true, "full_name_ru": true}[f.RuleID]; ok {
				want = rules.CategoryPII
			}
			if f.Category != want {
				t.Fatalf("%s: category = %s, want %s", f.RuleID, f.Category, want)
			}
		}
	}
	for id := range expectedRuleIDs {
		if !found[id] {
			t.Errorf("missing finding for rule %s", id)
		}
	}
	for id := range found {
		if !expectedRuleIDs[id] {
			t.Errorf("unexpected finding for rule %s", id)
		}
	}
}

func TestE2ENegativeSimilarButNotLeak(t *testing.T) {
	dir := initRepo(t)
	commitFile(t, dir, "clean.txt", "plain\n", "base")
	ndir := writeDicts(t, map[string]string{
		"surnames.txt":    "каренин\nкаренина\n",
		"given.txt":       "анна\n",
		"patronymics.txt": "иванович\n",
		"exclusions.txt":  "анна каренина\n",
	})
	notLeaks := `maybe = "AKIA" /* неполный ключ — нет 16 символов */
phone_like = "999 123-45-67" /* без +7/8 — не телефон по правилу */
title = "Анна Каренина" /* в exclusions */
`
	commitFile(t, dir, "not_leaks.txt", notLeaks, "not-leaks")
	head := headSHA(t, dir)
	base := strings.TrimSpace(gitCmd(t, dir, "rev-parse", "HEAD~1"))
	rs, err := rules.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	ns, err := names.Load(ndir, "surnames.txt", "given.txt", "patronymics.txt", "exclusions.txt", 2, 4)
	if err != nil {
		t.Fatal(err)
	}
	res, err := engine.Scan(engine.Options{RepoDir: dir, Base: base, Head: head, Cfg: config.Default(), RS: rs, Names: ns})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range res.Findings {
		switch f.RuleID {
		case "aws_access_key", "full_name_ru":
			t.Errorf("unexpected finding %s in %s", f.RuleID, f.File)
		}
	}
}
