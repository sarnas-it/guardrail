package detect

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sarnas-it/guardrail/internal/names"
	"github.com/sarnas-it/guardrail/internal/rules"
)

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

func fullNameSet(t *testing.T, minMatches, window int) *names.Set {
	t.Helper()
	dir := writeDicts(t, map[string]string{
		"surnames.txt":    "иванов\nпетров\nсидоров\nкаренин\n",
		"given.txt":       "иван\nпётр\nмария\nанна\n",
		"patronymics.txt": "иванович\nпетрович\nалексеевна\n",
		"exclusions.txt":  "анна каренина\n",
	})
	s, err := names.Load(dir, "surnames.txt", "given.txt", "patronymics.txt", "exclusions.txt", minMatches, window)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func dictionaryRule(t *testing.T) *rules.Rule {
	t.Helper()
	rs, err := rules.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	r, ok := rs.Get("full_name_ru")
	if !ok {
		t.Fatal("full_name_ru rule missing")
	}
	return r
}

func TestFullNameFullTriple(t *testing.T) {
	s := fullNameSet(t, 2, 4)
	r := dictionaryRule(t)
	ms := FullName(`customer = {"name": "Иванов Иван Иванович"}`, s, r)
	if len(ms) != 1 {
		t.Fatalf("expected 1 match, got %d: %+v", len(ms), ms)
	}
	if ms[0].Rule.ID != "full_name_ru" {
		t.Fatalf("unexpected rule %s", ms[0].Rule.ID)
	}
	if ms[0].Value != "иванов иван иванович" {
		t.Fatalf("unexpected value %q", ms[0].Value)
	}
}

func TestFullNameTwoCategories(t *testing.T) {
	s := fullNameSet(t, 2, 4)
	r := dictionaryRule(t)
	// имя + фамилия — 2 категории, ловится при min_matches=2.
	ms := FullName(`author = "Петров Пётр"`, s, r)
	if len(ms) != 1 {
		t.Fatalf("expected 1 match, got %d", len(ms))
	}
	if ms[0].Value != "петров пётр" {
		t.Fatalf("unexpected value %q", ms[0].Value)
	}
}

func TestFullNameThresholdThree(t *testing.T) {
	s := fullNameSet(t, 3, 4)
	r := dictionaryRule(t)
	// Только 2 слова — при пороге 3 не срабатывает.
	if ms := FullName(`author = "Петров Пётр"`, s, r); len(ms) != 0 {
		t.Fatalf("expected no match at min_matches=3, got %+v", ms)
	}
	// Полное ФИО срабатывает.
	if ms := FullName(`author = "Иванов Иван Иванович"`, s, r); len(ms) != 1 {
		t.Fatalf("expected match for triple at min_matches=3, got %+v", ms)
	}
}

func TestFullNameExclusion(t *testing.T) {
	s := fullNameSet(t, 2, 4)
	r := dictionaryRule(t)
	// анна(имя) + каренин(фамилия) = 2 категории, но фраза в exclusions.
	if ms := FullName(`title = "Анна Каренина"`, s, r); len(ms) != 0 {
		t.Fatalf("excluded phrase must not match, got %+v", ms)
	}
}

func TestFullNameNonNameTokensSeparate(t *testing.T) {
	s := fullNameSet(t, 2, 4)
	r := dictionaryRule(t)
	// Токены разнесены > window — окно не склеивает их.
	line := `иванов "много шума и текста между" иванович`
	if ms := FullName(line, s, r); len(ms) != 0 {
		t.Fatalf("window must not span far-apart tokens, got %+v", ms)
	}
}

func TestFullNameInactiveSet(t *testing.T) {
	dir := writeDicts(t, map[string]string{"surnames.txt": "иванов\n"})
	s, err := names.Load(dir, "surnames.txt", "", "", "", 2, 4)
	if err != nil {
		t.Fatal(err)
	}
	if s.Active() {
		t.Fatal("single-list set must be inactive")
	}
	if ms := FullName(`x = "Иванов Иван"`, s, dictionaryRule(t)); len(ms) != 0 {
		t.Fatalf("inactive set must not match, got %+v", ms)
	}
}
