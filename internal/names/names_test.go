package names

import (
	"os"
	"path/filepath"
	"testing"
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

func TestLoadAndClassify(t *testing.T) {
	dir := writeDicts(t, map[string]string{
		"surnames.txt":    "иванов\nпетров\n",
		"given.txt":       "иван\nпётр\nмария\n",
		"patronymics.txt": "иванович\nпетровна\n",
	})
	s, err := Load(dir, "surnames.txt", "given.txt", "patronymics.txt", "", 2, 4)
	if err != nil {
		t.Fatal(err)
	}
	if !s.Active() {
		t.Fatal("expected active set")
	}
	if c := s.Classify("иванов"); c&Surname == 0 {
		t.Fatal("иванов must be a surname")
	}
	if c := s.Classify("иван"); c&GivenName == 0 {
		t.Fatal("иван must be a given name")
	}
	if c := s.Classify("иванович"); c&Patronymic == 0 {
		t.Fatal("иванович must be a patronymic")
	}
	if c := s.Classify("ИВАНОВ"); c&Surname == 0 {
		t.Fatal("normalization must lowercase")
	}
	if c := s.Classify("apple"); c != 0 {
		t.Fatal("unknown token must classify as none")
	}
}

func TestLoadMissingFileIsError(t *testing.T) {
	dir := writeDicts(t, map[string]string{"surnames.txt": "иванов\n"})
	if _, err := Load(dir, "surnames.txt", "given.txt", "patronymics.txt", "", 2, 4); err == nil {
		t.Fatal("expected error for missing referenced file")
	}
}

func TestLoadEmptyIsInactive(t *testing.T) {
	dir := writeDicts(t, map[string]string{
		"surnames.txt":    "иванов\n",
		"given.txt":       "иван\n",
		"patronymics.txt": "",
	})
	s, err := Load(dir, "surnames.txt", "given.txt", "patronymics.txt", "", 2, 4)
	if err != nil {
		t.Fatal(err)
	}
	if s.Active() {
		t.Fatal("all categories must be non-empty for active set")
	}
}

func TestExclusions(t *testing.T) {
	dir := writeDicts(t, map[string]string{
		"surnames.txt":    "каренин\n",
		"given.txt":       "анна\n",
		"patronymics.txt": "иванович\n",
		"exclusions.txt":  "анна каренина\n",
	})
	s, err := Load(dir, "surnames.txt", "given.txt", "patronymics.txt", "exclusions.txt", 2, 4)
	if err != nil {
		t.Fatal(err)
	}
	if !s.IsExcluded("Анна Каренина") {
		t.Fatal("exclusion must match normalized phrase")
	}
	if s.IsExcluded("анна") {
		t.Fatal("partial phrase must not match")
	}
}
