# Dictionary-based full-name detection + e2e corpus — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add dictionary-driven Russian full-name detection (`full_name_ru`, PII/warn) to guardrail and prove the whole pipeline with a local `go test ./e2e/` corpus over real git repos covering every rule.

**Architecture:** New rule type flag `type: dictionary` on rules; a new `internal/names` package loads surname/given-name/patronymic/exclusion wordlists from files referenced in `guardrail.yml` (paths relative to the config's directory, no built-in default); a new `detect.FullName(line, set)` does sliding-window token classification (`≥ min_matches` distinct categories within a window) with whole-phrase exclusion matching; `engine.Scan` merges these matches with the existing regex path. `internal/config` grows a validated `names` section. e2e tests drive `engine.Scan` against real git repos.

**Tech Stack:** Go 1.25 stdlib (regexp for tokenization `\p{L}+`, unicode), existing `gopkg.in/yaml.v3`, existing git-CLI runner. No new external deps.

## Global Constraints

- Правило: id `full_name_ru`, category `pii`, severity `warn`, описание «Russian full name (surname + given name + patronymic)», `type: dictionary`.
- Конфиг: секция `names` с ключами `min_matches` (2 или 3, default 2), `window` (≥2, default 4), `surnames_file`, `given_names_file`, `patronymics_file`, `exclusions_file` — все значения-строки (пути), не массивы.
- Нет встроенного дефолта: словари читаются только из подключаемых файлов. Пути резолвятся относительно директории `guardrail.yml`.
- Битый/нечитаемый указанный файл словаря → ошибка (exit 2). Отсутствующий/пустой файл → категория пуста. Все категории пусты или секция отсутствует → `full_name_ru` off, без ошибки.
- Формат файла словаря: одна запись на строку; нормализация — нижний регистр, только буквы; пробелы допустимы только в `exclusions_file` (целые фразы).
- Детекция ФИО построчно (окно не выходит за пределы одной добавленной строки диффа).
- Один токен может принадлежать нескольким категориям (маска складывается).
- Фраза-кандидат нормализуется (нижний регистр); совпадение с exclusion (полная фраза окна) → находка отбрасывается.
- Дубликаты: не более одного Match на (строка, фраза) для full_name_ru.
- Exit-коды, allowlist, fingerprint, маскирование, SARIF/JSON — без изменений; `full_name_ru` обычный PII-warn.
- Имена функций/полей и сообщения коммитов англ., коммиты `feat:`, `test:`, `fix:`, `docs:`.
- Существующие regex-правила не регрессируют: `go test ./...` зелёный.
- Спека: `docs/superpowers/specs/2026-09-09-full-name-dictionary-e2e-design.md`.

---

### Task 1: type-флаг правил + правило full_name_ru в pii.yaml

**Files:**
- Modify: `internal/rules/rules.go` (Rule, fileRule, константы типов)
- Modify: `internal/rules/rulefile.go` (валидация type)
- Modify: `internal/rules/defaults/pii.yaml` (добавить правило)
- Test: `internal/rules/rules_test.go`
- Test: `internal/rules/rulefile_test.go`

**Interfaces:**
- Consumes: существующая структура RuleSet/загрузка.
- Produces:
```go
type RuleType string
const (
	RuleTypeRegex      RuleType = "regex"
	RuleTypeDictionary RuleType = "dictionary"
)

type Rule struct {
	...
	Type        RuleType
}

type fileRule struct {
	...
	Type string `yaml:"type"` // "regex" (default) | "dictionary"
}
```

- [ ] **Step 1: Написать падающие тесты**

Добавить в `internal/rules/rules_test.go`:
```go
func TestRuleTypesConstants(t *testing.T) {
	if RuleTypeRegex != "regex" || RuleTypeDictionary != "dictionary" {
		t.Fatal("rule type constants mismatch")
	}
}
```

В `internal/rules/rulefile_test.go` добавить:
```go
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
```

- [ ] **Step 2: Прогнать — убедиться, что падает**

```bash
cd /home/basili4/GolandProjects/guardrail && go test ./internal/rules/ -run 'TestRuleTypes|TestLoadFS.*[Dd]ictionary|TestLoadFSRejectsBadType' -v
```

Ожидается: compile error — нет поля Type.

- [ ] **Step 3: Добавить тип в `internal/rules/rules.go`**

```go
type RuleType string

const (
	RuleTypeRegex      RuleType = "regex"
	RuleTypeDictionary RuleType = "dictionary"
)
```

В `Rule` добавить поле `Type RuleType`; в `fileRule` добавить `Type string \`yaml:"type"\``.

- [ ] **Step 4: Валидация в `internal/rules/rulefile.go`**

В `parseYAML` перед компиляцией regex обработать type:

```go
rtype := RuleType(fr.Type)
if rtype == "" {
	rtype = RuleTypeRegex
}
if rtype != RuleTypeRegex && rtype != RuleTypeDictionary {
	return fmt.Errorf("%s: rule %q: bad type %q", file, fr.ID, fr.Type)
}
if rtype == RuleTypeDictionary {
	if fr.Regex != "" || len(fr.Keywords) > 0 || fr.EntropyMin > 0 {
		return fmt.Errorf("%s: rule %q: dictionary rule must not set regex/keywords/entropy_min", file, fr.ID)
	}
} else if fr.Regex == "" {
	return fmt.Errorf("%s: rule %q: missing regex", file, fr.ID)
}
```

Ветку «missing regex» для regex-правил оставить только внутри `else if`. При `RuleTypeDictionary` не компилировать regex: `Regex: nil`. При сохранении в `byID` заполнять `Type: rtype`.

- [ ] **Step 5: Добавить full_name_ru в pii.yaml**

`internal/rules/defaults/pii.yaml` — добавить в конец:
```yaml
  - id: full_name_ru
    category: pii
    severity: warn
    description: Russian full name (surname + given name + patronymic)
    type: dictionary
```

- [ ] **Step 6: Прогнать тесты rules**

```bash
cd /home/basili4/GolandProjects/guardrail && go test ./internal/rules/ -v && go build ./... && go vet ./...
```

Ожидается: PASS. `LoadDefault()` компилирует все regex-правила и принимает full_name_ru как dictionary без regex.

- [ ] **Step 7: Коммит**

```bash
cd /home/basili4/GolandProjects/guardrail
git add internal/rules
git commit -m "feat: rule type flag and dictionary full_name_ru rule"
```

---

### Task 2: names.Set — загрузка словарей и классификация токенов

**Files:**
- Create: `internal/names/names.go`
- Create: `internal/names/load.go`
- Test: `internal/names/names_test.go`

**Interfaces:**
- Consumes: `config.Config` (поле `Names`, см. Task 3; здесь тесты создают структуру локально — **Task 3 добавит поле в config, эта задача не зависит от него**).
- Produces:
```go
package names

type Categories int

const (
	Surname Categories = 1 << iota
	GivenName
	Patronymic
)

type Set struct {
	surnames, givenNames, patronymics map[string]struct{}
	exclusions map[string]struct{}
	MinMatches int
	Window     int
	active     bool
}

// Load читает файлы словарей. Пути в cfg резолвятся относительно
// конфиг-директории configDir. Указанный-но-битый файл → error.
// Секция пуста/не задана → активный Set с пустыми словарями (Active()==false).
func Load(configDir string, surnamesFile, givenNamesFile, patronymicsFile, exclusionsFile string, minMatches, window int) (*Set, error)

func (s *Set) Active() bool
func (s *Set) Classify(token string) Categories
func (s *Set) IsExcluded(phrase string) bool
func normalize(s string) string
func readList(path string) (map[string]struct{}, error)
```

- [ ] **Step 1: Написать падающие тесты**

`internal/names/names_test.go`:
```go
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
		"surnames.txt":   "иванов\nпетров\n",
		"given.txt":      "иван\nпётр\nмария\n",
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
```

- [ ] **Step 2: Прогнать — убедиться, что падает**

```bash
cd /home/basili4/GolandProjects/guardrail && go test ./internal/names/ -v
```

Ожидается: compile error (нет пакета).

- [ ] **Step 3: Реализовать `internal/names/names.go`**

```go
package names

type Categories int

const (
	Surname Categories = 1 << iota
	GivenName
	Patronymic
)

type Set struct {
	surnames     map[string]struct{}
	givenNames   map[string]struct{}
	patronymics  map[string]struct{}
	exclusions   map[string]struct{}
	MinMatches   int
	Window       int
	active       bool
}

// Active сообщает, что загружены все три списка (непустые) — только тогда
// правило full_name_ru может срабатывать.
func (s *Set) Active() bool { return s != nil && s.active }

// Classify возвращает битмаску категорий для токена. Пустой/неизвестный → 0.
func (s *Set) Classify(token string) Categories {
	n := normalize(token)
	var c Categories
	if _, ok := s.surnames[n]; ok {
		c |= Surname
	}
	if _, ok := s.givenNames[n]; ok {
		c |= GivenName
	}
	if _, ok := s.patronymics[n]; ok {
		c |= Patronymic
	}
	return c
}

// IsExcluded проверяет нормализованную фразу по списку исключений.
func (s *Set) IsExcluded(phrase string) bool {
	if s == nil {
		return false
	}
	_, ok := s.exclusions[normalize(phrase)]
	return ok
}

// normalize приводит к нижнему регистру и оставляет только буквы.
// Для целых фраз исключений пробелы сохраняются.
func normalize(s string) string {
	runes := make([]rune, 0, len(s))
	inSpace := false
	for _, r := range s {
		switch {
		case r >= 'а' && r <= 'я' || r >= 'А' && r <= 'Я' || r == 'ё' || r == 'Ё':
			if inSpace && len(runes) > 0 {
				runes = append(runes, ' ')
			}
			inSpace = false
			runes = append(runes, toLower(r))
		case r == ' ' || r == '\t':
			inSpace = true
		}
	}
	return string(runes)
}

func toLower(r rune) rune {
	if r >= 'А' && r <= 'Я' {
		return r + ('а' - 'А')
	}
	if r == 'Ё' {
		return 'ё'
	}
	return r
}
```

- [ ] **Step 4: Реализовать `internal/names/load.go`**

```go
package names

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Load читает файлы словарей. configDir — директория guardrail.yml,
// относительно которой резолвятся относительные пути. Пустая строка пути
// означает «категория не задана». Если заданный путь пуст после
// нормализации (пустой файл) категория остаётся пустой.
func Load(configDir, surnamesFile, givenNamesFile, patronymicsFile, exclusionsFile string, minMatches, window int) (*Set, error) {
	if minMatches == 0 {
		minMatches = 2
	}
	if window == 0 {
		window = 4
	}
	s := &Set{
		surnames:    map[string]struct{}{},
		givenNames:  map[string]struct{}{},
		patronymics: map[string]struct{}{},
		exclusions:  map[string]struct{}{},
		MinMatches:  minMatches,
		Window:      window,
	}
	var err error
	if s.surnames, err = readList(resolve(configDir, surnamesFile)); err != nil {
		return nil, fmt.Errorf("surnames_file: %w", err)
	}
	if s.givenNames, err = readList(resolve(configDir, givenNamesFile)); err != nil {
		return nil, fmt.Errorf("given_names_file: %w", err)
	}
	if s.patronymics, err = readList(resolve(configDir, patronymicsFile)); err != nil {
		return nil, fmt.Errorf("patronymics_file: %w", err)
	}
	if s.exclusions, err = readList(resolve(configDir, exclusionsFile)); err != nil {
		return nil, fmt.Errorf("exclusions_file: %w", err)
	}
	s.active = len(s.surnames) > 0 && len(s.givenNames) > 0 && len(s.patronymics) > 0
	return s, nil
}

func resolve(configDir, path string) string {
	if path == "" || filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(configDir, path)
}

// readList читает файл: одна запись на строку, нормализация normalize.
// path == "" → пустой список без ошибки. Несуществующий файл → error.
func readList(path string) (map[string]struct{}, error) {
	out := map[string]struct{}{}
	if path == "" {
		return out, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		n := normalize(line)
		if n != "" {
			out[n] = struct{}{}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
```

- [ ] **Step 5: Прогнать тесты names**

```bash
cd /home/basili4/GolandProjects/guardrail && go test ./internal/names/ -v && go vet ./internal/names/
```

Ожидается: PASS.

- [ ] **Step 6: Коммит**

```bash
cd /home/basili4/GolandProjects/guardrail
git add internal/names
git commit -m "feat: load dictionary wordlists into names.Set"
```

---

### Task 3: Конфиг — секция names с валидацией

**Files:**
- Modify: `internal/config/config.go` (NamesConfig, поле Config.Names, валидация)
- Test: `internal/config/config_test.go`

**Interfaces:**
- Consumes: существующий config.Load/validate.
- Produces:
```go
type NamesConfig struct {
	MinMatches       int    `yaml:"min_matches"`
	Window           int    `yaml:"window"`
	SurnamesFile     string `yaml:"surnames_file"`
	GivenNamesFile   string `yaml:"given_names_file"`
	PatronymicsFile  string `yaml:"patronymics_file"`
	ExclusionsFile   string `yaml:"exclusions_file"`
}

// в Config:
Names NamesConfig `yaml:"names"`
```

- [ ] **Step 1: Написать падающие тесты**

`internal/config/config_test.go` добавить:
```go
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
```

- [ ] **Step 2: Прогнать — падает**

```bash
cd /home/basili4/GolandProjects/guardrail && go test ./internal/config/ -run 'TestLoad.*Names' -v
```

Ожидается: compile error (нет поля Names).

- [ ] **Step 3: Реализовать в `internal/config/config.go`**

Добавить структуру и поле:

```go
type NamesConfig struct {
	MinMatches      int    `yaml:"min_matches"`
	Window          int    `yaml:"window"`
	SurnamesFile    string `yaml:"surnames_file"`
	GivenNamesFile  string `yaml:"given_names_file"`
	PatronymicsFile string `yaml:"patronymics_file"`
	ExclusionsFile  string `yaml:"exclusions_file"`
}
```

В `Config` добавить `Names NamesConfig \`yaml:"names"\``.

В `validate` добавить в конец:
```go
if cfg.Names.MinMatches != 0 && cfg.Names.MinMatches != 2 && cfg.Names.MinMatches != 3 {
	return nil, fmt.Errorf("names.min_matches must be 2 or 3, got %d", cfg.Names.MinMatches)
}
if cfg.Names.Window != 0 && cfg.Names.Window < 2 {
	return nil, fmt.Errorf("names.window must be >= 2, got %d", cfg.Names.Window)
}
```

`Default()` не меняется: нулевые значения = дефолты (2/4) в `names.Load`.

- [ ] **Step 4: Прогнать тесты config**

```bash
cd /home/basili4/GolandProjects/guardrail && go test ./internal/config/ -v && go build ./... && go vet ./...
```

Ожидается: PASS. (KnownFields уже активен — неизвестный ключ `full_names_file` в names будет ошибкой.)

- [ ] **Step 5: Коммит**

```bash
cd /home/basili4/GolandProjects/guardrail
git add internal/config
git commit -m "feat: validate names config section"
```

---

### Task 4: Детектор FullName (окно + категории + exclusions)

**Files:**
- Create: `internal/detect/fullname.go`
- Test: `internal/detect/fullname_test.go`

**Interfaces:**
- Consumes: `names.Set` (Task 2), `rules.Rule` (для сборки Match).
- Produces:
```go
// FullName ищет в строке окна токенов с >= set.MinMatches разными
// категориями имён и возвращает Match{Rule: <правило full_name_ru>,
// Value: <нормализованная фраза>, Start/End}. Не более одного матча на
// строку; nil, если набор не активен или совпадения нет.
func FullName(line string, set *names.Set, rule *rules.Rule) []Match
```

- [ ] **Step 1: Написать падающие тесты**

`internal/detect/fullname_test.go`:
```go
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
		"surnames.txt":   "иванов\nпетров\nсидоров\nкаренин\n",
		"given.txt":      "иван\nпётр\nмария\nанна\n",
		"patronymics.txt": "иванович\nпетрович\nалексеевна\n",
		"exclusions.txt": "анна каренина\n",
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
```

- [ ] **Step 2: Прогнать — падает**

```bash
cd /home/basili4/GolandProjects/guardrail && go test ./internal/detect/ -run TestFullName -v
```

Ожидается: compile error (нет FullName).

- [ ] **Step 3: Реализовать `internal/detect/fullname.go`**

```go
package detect

import (
	"strings"
	"unicode/utf8"

	"github.com/sarnas-it/guardrail/internal/names"
	"github.com/sarnas-it/guardrail/internal/rules"
)

type token struct {
	word      string // нормализованные буквы токена (нижний регистр)
	mask      names.Categories
	byteStart int
	byteEnd   int
}

// FullName ищет в строке окно из set.Window соседних кириллических токенов,
// в котором >= set.MinMatches РАЗЛИЧНЫХ категорий имён представлены как
// минимум двумя разными токенами. Возвращает не более одного Match на строку
// с нормализованной фразой-кандидатом. Возвращает nil, если set не активен
// или совпадения нет.
func FullName(line string, set *names.Set, rule *rules.Rule) []Match {
	if set == nil || !set.Active() {
		return nil
	}
	toks := tokenize(line, set) // все кириллические токены строки
	if len(toks) == 0 {
		return nil
	}
	window := set.Window
	if window < 2 {
		window = 2
	}

	// Ищем первое окно, где набралось >= MinMatches категорий от >= 2 токенов.
	bestStart, bestEnd := -1, -1
	for start := 0; start < len(toks); start++ {
		var union names.Categories
		named := 0
		for end := start; end < len(toks) && end-start < window; end++ {
			if toks[end].mask != 0 {
				named++
			}
			union |= toks[end].mask
			if named >= 2 && popcount(union) >= set.MinMatches {
				bestStart, bestEnd = start, end
				break
			}
		}
		if bestStart >= 0 {
			break
		}
	}
	if bestStart < 0 {
		return nil
	}

	// Сокращаем окно до первой/последней именной границы, оставляя порог.
	first := bestStart
	for first < bestEnd && toks[first].mask == 0 {
		first++
	}
	last := bestEnd
	for last > first && toks[last].mask == 0 {
		last--
	}
	phrase := phraseOf(toks[first : last+1])
	if phrase == "" || set.IsExcluded(phrase) {
		return nil
	}
	return []Match{{
		Rule:  rule,
		Value: phrase,
		Start: toks[first].byteStart,
		End:   toks[last].byteEnd,
	}}
}

// tokenize проходит строку по байтам, выделяя все кириллические
// последовательности букв (служебные слова тоже — они раздвигают окно),
// классифицирует каждую по словарям и запоминает байтовые границы.
func tokenize(line string, set *names.Set) []token {
	var out []token
	i := 0
	for i < len(line) {
		r, size := utf8.DecodeRuneInString(line[i:])
		if !isLetter(r) {
			i += size
			continue
		}
		start := i
		for i < len(line) {
			r, size = utf8.DecodeRuneInString(line[i:])
			if !isLetter(r) {
				break
			}
			i += size
		}
		word := strings.ToLower(line[start:i])
		out = append(out, token{word: word, mask: set.Classify(word), byteStart: start, byteEnd: i})
	}
	return out
}

func isLetter(r rune) bool {
	return r >= 'а' && r <= 'я' || r >= 'А' && r <= 'Я' || r == 'ё' || r == 'Ё'
}

// phraseOf собирает нормализованную фразу (нижний регистр, токены через пробел).
func phraseOf(toks []token) string {
	if len(toks) == 0 {
		return ""
	}
	var b strings.Builder
	for i, t := range toks {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(t.word)
	}
	return b.String()
}

func popcount(c names.Categories) int {
	n := int(c)
	cnt := 0
	for n > 0 {
		cnt += n & 1
		n >>= 1
	}
	return cnt
}
```

Примечание (важное проектное решение, зафиксировано в спеке): условие `named >= 2` (минимум два токена с ненулевой маской) гарантирует, что одно слово, попавшее сразу в два списка (например «Роман» = имя и фамилия), не сработает как ФИО в одиночку.

- [ ] **Step 4: Прогнать тесты FullName**

```bash
cd /home/basili4/GolandProjects/guardrail && go test ./internal/detect/ -run TestFullName -v
```

Ожидается: PASS. Проверить, что кириллица/Ё нормализуется, окно раздвигается служебными словами, exclusions работают.

- [ ] **Step 5: Прогнать весь detect**

```bash
cd /home/basili4/GolandProjects/guardrail && go test ./internal/detect/ -v && go build ./... && go vet ./...
```

Ожидается: PASS (regex-детектор не затронут).

- [ ] **Step 6: Коммит**

```bash
cd /home/basili4/GolandProjects/guardrail
git add internal/detect/fullname.go internal/detect/fullname_test.go
git commit -m "feat: windowed dictionary full-name detector"
```

---

### Task 5: Интеграция в engine + app

**Files:**
- Modify: `internal/engine/engine.go` (Options.Names, вызов FullName)
- Modify: `internal/app/app.go` (загрузка names.Set из конфига)
- Test: `internal/engine/engine_test.go`
- Test: `internal/app/app_test.go`

**Interfaces:**
- Consumes: `names.Set` (Task 2), `config.Names` (Task 3), `detect.FullName` (Task 4).
- Produces:
```go
// engine.Options получает поле:
Names *names.Set // nil → словарный детектор не запускается

// app.Run загружает словари и прокидывает их в engine.Scan.
```

- [ ] **Step 1: Написать падающие тесты**

В `internal/engine/engine_test.go` добавить helper и тест (переиспользуя gitCmd из файла):

```go
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
		"surnames.txt":   "иванов\n",
		"given.txt":      "иван\n",
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
```

Не забыть: в import-блок `engine_test.go` добавить `"github.com/sarnas-it/guardrail/internal/names"` (config/rules/git уже есть; os тоже есть).

В `internal/app/app_test.go` добавить:
```go
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
```

- [ ] **Step 2: Прогнать — падает**

```bash
cd /home/basili4/GolandProjects/guardrail && go test ./internal/engine/ -run 'TestScan.*FullName|TestScanNoFullName' -v
go test ./internal/app/ -run TestRunLoadsNamesFromConfigDir -v
```

Ожидается: compile error (нет поля Names).

- [ ] **Step 3: Интеграция в `internal/engine/engine.go`**

```go
import "github.com/sarnas-it/guardrail/internal/names"
```

В `Options` добавить:
```go
Names *names.Set
```

В `Scan`, перед основным циклом получить правило full_name_ru (nil-safe):

```go
var fullNameRule *rules.Rule
if opts.RS != nil {
	if r, ok := opts.RS.Get("full_name_ru"); ok && r.Type == rules.RuleTypeDictionary {
		fullNameRule = r
	}
}
```

Внутри цикла по `filtered`, сразу после `ms := detect.Line(...)`:

```go
if fullNameRule != nil && opts.Names != nil {
	ms = append(ms, detect.FullName(l.Text, opts.Names, fullNameRule)...)
}
```

Остальной конвейер (severity/allowlist/fingerprint/sort) без изменений.

- [ ] **Step 4: Загрузка словарей в `internal/app/app.go`**

Добавить импорт `"github.com/sarnas-it/guardrail/internal/names"`. Запомнить директорию конфига сразу после успешного `config.Load`:

```go
	cfg := config.Default()
	cfgDir := "."
	if configPath != "" {
		cfgDir = filepath.Dir(abs(configPath))
		cfg, err = config.Load(abs(configPath), rs)
		if err != nil {
			return 2, err
		}
	}
```

(заменить существующий блок `cfg := config.Default() ... if configPath != "" {...}`).

Перед `engine.Scan` загрузить словари:

```go
	var ns *names.Set
	if cfg.Names.SurnamesFile != "" || cfg.Names.GivenNamesFile != "" || cfg.Names.PatronymicsFile != "" {
		ns, err = names.Load(cfgDir,
			cfg.Names.SurnamesFile, cfg.Names.GivenNamesFile,
			cfg.Names.PatronymicsFile, cfg.Names.ExclusionsFile,
			cfg.Names.MinMatches, cfg.Names.Window)
		if err != nil {
			return 2, err
		}
	}
```

В `engine.Options{...}` добавить `Names: ns`.

- [ ] **Step 5: Прогнать тесты engine и app**

```bash
cd /home/basili4/GolandProjects/guardrail && go test ./internal/engine/ ./internal/app/ -v && go build ./... && go vet ./...
```

Ожидается: PASS. ФИО = warn → exit 0 в app-тесте; остальные находки в makeScanRepo дают exit не проверяется здесь.

- [ ] **Step 6: Коммит**

```bash
cd /home/basili4/GolandProjects/guardrail
git add internal/engine/engine.go internal/app/app.go internal/engine/engine_test.go internal/app/app_test.go
git commit -m "feat: wire names.Set through engine and app"
```

---

### Task 6: e2e-корпус по всем правилам

**Files:**
- Create: `e2e/e2e_test.go`
- Create: `e2e/testdata/surnames.txt` и др. словари (или генерируются в тесте — выбран вариант в тесте через writeDicts)

**Interfaces:**
- Consumes: всё (engine.Scan, names, config, rules, git).
- Produces: go-тест `go test ./e2e/`.

- [ ] **Step 1: Написать e2e-тест**

`e2e/e2e_test.go`:
```go
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
		"surnames.txt":    "каренин\n",
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
```

- [ ] **Step 2: Прогнать — падает/проверить**

```bash
cd /home/basili4/GolandProjects/guardrail && go test ./e2e/ -v
```

Разбор: сначала ожидаются несоответствия — это нормально на первом прогоне, цель — довести до зелёного. **Не редактировать правила без анализа**: если негативный тест ловит лишнее — проверить, реальная ли это утечка по текущим правилам; при необходимости поправить образец (не правило), чтобы он был «не-утечкой» по действующей грамматике.

Целевое состояние: позитивный тест находит ВСЕ 15 ruleID; негативный — не находит aws_access_key и full_name_ru (образцы подобраны под действующие правила: `"AKIA"` без 16 символов, `999 123-45-67` без `+7`/`8`, «Анна Каренина» в exclusions).

- [ ] **Step 3: Прогнать весь проект**

```bash
cd /home/basili4/GolandProjects/guardrail && go test ./... && go build ./... && go vet ./...
```

Ожидается: PASS, включая e2e.

- [ ] **Step 4: Коммит**

```bash
cd /home/basili4/GolandProjects/guardrail
git add e2e
git commit -m "test: e2e corpus covering every rule on real git repos"
```

---

## Self-Review

**Спека → план:**
- type-флаг `dictionary` + правило full_name_ru в pii.yaml — Task 1. ✓
- names.Set: файлы словарей, normalize, classify, exclusions, active — Task 2. ✓
- Конфиг names (min_matches/window/файлы), валидация — Task 3. ✓
- Оконный детектор с popcount категорий и exclusions — Task 4. ✓
- Интеграция: engine.Options.Names + вызов FullName; app загружает names из dir(конфиг) — Task 5. ✓
- e2e: все правила + негатив + (allowlist-сценарий покрыт существующим engine-тестом TestScanSeverityOverrideToWarnAndAllowlist; порог 3 и off — в fullname_test Task 4). ✓

**Плейсхолдеры:** отсутствуют; код для каждого шага дан полностью.

**Консистентность типов:**
- `names.Load(configDir, surnames, given, patronymics, exclusions string, minMatches, window int)` — сигнатура едина в Task 2/4/5/6.
- `Set.Active()`, `Set.Classify(token)`, `Set.IsExcluded(phrase)` согласованы.
- `detect.FullName(line string, set *names.Set, rule *rules.Rule) []Match` — едино во всех вызовах.
- `config.Names` поля совпадают с yaml-ключами и с readList.
- `engine.Options.Names *names.Set` — Task 5; при nil словарный детектор не запускается (тесты TestScanNoFullNameWithoutNames).
- Regex-детектор: detect.Line не меняется (защищено Task 4 тестами и существующими).
