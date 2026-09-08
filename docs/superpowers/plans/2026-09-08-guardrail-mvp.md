# Guardrail — сканер секретов и ПДн в CI: план реализации

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Реализовать и опубликовать container action `guardrail`, который при запуске в GitHub Actions клиентского репозитория локально сканирует дифф PR/push на секреты и ПДн РФ, печатает отчёт (лог + SARIF/JSON), маскирует значения и блокирует пайплайн при находках-секретах.

**Architecture:** Go-бинарь в контейнере (alpine + git). CLI получает `base`/`head`, через `git diff --unified=0` собирает добавленные строки изменённых файлов, прогоняет каждую строку через встроенные правила (regex + контекстные ключевые слова + порог энтропии), применяет конфиг `guardrail.yml` (severity, allowlist, исключения путей), дедуплицирует по fingerprint и выдаёт лог/SARIF/JSON. Exit: `0` нет блокирующих, `1` найден секрет, `2` ошибка выполнения. Значения находок маскируются (полное значение только при `reveal`).

**Tech Stack:** Go 1.25, стандартная библиотека (regexp RE2, crypto/sha256, embed), единственная внешняя зависимость `gopkg.in/yaml.v3`, Docker/alpine с git для образа, GitHub Actions для CI.

**Спека:** `docs/superpowers/specs/2026-09-08-guardrail-secret-pii-scanner-design.md` (копия лежит в корне репозитория guardrail).

## Global Constraints

- Код живёт в отдельном репозитории `/home/basili4/GolandProjects/guardrail` (github.com/sarnas-it/guardrail). Все `git`-команды задач выполняются из этой директории.
- Go-модуль: `module github.com/sarnas-it/guardrail`, `go 1.25`.
- Regex — только RE2 из стандартной библиотеки (regexp), без backreferences/lookahead.
- Единственная внешняя зависимость: `gopkg.in/yaml.v3`.
- ПДн-правила имеют `severity: warn`, секрет-правила — `severity: block`. Блокируют только секреты.
- Значения находок в выводе всегда маскируются, кроме случая `reveal: true` в конфиге или `GUARDRAIL_REVEAL=1` в env.
- Неизвестный ключ в `guardrail.yml` и неизвестный `rule` в allowlist — ошибка выполнения (exit 2).
- Exit-коды: `0` — нет блокирующих, `1` — есть секрет, `2` — ошибка выполнения.
- Репозиторий guardrail — публичный.
- Файлы правил по умолчанию: `internal/rules/defaults/secrets.yaml`, `internal/rules/defaults/pii.yaml`, встраиваются в бинарь через `//go:embed`.
- Сообщения коммитов: англ., префиксы `feat:`, `test:`, `fix:`, `docs:`, `chore:`, `ci:`.
- Продакшн sarnas.ru и прод-БД не затрагиваются (проект отдельный).

---

### Task 1: Скелет модуля и CLI-каркас

**Files:**
- Create: `/home/basili4/GolandProjects/guardrail/go.mod`
- Create: `/home/basili4/GolandProjects/guardrail/go.sum`
- Create: `/home/basili4/GolandProjects/guardrail/cmd/guardrail/main.go`
- Create: `/home/basili4/GolandProjects/guardrail/.gitignore`
- Create: `/home/basili4/GolandProjects/guardrail/Makefile`

**Interfaces:**
- Consumes: ничего.
- Produces: бинарь `guardrail` c подкомандой `scan`, функция `run(args []string) int` в `main` (для тестов — `guardrail_main` недоступен, поэтому логику выносим в `internal/app` в Task 12; здесь — только каркас с выводом help).

- [ ] **Step 1: Создать go.mod и модуль**

```bash
cd /home/basili4/GolandProjects/guardrail
go mod init github.com/sarnas-it/guardrail
```

- [ ] **Step 2: Создать .gitignore и Makefile**

`.gitignore`:
```
/guardrail
/dist/
*.sarif
*.test
```

`Makefile`:
```make
.PHONY: build test vet

build:
	go build -o guardrail ./cmd/guardrail

test:
	go test ./...

vet:
	go vet ./...
```

- [ ] **Step 3: Написать каркас main**

`cmd/guardrail/main.go`:
```go
package main

import (
	"fmt"
	"os"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 || args[0] == "scan" {
		fmt.Fprintln(os.Stderr, "guardrail scan --base <sha> --head <sha> [--config guardrail.yml]")
		return 2
	}
	fmt.Fprintf(os.Stderr, "unknown command: %s\n", args[0])
	return 2
}
```

- [ ] **Step 4: Собрать и проверить**

```bash
cd /home/basili4/GolandProjects/guardrail && go build ./... && go vet ./...
```

Ожидается: сборка и vet без ошибок. Логика `run` будет переписана в Task 9; здесь scaffold ради структуры.

- [ ] **Step 5: Коммит**

```bash
cd /home/basili4/GolandProjects/guardrail
git add go.mod go.sum .gitignore Makefile cmd/guardrail/main.go
git commit -m "chore: scaffold guardrail module and CLI skeleton"
```

---

### Task 2: Пакет правил (rules) и встроенные правила

**Files:**
- Create: `internal/rules/rules.go`
- Create: `internal/rules/rulefile.go`
- Create: `internal/rules/defaults/secrets.yaml`
- Create: `internal/rules/defaults/pii.yaml`
- Test: `internal/rules/rules_test.go`
- Test: `internal/rules/rulefile_test.go`

**Interfaces:**
- Produces (используется всеми следующими задачами):
```go
type Category string
const (
	CategorySecret Category = "secret"
	CategoryPII    Category = "pii"
)

type Severity string
const (
	SeverityBlock Severity = "block"
	SeverityWarn  Severity = "warn"
)

type Rule struct {
	ID          string
	Category    Category
	Severity    Severity
	Description string
	Keywords    []string
	EntropyMin  float64
	Regex       *regexp.Regexp
}

type fileRule struct {
	ID          string   `yaml:"id"`
	Category    Category `yaml:"category"`
	Severity    Severity `yaml:"severity"`
	Description string   `yaml:"description"`
	Regex       string   `yaml:"regex"`
	Keywords    []string `yaml:"keywords"`
	EntropyMin  float64  `yaml:"entropy_min"`
}

type fileRules struct {
	Rules []fileRule `yaml:"rules"`
}

type RuleSet struct {
	rules []*Rule
	byID  map[string]*Rule
}

func LoadDefault() (*RuleSet, error)
func (rs *RuleSet) Rules() []*Rule
func (rs *RuleSet) Get(id string) (*Rule, bool)
func (rs *RuleSet) ValidateIDs(ids []string) error
```

- [ ] **Step 1: Написать падающие тесты правил**

`internal/rules/rules_test.go`:
```go
package rules

import "testing"

func TestRuleSetGetAndRules(t *testing.T) {
	rs := &RuleSet{
		rules: []*Rule{{ID: "aws_access_key", Category: CategorySecret, Severity: SeverityBlock}},
		byID:  map[string]*Rule{"aws_access_key": {ID: "aws_access_key"}},
	}
	if _, ok := rs.Get("aws_access_key"); !ok {
		t.Fatal("expected to find aws_access_key")
	}
	if _, ok := rs.Get("nope"); ok {
		t.Fatal("unexpected rule nope")
	}
	if len(rs.Rules()) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rs.Rules()))
	}
}

func TestValidateIDs(t *testing.T) {
	rs := &RuleSet{byID: map[string]*Rule{"a": {ID: "a"}}}
	if err := rs.ValidateIDs([]string{"a"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := rs.ValidateIDs([]string{"b"}); err == nil {
		t.Fatal("expected error for unknown id b")
	}
}
```

- [ ] **Step 2: Запустить тест — убедиться, что падает**

```bash
cd /home/basili4/GolandProjects/guardrail && go test ./internal/rules/ -run 'TestRuleSetGetAndRules|TestValidateIDs' -v
```

Ожидается: compile error — типов нет.

- [ ] **Step 3: Реализовать `internal/rules/rules.go`**

```go
package rules

import (
	"fmt"
	"regexp"
)

type Category string

const (
	CategorySecret Category = "secret"
	CategoryPII    Category = "pii"
)

type Severity string

const (
	SeverityBlock Severity = "block"
	SeverityWarn  Severity = "warn"
)

type Rule struct {
	ID          string
	Category    Category
	Severity    Severity
	Description string
	Keywords    []string
	EntropyMin  float64
	Regex       *regexp.Regexp
}

// fileRule — структура YAML-записи правила в defaults/*.yaml.
type fileRule struct {
	ID          string   `yaml:"id"`
	Category    Category `yaml:"category"`
	Severity    Severity `yaml:"severity"`
	Description string   `yaml:"description"`
	Regex       string   `yaml:"regex"`
	Keywords    []string `yaml:"keywords"`
	EntropyMin  float64  `yaml:"entropy_min"`
}

// fileRules — корневая структура YAML-файла правил.
type fileRules struct {
	Rules []fileRule `yaml:"rules"`
}

type RuleSet struct {
	rules []*Rule
	byID  map[string]*Rule
}

func (rs *RuleSet) Rules() []*Rule        { return rs.rules }
func (rs *RuleSet) Get(id string) (*Rule, bool) {
	r, ok := rs.byID[id]
	return r, ok
}

func (rs *RuleSet) ValidateIDs(ids []string) error {
	for _, id := range ids {
		if _, ok := rs.byID[id]; !ok {
			return fmt.Errorf("unknown rule id %q", id)
		}
	}
	return nil
}
```

- [ ] **Step 4: Прогнать тесты**

```bash
cd /home/basili4/GolandProjects/guardrail && go test ./internal/rules/ -run 'TestRuleSetGetAndRules|TestValidateIDs' -v
```

Ожидается: PASS.

- [ ] **Step 5: Написать падающий тест загрузки правил из файловой системы**

`internal/rules/rulefile_test.go`:
```go
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
```

- [ ] **Step 6: Прогнать — убедиться, что падает**

```bash
cd /home/basili4/GolandProjects/guardrail && go get gopkg.in/yaml.v3 && go test ./internal/rules/ -run 'TestLoadFS|TestLoadDefault' -v
```

Ожидается: compile error — нет `LoadFS`.

- [ ] **Step 7: Реализовать `internal/rules/rulefile.go`**

```go
package rules

import (
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"regexp"
	"sort"

	"gopkg.in/yaml.v3"
)

//go:embed defaults/*.yaml
var defaultFS embed.FS

// LoadDefault загружает и компилирует встроенные правила из defaults/.
func LoadDefault() (*RuleSet, error) {
	return LoadFS(defaultFS)
}

// LoadFS читает все файлы *.yaml из fsys и собирает отсортированный RuleSet.
func LoadFS(fsys fs.FS) (*RuleSet, error) {
	var files []string
	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && filepath.Ext(path) == ".yaml" {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(files)

	rs := &RuleSet{byID: map[string]*Rule{}}
	for _, f := range files {
		data, err := fs.ReadFile(fsys, f)
		if err != nil {
			return nil, err
		}
		if err := rs.parseYAML(f, data); err != nil {
			return nil, err
		}
	}
	rs.rules = rs.byIDList()
	return rs, nil
}

// parseYAML разбирает один файл и добавляет его правила в rs.byID.
func (rs *RuleSet) parseYAML(file string, data []byte) error {
	var fw fileRules
	if err := yaml.Unmarshal(data, &fw); err != nil {
		return fmt.Errorf("%s: %w", file, err)
	}
	for _, fr := range fw.Rules {
		if fr.ID == "" {
			return errors.New(file + ": rule missing id")
		}
		if fr.Category != CategorySecret && fr.Category != CategoryPII {
			return fmt.Errorf("%s: rule %q: bad category %q", file, fr.ID, fr.Category)
		}
		if fr.Severity != SeverityBlock && fr.Severity != SeverityWarn {
			return fmt.Errorf("%s: rule %q: bad severity %q", file, fr.ID, fr.Severity)
		}
		if fr.Regex == "" {
			return fmt.Errorf("%s: rule %q: missing regex", file, fr.ID)
		}
		re, err := regexp.Compile(fr.Regex)
		if err != nil {
			return fmt.Errorf("%s: rule %q: bad regex: %w", file, fr.ID, err)
		}
		if _, dup := rs.byID[fr.ID]; dup {
			return fmt.Errorf("%s: duplicate rule id %q", file, fr.ID)
		}
		rs.byID[fr.ID] = &Rule{
			ID:          fr.ID,
			Category:    fr.Category,
			Severity:    fr.Severity,
			Description: fr.Description,
			Keywords:    fr.Keywords,
			EntropyMin:  fr.EntropyMin,
			Regex:       re,
		}
	}
	return nil
}

// byIDList возвращает правила, отсортированные по ID.
func (rs *RuleSet) byIDList() []*Rule {
	ids := make([]string, 0, len(rs.byID))
	for id := range rs.byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]*Rule, 0, len(ids))
	for _, id := range ids {
		out = append(out, rs.byID[id])
	}
	return out
}
```

Примечание: `TestLoadDefaultHasSecretAndPIIRules` требует файлы `defaults/secrets.yaml` и `defaults/pii.yaml` из Step 8 — до их создания этот тест падает с ошибкой. Порядок шагов ниже это учитывает: сначала Step 8 создаёт файлы, затем Step 9 прогоняет все тесты.

- [ ] **Step 8: Создать встроенные правила**
`internal/rules/defaults/secrets.yaml`:
```yaml
rules:
  - id: aws_access_key
    category: secret
    severity: block
    description: AWS access key ID
    regex: '\bAKIA[0-9A-Z]{16}\b'

  - id: aws_secret_access_key
    category: secret
    severity: block
    description: AWS secret access key (context + entropy)
    regex: '[A-Za-z0-9/+=]{40}'
    keywords: [aws_secret_access_key, secret_access_key, aws_secret]

  - id: google_api_key
    category: secret
    severity: block
    description: Google API key
    regex: 'AIza[0-9A-Za-z_\-]{35}'

  - id: github_token
    category: secret
    severity: block
    description: GitHub personal access token
    regex: 'gh[pousr]_[0-9A-Za-z]{36,255}'

  - id: slack_token
    category: secret
    severity: block
    description: Slack token
    regex: 'xox[baprs]-[0-9A-Za-z\-]{10,72}'

  - id: telegram_bot_token
    category: secret
    severity: block
    description: Telegram bot token
    regex: '[0-9]{8,10}:[A-Za-z0-9_\-]{35}'

  - id: private_key_pem
    category: secret
    severity: block
    description: PEM private key header
    regex: '-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY( BLOCK)?-----'

  - id: jwt_token
    category: secret
    severity: block
    description: JWT token (context)
    regex: 'eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+'
    keywords: [jwt, token, bearer]

  - id: db_connection_string
    category: secret
    severity: block
    description: DB connection string with credentials
    regex: '(postgres(ql)?|mysql|mongodb|redis)://[^:/\s]+:[^@\s]+@[^\s]+'

  - id: generic_api_key
    category: secret
    severity: block
    description: Generic high-entropy key near keyword
    regex: '[A-Za-z0-9_\-]{20,64}'
    keywords: [token, secret, api_key, apikey, password, passwd, client_secret, access_key, private_key, authorization]
    entropy_min: 4.0
```

`internal/rules/defaults/pii.yaml`:
```yaml
rules:
  - id: phone_ru
    category: pii
    severity: warn
    description: Russian phone number
    regex: '(?:\+7|8)\s?\(?\d{3}\)?\s?\d{3}[- ]?\d{2}[- ]?\d{2}'

  - id: email
    category: pii
    severity: warn
    description: E-mail address
    regex: '\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'

  - id: inn_ru
    category: pii
    severity: warn
    description: Russian INN
    regex: '\b\d{10,12}\b'
    keywords: [инн, inn, иин, идентификационный номер]

  - id: snils_ru
    category: pii
    severity: warn
    description: Russian SNILS
    regex: '\b\d{3}[- ]?\d{3}[- ]?\d{3}[- ]?\d{2}\b'

  - id: passport_ru
    category: pii
    severity: warn
    description: Russian passport series and number
    regex: '\b\d{2}\s?\d{2}\s?\d{6}\b'
    keywords: [паспорт, passport, серия, паспортные]
```

- [ ] **Step 9: Прогнать все тесты rules**

```bash
cd /home/basili4/GolandProjects/guardrail && go get gopkg.in/yaml.v3 && go mod tidy && go test ./internal/rules/ -v
```

Ожидается: PASS. `LoadDefault()` загружает и компилирует оба файла.

- [ ] **Step 10: Коммит**

```bash
cd /home/basili4/GolandProjects/guardrail
git add internal/rules go.mod go.sum
git commit -m "feat: rules package with embedded secret and RU-PII rules"
```

---

### Task 3: Энтропия и детектор (detect)

**Files:**
- Create: `internal/entropy/entropy.go`
- Create: `internal/detect/detect.go`
- Test: `internal/entropy/entropy_test.go`
- Test: `internal/detect/detect_test.go`

**Interfaces:**
- Consumes: `rules.RuleSet` из Task 2.
- Produces:
```go
package entropy
func Shannon(s string) float64

package detect

type Match struct {
	Rule  *rules.Rule
	Value string
	Start int
	End   int
}

func Line(rs *rules.RuleSet, line string) []Match
```

- [ ] **Step 1: Написать падающий тест энтропии**

`internal/entropy/entropy_test.go`:
```go
package entropy

import (
	"math"
	"testing"
)

func TestShannonKnownValues(t *testing.T) {
	cases := []struct {
		in   string
		want float64
	}{
		{"aaaa", 0},
		{"ab", 1},
		{"abcd", 2},
	}
	for _, c := range cases {
		got := Shannon(c.in)
		if math.Abs(got-c.want) > 1e-9 {
			t.Fatalf("Shannon(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}
```

- [ ] **Step 2: Прогнать — падает (нет пакета)**

```bash
cd /home/basili4/GolandProjects/guardrail && go test ./internal/entropy/ -v
```

- [ ] **Step 3: Реализовать `internal/entropy/entropy.go`**

```go
package entropy

import "math"

// Shannon возвращает энтропию Шеннона строки в битах на символ.
// Для пустой строки возвращает 0.
func Shannon(s string) float64 {
	if s == "" {
		return 0
	}
	freq := make(map[rune]int)
	for _, r := range s {
		freq[r]++
	}
	n := len([]rune(s))
	var h float64
	for _, c := range freq {
		p := float64(c) / float64(n)
		h -= p * math.Log2(p)
	}
	return h
}
```

- [ ] **Step 4: Прогнать тест энтропии — PASS**

```bash
cd /home/basili4/GolandProjects/guardrail && go test ./internal/entropy/ -v
```

- [ ] **Step 5: Написать падающий тест детектора**

`internal/detect/detect_test.go`:
```go
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
```

- [ ] **Step 6: Прогнать — падает**

```bash
cd /home/basili4/GolandProjects/guardrail && go test ./internal/detect/ -v
```

Ожидается: compile error (нет пакета detect).

- [ ] **Step 7: Реализовать `internal/detect/detect.go`**

```go
package detect

import (
	"strings"

	"github.com/sarnas-it/guardrail/internal/entropy"
	"github.com/sarnas-it/guardrail/internal/rules"
)

type Match struct {
	Rule  *rules.Rule
	Value string
	Start int
	End   int
}

// Line прогоняет одну строку по всем правилам и возвращает находки.
// Дедупликация на уровне одинаковых (rule, span) не выполняется — regex даёт
// непересекающиеся матчи. Порядок: по порядку правил из RuleSet (отсортированы по ID).
func Line(rs *rules.RuleSet, line string) []Match {
	var out []Match
	for _, r := range rs.Rules() {
		if !ruleApplies(r, line) {
			continue
		}
		l := strings.ToLower(line)
		keywordOK := len(r.Keywords) == 0
		if !keywordOK {
			for _, k := range r.Keywords {
				if strings.Contains(l, strings.ToLower(k)) {
					keywordOK = true
					break
				}
			}
		}
		if !keywordOK {
			continue
		}
		for _, loc := range r.Regex.FindAllStringIndex(line, -1) {
			val := line[loc[0]:loc[1]]
			if r.EntropyMin > 0 && entropy.Shannon(val) < r.EntropyMin {
				continue
			}
			out = append(out, Match{Rule: r, Value: val, Start: loc[0], End: loc[1]})
		}
	}
	return out
}

// ruleApplies отсекает правила с пустым regex (в загруженных файлах их нет).
func ruleApplies(r *rules.Rule, line string) bool {
	return r != nil && r.Regex != nil
}
```

- [ ] **Step 8: Прогнать тесты детектора**

```bash
cd /home/basili4/GolandProjects/guardrail && go test ./internal/detect/ -v
```

Ожидается: PASS. Если `generic_api_key` ловит строку из Step 5 теста 3 — поправить regex/энтропию в defaults, проверив значение энтропии.

- [ ] **Step 9: Коммит**

```bash
cd /home/basili4/GolandProjects/guardrail
git add internal/entropy internal/detect
git commit -m "feat: shannon entropy and line detector"
```

---

### Task 4: Git-раннер — дифф добавленных строк

**Files:**
- Create: `internal/git/git.go`
- Create: `internal/git/diff.go`
- Test: `internal/git/diff_test.go`
- Test: `internal/git/git_test.go`

**Interfaces:**
- Produces:
```go
package git

type AddedLine struct {
	Path string
	Line int    // 1-based номер строки в новой версии файла
	Text string
}

type Runner struct{ Dir string }

func New(dir string) *Runner
func (r *Runner) AddedLines(base, head string) ([]AddedLine, error)
func (r *Runner) BlobSize(head, path string) (int64, error)
func (r *Runner) RevExists(rev string) bool

const EmptyTree = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"

func parseDiffHunks(diff []byte) []AddedLine   // чистый парсер unified-диффа, тестируемый без git
func parseNewPath(header string) string        // из "+++ b/path"
```

- [ ] **Step 1: Написать падающий тест парсера диффа**

`internal/git/diff_test.go`:
```go
package git

import "testing"

func TestParseDiffHunks(t *testing.T) {
	diff := `diff --git a/a.txt b/a.txt
index 1111111..2222222 100644
--- a/a.txt
+++ b/a.txt
@@ -1,3 +1,3 @@
 kept line
-old line
+new line
+AKIAIOSFODNN7EXAMPLE added
\ No newline at end of file
`
	lines := parseDiffHunks([]byte(diff))
	if len(lines) != 2 {
		t.Fatalf("expected 2 added lines, got %d: %+v", len(lines), lines)
	}
	if lines[0].Path != "a.txt" || lines[0].Line != 2 {
		t.Fatalf("bad first added line: %+v", lines[0])
	}
	if lines[1].Path != "a.txt" || lines[1].Line != 3 || lines[1].Text != "AKIAIOSFODNN7EXAMPLE added" {
		t.Fatalf("bad second added line: %+v", lines[1])
	}
}

func TestParseDiffHunksNewFile(t *testing.T) {
	diff := `diff --git a/new.txt b/new.txt
new file mode 100644
index 0000000..3333333
--- /dev/null
+++ b/new.txt
@@ -0,0 +1,2 @@
+line one
+line two
`
	lines := parseDiffHunks([]byte(diff))
	if len(lines) != 2 {
		t.Fatalf("expected 2 added lines, got %d: %+v", len(lines), lines)
	}
	if lines[0].Line != 1 || lines[0].Text != "line one" {
		t.Fatalf("bad new-file first line: %+v", lines[0])
	}
	if lines[1].Line != 2 {
		t.Fatalf("bad new-file second line: %+v", lines[1])
	}
}
```

- [ ] **Step 2: Прогнать — падает**

```bash
cd /home/basili4/GolandProjects/guardrail && go test ./internal/git/ -run TestParseDiffHunks -v
```

- [ ] **Step 3: Реализовать `internal/git/diff.go`**

```go
package git

import (
	"bufio"
	"bytes"
	"strconv"
	"strings"
)

type AddedLine struct {
	Path string
	Line int
	Text string
}

// parseDiffHunks разбирает unified-дифф (git diff -U0 --no-color base head)
// и возвращает добавленные строки с номерами строк в новой версии файла.
func parseDiffHunks(diff []byte) []AddedLine {
	var out []AddedLine
	sc := bufio.NewScanner(bytes.NewReader(diff))
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)

	var path string
	var newLine int
	inHunk := false

	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "+++ "):
			path = parseNewPath(line)
		case strings.HasPrefix(line, "@@ "):
			start, ok := parseHunkNewStart(line)
			if !ok {
				continue
			}
			newLine = start
			inHunk = true
		default:
			if !inHunk {
				continue
			}
			switch {
			case strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "+++"):
				out = append(out, AddedLine{Path: path, Line: newLine, Text: strings.TrimPrefix(line, "+")})
				newLine++
			case strings.HasPrefix(line, "-"):
				// удалённые строки не двигают счётчик новой версии
			case strings.HasPrefix(line, "\\"):
				// маркер "No newline at end of file"
			default:
				newLine++
			}
		}
	}
	return out
}

func parseNewPath(header string) string {
	p := strings.TrimSpace(strings.TrimPrefix(header, "+++ "))
	p = strings.TrimPrefix(p, "b/")
	// git может выводить кавычки для спецсимволов; в MVP не декодируем.
	return p
}

// parseHunkNewStart извлекает стартовую строку новой стороны из "@@ -a,b +c,d @@".
func parseHunkNewStart(hunk string) (int, bool) {
	parts := strings.Split(hunk, " ")
	if len(parts) < 3 {
		return 0, false
	}
	newPart := strings.TrimPrefix(parts[2], "+")
	comma := strings.IndexByte(newPart, ',')
	if comma >= 0 {
		newPart = newPart[:comma]
	}
	n, err := strconv.Atoi(newPart)
	if err != nil {
		return 0, false
	}
	return n, true
}
```

- [ ] **Step 4: Прогнать тесты парсера — PASS**

```bash
cd /home/basili4/GolandProjects/guardrail && go test ./internal/git/ -run TestParseDiffHunks -v
```

- [ ] **Step 5: Написать падающий тест Runner на реальном репо**

`internal/git/git_test.go`:
```go
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
```

- [ ] **Step 6: Прогнать — падает**

```bash
cd /home/basili4/GolandProjects/guardrail && go test ./internal/git/ -run 'TestAddedLines|TestBlobSizeAndRevExists' -v
```

Ожидается: compile error — нет пакета `internal/git`.

- [ ] **Step 7: Реализовать `internal/git/git.go`**

```go
package git

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

const EmptyTree = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"

type Runner struct{ Dir string }

func New(dir string) *Runner { return &Runner{Dir: dir} }

func (r *Runner) run(args ...string) ([]byte, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = r.Dir
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("git %v: %w: %s", args, err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

// AddedLines возвращает добавленные строки в диапазоне base..head.
// Используется diff от merge-base(base, head) до head (семантика base...head),
// чтобы сканировать только то, что принёс head. Если merge-base недоступен
// (нет общего предка), падает в diff base..head напрямую.
func (r *Runner) AddedLines(base, head string) ([]AddedLine, error) {
	diff, err := r.threeDotOrTwoDotDiff(base, head)
	if err != nil {
		return nil, err
	}
	return parseDiffHunks(diff), nil
}

func (r *Runner) threeDotOrTwoDotDiff(base, head string) ([]byte, error) {
	if base == EmptyTree {
		// Материализуем пустое дерево в объектной БД (hash-object без -w не хранит).
		if _, err := r.run("hash-object", "-w", "-t", "tree", "/dev/null"); err != nil {
			return nil, err
		}
		return r.run("diff", "--no-color", "-U0", "--no-ext-diff", EmptyTree, head)
	}
	mb, err := r.mergeBase(base, head)
	if err == nil && mb != "" {
		return r.run("diff", "--no-color", "-U0", "--no-ext-diff", mb, head)
	}
	// Нет общего предка — сравниваем напрямую.
	return r.run("diff", "--no-color", "-U0", "--no-ext-diff", base, head)
}

func (r *Runner) mergeBase(a, b string) (string, error) {
	out, err := r.run("merge-base", a, b)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// BlobSize возвращает размер блоба файла в указанной ревизии.
func (r *Runner) BlobSize(head, path string) (int64, error) {
	out, err := r.run("cat-file", "-s", head+":"+path)
	if err != nil {
		return 0, err
	}
	var n int64
	if _, err := fmt.Sscanf(strings.TrimSpace(string(out)), "%d", &n); err != nil {
		return 0, fmt.Errorf("parse size %q: %w", out, err)
	}
	return n, nil
}

// RevExists проверяет существование ревизии (commit/дерева).
func (r *Runner) RevExists(rev string) bool {
	_, err := r.run("rev-parse", "--verify", "--quiet", rev)
	return err == nil
}

// ParentOrEmpty возвращает родителя head, либо EmptyTree для корневого коммита.
func (r *Runner) ParentOrEmpty(head string) (string, error) {
	out, err := r.run("rev-parse", "--verify", "--quiet", head+"^")
	if err == nil {
		return strings.TrimSpace(string(out)), nil
	}
	return EmptyTree, nil
}
```

- [ ] **Step 8: Прогнать тесты git**

```bash
cd /home/basili4/GolandProjects/guardrail && go test ./internal/git/ -v
```

Ожидается: PASS. При необходимости правим тест (нет `strings` import — добавить `strings` в git_test.go).

- [ ] **Step 9: Коммит**

```bash
cd /home/basili4/GolandProjects/guardrail
git add internal/git
git commit -m "feat: git runner collecting added diff lines"
```

---

### Task 5: Конфиг и allowlist

**Files:**
- Create: `internal/config/config.go`
- Create: `internal/glob/glob.go`
- Test: `internal/config/config_test.go`
- Test: `internal/glob/glob_test.go`

**Interfaces:**
- Consumes: `rules.RuleSet` (для ValidateIDs).
- Produces:
```go
package config

type IgnoreMatch struct {
	Rule        string `yaml:"rule"`
	Path        string `yaml:"path"`
	Line        int    `yaml:"line"`
	Fingerprint string `yaml:"fingerprint"`
	Reason      string `yaml:"reason"`
	Until       string `yaml:"until"`
}

type IgnoreConfig struct {
	Paths   []string      `yaml:"paths"`
	Matches []IgnoreMatch `yaml:"matches"`
}

type ScanConfig struct {
	MaxFileSizeKB     int      `yaml:"max_file_size_kb"`
	ExtraIgnoredPaths []string `yaml:"extra_ignored_paths"`
}

type OutputConfig struct {
	SarifFile string `yaml:"sarif_file"`
	Reveal    bool   `yaml:"reveal"`
}

type Config struct {
	Severity map[string]string `yaml:"severity"`
	Ignore   IgnoreConfig      `yaml:"ignore"`
	Scan     ScanConfig        `yaml:"scan"`
	Output   OutputConfig      `yaml:"output"`
}

func Default() *Config
func Load(path string, rs *rules.RuleSet) (*Config, error) // нет файла → Default; невалид → err

package glob
func Match(pattern, name string) bool // поддержка * и ** в путях, '/' разделитель
```

- [ ] **Step 1: Написать падающие тесты glob**

`internal/glob/glob_test.go`:
```go
package glob

import "testing"

func TestMatch(t *testing.T) {
	cases := []struct {
		pattern string
		name    string
		want    bool
	}{
		{"vendor/**", "vendor/foo/bar.go", true},
		{"vendor/**", "vendor/x.go", true},
		{"vendor/**", "src/vendor/x.go", false},
		{"**/*.min.js", "static/app.min.js", true},
		{"**/*.min.js", "static/app.js", false},
		{"*.go", "main.go", true},
		{"*.go", "internal/x/main.go", false},
		{"internal/**", "internal/x/main.go", true},
	}
	for _, c := range cases {
		if got := Match(c.pattern, c.name); got != c.want {
			t.Fatalf("Match(%q, %q) = %v, want %v", c.pattern, c.name, got, c.want)
		}
	}
}
```

- [ ] **Step 2: Прогнать — падает**

```bash
cd /home/basili4/GolandProjects/guardrail && go test ./internal/glob/ -v
```

- [ ] **Step 3: Реализовать `internal/glob/glob.go`**

```go
package glob

import "strings"

// Match сравнивает pattern с именем файла/пути (разделитель '/'),
// поддерживая '*' (в пределах сегмента) и '**' (любое число сегментов).
func Match(pattern, name string) bool {
	return match(strings.Split(pattern, "/"), strings.Split(name, "/"))
}

func match(pat, name []string) bool {
	if len(pat) == 0 {
		return len(name) == 0
	}
	switch pat[0] {
	case "**":
		// ** съедает ноль и более сегментов.
		if match(pat[1:], name) {
			return true
		}
		if len(name) == 0 {
			return false
		}
		return match(pat, name[1:])
	case "*":
		if len(name) == 0 {
			return false
		}
		return match(pat[1:], name[1:])
	default:
		if len(name) == 0 || !segment(pat[0], name[0]) {
			return false
		}
		return match(pat[1:], name[1:])
	}
}

func segment(p, n string) bool {
	return simple(p, n)
}

func simple(p, s string) bool {
	for len(p) > 0 {
		if p[0] == '*' {
			for i := 0; i <= len(s); i++ {
				if simple(p[1:], s[i:]) {
					return true
				}
			}
			return false
		}
		if len(s) == 0 {
			return false
		}
		if p[0] == '?' || p[0] == s[0] {
			p, s = p[1:], s[1:]
			continue
		}
		return false
	}
	return len(s) == 0
}
```

- [ ] **Step 4: Прогнать — PASS**

```bash
cd /home/basili4/GolandProjects/guardrail && go test ./internal/glob/ -v
```

- [ ] **Step 5: Написать падающие тесты конфига**

`internal/config/config_test.go`:
```go
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
```

- [ ] **Step 6: Прогнать — падает**

```bash
cd /home/basili4/GolandProjects/guardrail && go test ./internal/config/ -v
```

- [ ] **Step 7: Реализовать `internal/config/config.go`**

```go
package config

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/sarnas-it/guardrail/internal/rules"
	"gopkg.in/yaml.v3"
)

type IgnoreMatch struct {
	Rule        string `yaml:"rule"`
	Path        string `yaml:"path"`
	Line        int    `yaml:"line"`
	Fingerprint string `yaml:"fingerprint"`
	Reason      string `yaml:"reason"`
	Until       string `yaml:"until"`
}

type IgnoreConfig struct {
	Paths   []string      `yaml:"paths"`
	Matches []IgnoreMatch `yaml:"matches"`
}

type ScanConfig struct {
	MaxFileSizeKB     int      `yaml:"max_file_size_kb"`
	ExtraIgnoredPaths []string `yaml:"extra_ignored_paths"`
}

type OutputConfig struct {
	SarifFile string `yaml:"sarif_file"`
	Reveal    bool   `yaml:"reveal"`
}

type Config struct {
	Severity map[string]string `yaml:"severity"`
	Ignore   IgnoreConfig      `yaml:"ignore"`
	Scan     ScanConfig        `yaml:"scan"`
	Output   OutputConfig      `yaml:"output"`
}

func Default() *Config {
	return &Config{
		Severity: map[string]string{},
	}
}

// Load читает конфиг. Если файла нет — возвращает Default(). Валидирует
// severity-ключи и rule в allowlist по известным правилам. Неизвестные поля
// YAML считаются ошибкой (KnownFields).
func Load(path string, rs *rules.RuleSet) (*Config, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return Default(), nil
	}
	if err != nil {
		return nil, err
	}
	cfg := Default()
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return validate(cfg, rs)
}

func validate(cfg *Config, rs *rules.RuleSet) (*Config, error) {
	var unknown []string
	for id, v := range cfg.Severity {
		if _, ok := rs.Get(id); !ok {
			unknown = append(unknown, id)
		}
		if v != "block" && v != "warn" && v != "off" {
			return nil, fmt.Errorf("severity override for %q must be block|warn|off, got %q", id, v)
		}
	}
	if len(unknown) > 0 {
		return nil, fmt.Errorf("unknown rule id(s) in severity: %s", strings.Join(unknown, ", "))
	}
	for _, m := range cfg.Ignore.Matches {
		if m.Rule == "" {
			return nil, errors.New("ignore.matches entry missing rule")
		}
		if _, ok := rs.Get(m.Rule); !ok {
			return nil, fmt.Errorf("unknown rule id %q in ignore.matches", m.Rule)
		}
	}
	return cfg, nil
}
```

- [ ] **Step 8: Прогнать — PASS**

```bash
cd /home/basili4/GolandProjects/guardrail && go test ./internal/config/ ./internal/glob/ -v
```

- [ ] **Step 9: Коммит**

```bash
cd /home/basili4/GolandProjects/guardrail
git add internal/config internal/glob
git commit -m "feat: guardrail.yml config parsing with strict validation and glob allowlist paths"
```

---

### Task 6: Движок сканирования

**Files:**
- Create: `internal/engine/engine.go`
- Create: `internal/engine/fingerprint.go`
- Create: `internal/engine/ignore.go`
- Test: `internal/engine/engine_test.go`
- Test: `internal/engine/fingerprint_test.go`

**Interfaces:**
- Consumes: `git.Runner`, `rules.RuleSet`, `config.Config`, `detect`, `glob`.
- Produces:
```go
package engine

type Finding struct {
	RuleID      string
	Category    rules.Category
	Severity    rules.Severity
	Description string
	File        string
	Line        int
	Value       string // полное значение (маскируется на выводе)
	Fingerprint string
}

type Options struct {
	RepoDir string
	Base    string
	Head    string
	Cfg     *config.Config
	RS      *rules.RuleSet
	Runner  *git.Runner // если nil — git.New(RepoDir)
}

type Result struct {
	Findings []Finding
	Allowed  int // находок, подавленных allowlist
}

func Scan(opts Options) (*Result, error)

func Fingerprint(ruleID, file string, value string) string

var builtinIgnoredPaths = []string{
	"**/go.sum", "**/package-lock.json", "**/yarn.lock", "**/pnpm-lock.yaml",
	"**/Cargo.lock", "**/composer.lock", "**/Gemfile.lock", "**/poetry.lock",
	"**/*.min.js", "**/*.map", "**/*.svg", "**/*.png", "**/*.jpg",
	"**/*.jpeg", "**/*.gif", "**/*.webp", "**/*.ico", "**/*.woff",
	"**/*.woff2", "**/*.ttf", "**/*.eot",
}
```

- [ ] **Step 1: Написать падающий тест fingerprint**

`internal/engine/fingerprint_test.go`:
```go
package engine

import "testing"

func TestFingerprintStableAndDistinct(t *testing.T) {
	a := Fingerprint("aws_access_key", "x.yml", "AKIAIOSFODNN7EXAMPLE")
	b := Fingerprint("aws_access_key", "x.yml", "AKIAIOSFODNN7EXAMPLE")
	if a != b {
		t.Fatal("fingerprint must be stable")
	}
	c := Fingerprint("aws_access_key", "x.yml", "DIFFERENTVALUE")
	if a == c {
		t.Fatal("different value must differ")
	}
	d := Fingerprint("aws_access_key", "y.yml", "AKIAIOSFODNN7EXAMPLE")
	if a == d {
		t.Fatal("different file must differ")
	}
	if len(a) != 64 {
		t.Fatalf("expected sha256 hex (64), got %d", len(a))
	}
}
```

- [ ] **Step 2: Прогнать — падает**

```bash
cd /home/basili4/GolandProjects/guardrail && go test ./internal/engine/ -run TestFingerprint -v
```

- [ ] **Step 3: Реализовать `internal/engine/fingerprint.go`**

```go
package engine

import (
	"crypto/sha256"
	"encoding/hex"
)

// Fingerprint — sha256(ruleID + "\x00" + file + "\x00" + value) в hex.
func Fingerprint(ruleID, file, value string) string {
	h := sha256.New()
	h.Write([]byte(ruleID))
	h.Write([]byte{0})
	h.Write([]byte(file))
	h.Write([]byte{0})
	h.Write([]byte(value))
	return hex.EncodeToString(h.Sum(nil))
}
```

- [ ] **Step 4: Прогнать fingerprint — PASS**

```bash
cd /home/basili4/GolandProjects/guardrail && go test ./internal/engine/ -run TestFingerprint -v
```

- [ ] **Step 5: Написать падающий тест игнора путей и allowlist**

`internal/engine/engine_test.go` (сначала тесты helpers):
```go
package engine

import (
	"strings"
	"testing"

	"github.com/sarnas-it/guardrail/internal/config"
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
```

- [ ] **Step 6: Прогнать — падает**

```bash
cd /home/basili4/GolandProjects/guardrail && go test ./internal/engine/ -run 'TestIsPathIgnored|TestAllowed' -v
```

- [ ] **Step 7: Реализовать `internal/engine/ignore.go`**

```go
package engine

import (
	"strings"
	"time"

	"github.com/sarnas-it/guardrail/internal/config"
	"github.com/sarnas-it/guardrail/internal/glob"
)

var builtinIgnoredPaths = []string{
	"**/go.sum", "**/package-lock.json", "**/yarn.lock", "**/pnpm-lock.yaml",
	"**/Cargo.lock", "**/composer.lock", "**/Gemfile.lock", "**/poetry.lock",
	"**/*.min.js", "**/*.map", "**/*.svg", "**/*.png", "**/*.jpg",
	"**/*.jpeg", "**/*.gif", "**/*.webp", "**/*.ico", "**/*.woff",
	"**/*.woff2", "**/*.ttf", "**/*.eot",
}

func IsPathIgnored(cfg *config.Config, path string) bool {
	p := strings.TrimPrefix(path, "/")
	for _, pat := range builtinIgnoredPaths {
		if glob.Match(pat, p) {
			return true
		}
	}
	for _, pat := range cfg.Scan.ExtraIgnoredPaths {
		if glob.Match(pat, p) {
			return true
		}
	}
	for _, pat := range cfg.Ignore.Paths {
		if glob.Match(pat, p) {
			return true
		}
	}
	return false
}

// IsAllowed проверяет, попадает ли находка под ignore.matches.
// Записи с until в прошлом считаются неактивными.
func IsAllowed(cfg *config.Config, f Finding) bool {
	for _, m := range cfg.Ignore.Matches {
		if m.Rule != f.RuleID {
			continue
		}
		if m.Until != "" {
			d, err := time.Parse("2006-01-02", m.Until)
			if err == nil && time.Now().After(d.Add(24*time.Hour)) {
				continue
			}
		}
		if m.Fingerprint != "" {
			if m.Fingerprint == f.Fingerprint {
				return true
			}
			continue
		}
		pathOK := m.Path == "" || glob.Match(m.Path, f.File) || m.Path == f.File
		lineOK := m.Line == 0 || m.Line == f.Line
		if pathOK && lineOK {
			return true
		}
	}
	return false
}
```

- [ ] **Step 8: Прогнать helpers — PASS**

```bash
cd /home/basili4/GolandProjects/guardrail && go test ./internal/engine/ -run 'TestIsPathIgnored|TestAllowed' -v
```

- [ ] **Step 9: Написать падающий интеграционный тест Scan на реальном git-репо**

Добавить в `internal/engine/engine_test.go` (в конец файла; в общий import-блок добавить недостающие `os`, `os/exec`, `path/filepath`, `strings`, `github.com/sarnas-it/guardrail/internal/rules` — `config` и `testing` уже импортированы):
```go
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
```

- [ ] **Step 10: Прогнать — падает**

```bash
cd /home/basili4/GolandProjects/guardrail && go test ./internal/engine/ -run 'TestScan' -v
```

Ожидается: compile error (нет Scan).

- [ ] **Step 11: Реализовать `internal/engine/engine.go`**

```go
package engine

import (
	"sort"

	"github.com/sarnas-it/guardrail/internal/config"
	"github.com/sarnas-it/guardrail/internal/detect"
	"github.com/sarnas-it/guardrail/internal/git"
	"github.com/sarnas-it/guardrail/internal/rules"
)

type Finding struct {
	RuleID      string
	Category    rules.Category
	Severity    rules.Severity
	Description string
	File        string
	Line        int
	Value       string
	Fingerprint string
}

type Options struct {
	RepoDir string
	Base    string
	Head    string
	Cfg     *config.Config
	RS      *rules.RuleSet
	Runner  *git.Runner
}

type Result struct {
	Findings []Finding
	Allowed  int
}

func Scan(opts Options) (*Result, error) {
	runner := opts.Runner
	if runner == nil {
		runner = git.New(opts.RepoDir)
	}
	cfg := opts.Cfg
	if cfg == nil {
		cfg = config.Default()
	}

	lines, err := runner.AddedLines(opts.Base, opts.Head)
	if err != nil {
		return nil, err
	}

	// Дропаем строки игнорируемых файлов и слишком больших.
	filtered := make([]git.AddedLine, 0, len(lines))
	for _, l := range lines {
		if IsPathIgnored(cfg, l.Path) {
			continue
		}
		if cfg.Scan.MaxFileSizeKB > 0 {
			sz, err := runner.BlobSize(opts.Head, l.Path)
			if err != nil {
				continue // файл мог быть удалён в head — пропускаем
			}
			if sz > int64(cfg.Scan.MaxFileSizeKB)*1024 {
				continue
			}
		}
		filtered = append(filtered, l)
	}

	seen := map[string]bool{}
	var res Result
	for _, l := range filtered {
		ms := detect.Line(opts.RS, l.Text)
		for _, m := range ms {
			sev := effectiveSeverity(cfg, m.Rule)
			if sev == "" {
				continue
			}
			fp := Fingerprint(m.Rule.ID, l.Path, m.Value)
			if seen[fp] {
				continue
			}
			seen[fp] = true
			f := Finding{
				RuleID:      m.Rule.ID,
				Category:    m.Rule.Category,
				Severity:    sev,
				Description: m.Rule.Description,
				File:        l.Path,
				Line:        l.Line,
				Value:       m.Value,
				Fingerprint: fp,
			}
			if IsAllowed(cfg, f) {
				res.Allowed++
				continue
			}
			res.Findings = append(res.Findings, f)
		}
	}

	sort.Slice(res.Findings, func(i, j int) bool {
		if res.Findings[i].File != res.Findings[j].File {
			return res.Findings[i].File < res.Findings[j].File
		}
		if res.Findings[i].Line != res.Findings[j].Line {
			return res.Findings[i].Line < res.Findings[j].Line
		}
		return res.Findings[i].RuleID < res.Findings[j].RuleID
	})
	return &res, nil
}

// effectiveSeverity возвращает severity правила с учётом конфига:
// "" означает отключено (off).
func effectiveSeverity(cfg *config.Config, r *rules.Rule) rules.Severity {
	if v, ok := cfg.Severity[r.ID]; ok {
		switch v {
		case "block":
			return rules.SeverityBlock
		case "warn":
			return rules.SeverityWarn
		case "off":
			return ""
		}
	}
	return r.Severity
}
```

- [ ] **Step 12: Прогнать тесты engine**

```bash
cd /home/basili4/GolandProjects/guardrail && go test ./internal/engine/ -v
```

Ожидается: PASS.

- [ ] **Step 13: Коммит**

```bash
cd /home/basili4/GolandProjects/guardrail
git add internal/engine
git commit -m "feat: scan engine with severity overrides and allowlist"
```

---

### Task 7: Маскирование и текстовый вывод

**Files:**
- Create: `internal/mask/mask.go`
- Create: `internal/output/text.go`
- Test: `internal/mask/mask_test.go`
- Test: `internal/output/text_test.go`

**Interfaces:**
- Consumes: `engine.Finding`.
- Produces:
```go
package mask
func Secret(s string) string

package output
func WriteText(w io.Writer, findings []engine.Finding, reveal bool) (int, int) // (blockCount, warnCount)
```

- [ ] **Step 1: Написать падающие тесты маски**

`internal/mask/mask_test.go`:
```go
package mask

import "testing"

func TestSecretMask(t *testing.T) {
	if got := Secret("AKIAIOSFODNN7EXAMPLE"); got != "AKIA…MPLE" {
		t.Fatalf("unexpected mask: %q", got)
	}
	if got := Secret("short"); got == "short" {
		t.Fatal("short value must not appear in clear")
	}
	if got := Secret("+7 999 123-45-67"); len(got) > 12 {
		t.Fatalf("mask too long: %q", got)
	}
}
```

- [ ] **Step 2: Прогнать — падает**

```bash
cd /home/basili4/GolandProjects/guardrail && go test ./internal/mask/ -v
```

- [ ] **Step 3: Реализовать `internal/mask/mask.go`**

```go
package mask

import "unicode/utf8"

// Secret маскирует строку: первые 4 и последние 4 руны, между ними '…'.
// Если рун <= 8 — возвращает фиксированный плейсхолдер.
func Secret(s string) string {
	n := utf8.RuneCountInString(s)
	if n <= 8 {
		return "<redacted>"
	}
	runes := []rune(s)
	return string(runes[:4]) + "…" + string(runes[n-4:])
}
```

- [ ] **Step 4: Прогнать — PASS**

```bash
cd /home/basili4/GolandProjects/guardrail && go test ./internal/mask/ -v
```

- [ ] **Step 5: Написать падающие тесты текстового вывода**

`internal/output/text_test.go`:
```go
package output

import (
	"bytes"
	"strings"
	"testing"

	"github.com/sarnas-it/guardrail/internal/engine"
	"github.com/sarnas-it/guardrail/internal/rules"
)

func TestWriteTextCounts(t *testing.T) {
	fs := []engine.Finding{
		{RuleID: "aws_access_key", Category: rules.CategorySecret, Severity: rules.SeverityBlock, File: "a.txt", Line: 3, Value: "AKIAIOSFODNN7EXAMPLE", Fingerprint: "x"},
		{RuleID: "phone_ru", Category: rules.CategoryPII, Severity: rules.SeverityWarn, File: "a.txt", Line: 4, Value: "+7 999 123-45-67", Fingerprint: "y"},
	}
	var buf bytes.Buffer
	block, warn := WriteText(&buf, fs, false)
	if block != 1 || warn != 1 {
		t.Fatalf("expected block=1 warn=1, got block=%d warn=%d", block, warn)
	}
	out := buf.String()
	if strings.Contains(out, "AKIAIOSFODNN7EXAMPLE") {
		t.Fatal("secret must be masked in output")
	}
	if strings.Contains(out, "+7 999 123-45-67") {
		t.Fatal("PII must be masked in output")
	}
	if !strings.Contains(out, "aws_access_key") || !strings.Contains(out, "a.txt:3") {
		t.Fatalf("missing context in output:\n%s", out)
	}
}

func TestWriteTextReveal(t *testing.T) {
	fs := []engine.Finding{
		{RuleID: "aws_access_key", Category: rules.CategorySecret, Severity: rules.SeverityBlock, File: "a.txt", Line: 3, Value: "AKIAIOSFODNN7EXAMPLE", Fingerprint: "x"},
	}
	var buf bytes.Buffer
	WriteText(&buf, fs, true)
	if !strings.Contains(buf.String(), "AKIAIOSFODNN7EXAMPLE") {
		t.Fatal("reveal must print full value")
	}
}
```

- [ ] **Step 6: Прогнать — падает**

```bash
cd /home/basili4/GolandProjects/guardrail && go test ./internal/output/ -v
```

- [ ] **Step 7: Реализовать `internal/output/text.go`**

```go
package output

import (
	"fmt"
	"io"

	"github.com/sarnas-it/guardrail/internal/engine"
	"github.com/sarnas-it/guardrail/internal/mask"
	"github.com/sarnas-it/guardrail/internal/rules"
)

// WriteText печатает находки и возвращает (blockCount, warnCount).
func WriteText(w io.Writer, findings []engine.Finding, reveal bool) (int, int) {
	var block, warn int
	for _, f := range findings {
		val := f.Value
		if !reveal {
			val = mask.Secret(f.Value)
		}
		switch f.Severity {
		case rules.SeverityBlock:
			block++
			fmt.Fprintf(w, "[block] %s: %s:%d: %s (%s)\n", f.RuleID, f.File, f.Line, val, f.Description)
		case rules.SeverityWarn:
			warn++
			fmt.Fprintf(w, "[warn]  %s: %s:%d: %s (%s)\n", f.RuleID, f.File, f.Line, val, f.Description)
		}
	}
	fmt.Fprintf(w, "summary: %d secret(s) [block], %d PII [warn]\n", block, warn)
	return block, warn
}
```

- [ ] **Step 8: Прогнать — PASS**

```bash
cd /home/basili4/GolandProjects/guardrail && go test ./internal/output/ -v
```

- [ ] **Step 9: Коммит**

```bash
cd /home/basili4/GolandProjects/guardrail
git add internal/mask internal/output
git commit -m "feat: value masking and text report"
```

---

### Task 8: SARIF и JSON вывод

**Files:**
- Create: `internal/output/sarif.go`
- Create: `internal/output/json.go`
- Test: `internal/output/sarif_test.go`
- Test: `internal/output/json_test.go`

**Interfaces:**
- Consumes: `engine.Finding`, `mask`.
- Produces:
```go
func WriteSARIF(w io.Writer, findings []engine.Finding, rules *rules.RuleSet, reveal bool) error
func WriteJSON(w io.Writer, findings []engine.Finding, reveal bool) error
```

- [ ] **Step 1: Написать падающие тесты**

`internal/output/sarif_test.go`:
```go
package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/sarnas-it/guardrail/internal/engine"
	"github.com/sarnas-it/guardrail/internal/rules"
)

func TestWriteSARIFStructure(t *testing.T) {
	rs, err := rules.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	fs := []engine.Finding{
		{RuleID: "aws_access_key", Category: rules.CategorySecret, Severity: rules.SeverityBlock, File: "a.txt", Line: 3, Value: "AKIAIOSFODNN7EXAMPLE", Fingerprint: "fp"},
	}
	var buf bytes.Buffer
	if err := WriteSARIF(&buf, fs, rs, false); err != nil {
		t.Fatal(err)
	}
	var doc map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	runs := doc["runs"].([]interface{})
	if len(runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(runs))
	}
	run := runs[0].(map[string]interface{})
	results := run["results"].([]interface{})
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	res := results[0].(map[string]interface{})
	if res["ruleId"] != "aws_access_key" {
		t.Fatalf("unexpected ruleId %v", res["ruleId"])
	}
	if res["level"] != "error" {
		t.Fatalf("expected level error for block secret, got %v", res["level"])
	}
	msg := res["message"].(map[string]interface{})["text"].(string)
	if strings.Contains(msg, "AKIAIOSFODNN7EXAMPLE") {
		t.Fatal("SARIF message must not include raw secret")
	}
}
```

`internal/output/json_test.go`:
```go
package output

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/sarnas-it/guardrail/internal/engine"
	"github.com/sarnas-it/guardrail/internal/rules"
)

func TestWriteJSON(t *testing.T) {
	fs := []engine.Finding{
		{RuleID: "aws_access_key", Category: rules.CategorySecret, Severity: rules.SeverityBlock, File: "a.txt", Line: 3, Value: "AKIAIOSFODNN7EXAMPLE", Fingerprint: "fp"},
	}
	var buf bytes.Buffer
	if err := WriteJSON(&buf, fs, false); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Findings []jsonFinding `json:"findings"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(doc.Findings))
	}
	if doc.Findings[0].Value == "AKIAIOSFODNN7EXAMPLE" {
		t.Fatal("json must be masked by default")
	}
	if doc.Findings[0].RuleID != "aws_access_key" {
		t.Fatalf("unexpected rule id %q", doc.Findings[0].RuleID)
	}
}
```

- [ ] **Step 2: Прогнать — падает**

```bash
cd /home/basili4/GolandProjects/guardrail && go test ./internal/output/ -run 'TestWriteSARIF|TestWriteJSON' -v
```

- [ ] **Step 3: Реализовать SARIF**

`internal/output/sarif.go`:
```go
package output

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/sarnas-it/guardrail/internal/engine"
	"github.com/sarnas-it/guardrail/internal/mask"
	"github.com/sarnas-it/guardrail/internal/rules"
)

type sarifDoc struct {
	Version string    `json:"version"`
	Schema  string    `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string        `json:"name"`
	InformationURI string        `json:"informationUri"`
	Rules          []sarifRule   `json:"rules"`
}

type sarifRule struct {
	ID               string         `json:"id"`
	ShortDescription sarifText      `json:"shortDescription"`
	DefaultConfiguration sarifLevel `json:"defaultConfiguration"`
}

type sarifLevel struct {
	Level string `json:"level"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID    string        `json:"ruleId"`
	Level     string        `json:"level"`
	Message   sarifText     `json:"message"`
	Locations []sarifLoc    `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
}

type sarifLoc struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           sarifRegion   `json:"region"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

func WriteSARIF(w io.Writer, findings []engine.Finding, rs *rules.RuleSet, reveal bool) error {
	doc := sarifDoc{
		Version: "2.1.0",
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Runs:    []sarifRun{{Tool: buildTool(rs)}},
	}
	for _, f := range findings {
		level := "warning"
		if f.Severity == rules.SeverityBlock {
			level = "error"
		}
		val := f.Value
		if !reveal {
			val = mask.Secret(f.Value)
		}
		msg := fmt.Sprintf("[%s] %s: %s", f.Severity, f.RuleID, val)
		doc.Runs[0].Results = append(doc.Runs[0].Results, sarifResult{
			RuleID: f.RuleID,
			Level:  level,
			Message: sarifText{Text: msg},
			PartialFingerprints: map[string]string{"primaryLocationLineHash": f.Fingerprint},
			Locations: []sarifLoc{{
				PhysicalLocation: sarifPhysical{
					ArtifactLocation: sarifArtifact{URI: f.File},
					Region:           sarifRegion{StartLine: f.Line},
				},
			}},
		})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

func buildTool(rs *rules.RuleSet) sarifTool {
	drv := sarifDriver{Name: "guardrail", InformationURI: "https://github.com/sarnas-it/guardrail"}
	if rs == nil {
		return sarifTool{Driver: drv}
	}
	for _, r := range rs.Rules() {
		lvl := "warning"
		if r.Severity == rules.SeverityBlock {
			lvl = "error"
		}
		drv.Rules = append(drv.Rules, sarifRule{
			ID:               r.ID,
			ShortDescription: sarifText{Text: r.Description},
			DefaultConfiguration: sarifLevel{Level: lvl},
		})
	}
	return sarifTool{Driver: drv}
}
```

- [ ] **Step 4: Реализовать JSON**

`internal/output/json.go`:
```go
package output

import (
	"encoding/json"
	"io"

	"github.com/sarnas-it/guardrail/internal/engine"
	"github.com/sarnas-it/guardrail/internal/mask"
)

type jsonFinding struct {
	RuleID      string `json:"ruleId"`
	Category    string `json:"category"`
	Severity    string `json:"severity"`
	File        string `json:"file"`
	Line        int    `json:"line"`
	Value       string `json:"value"`
	Fingerprint string `json:"fingerprint"`
}

type jsonDoc struct {
	Findings []jsonFinding `json:"findings"`
}

func WriteJSON(w io.Writer, findings []engine.Finding, reveal bool) error {
	doc := jsonDoc{}
	for _, f := range findings {
		val := f.Value
		if !reveal {
			val = mask.Secret(f.Value)
		}
		doc.Findings = append(doc.Findings, jsonFinding{
			RuleID:      f.RuleID,
			Category:    string(f.Category),
			Severity:    string(f.Severity),
			File:        f.File,
			Line:        f.Line,
			Value:       val,
			Fingerprint: f.Fingerprint,
		})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}
```

- [ ] **Step 5: Прогнать — PASS**

```bash
cd /home/basili4/GolandProjects/guardrail && go test ./internal/output/ -v
```

- [ ] **Step 6: Коммит**

```bash
cd /home/basili4/GolandProjects/guardrail
git add internal/output
git commit -m "feat: SARIF 2.1.0 and JSON reports"
```

---

### Task 9: CLI и точка входа

**Files:**
- Modify: `cmd/guardrail/main.go`
- Create: `internal/app/app.go`
- Create: `internal/app/app_test.go`

**Interfaces:**
- Consumes: все пакеты.
- Produces:
```go
package app

type ExitError struct{ Code int }

func Run(repoDir string, base, head, configPath, sarifFile, jsonFile string, reveal bool) (int, error)
   // 0 — нет блокирующих; 1 — есть секрет; 2 — ошибка (возвращается как error/ExitError)
func ResolveBase(runner *git.Runner, head, given string) (string, error)
func ResolveHead(runner *git.Runner, given string) (string, error)
```

- [ ] **Step 1: Написать падающие тесты app**

`internal/app/app_test.go`:
```go
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
```

- [ ] **Step 2: Прогнать — падает**

```bash
cd /home/basili4/GolandProjects/guardrail && go test ./internal/app/ -v
```

Ожидается: compile error (нет пакета app).

- [ ] **Step 3: Реализовать `internal/app/app.go`**

```go
package app

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/sarnas-it/guardrail/internal/config"
	"github.com/sarnas-it/guardrail/internal/engine"
	"github.com/sarnas-it/guardrail/internal/git"
	"github.com/sarnas-it/guardrail/internal/output"
	"github.com/sarnas-it/guardrail/internal/rules"
)

// Run выполняет сканирование репозитория в repoDir.
// base/head могут быть пустыми: head=HEAD, base=родитель или EmptyTree.
// configPath, sarifFile, jsonFile (если относительные) резолвятся относительно repoDir.
// Возвращает exit-код 0/1 и error (код 2) для ошибок выполнения.
func Run(repoDir, base, head, configPath, sarifFile, jsonFile string, reveal bool) (int, error) {
	rs, err := rules.LoadDefault()
	if err != nil {
		return 2, err
	}
	runner := git.New(repoDir)

	head, err = ResolveHead(runner, head)
	if err != nil {
		return 2, err
	}
	base, err = ResolveBase(runner, head, base)
	if err != nil {
		return 2, err
	}

	abs := func(p string) string {
		if p == "" || filepath.IsAbs(p) {
			return p
		}
		return filepath.Join(repoDir, p)
	}

	cfg := config.Default()
	if configPath != "" {
		cfg, err = config.Load(abs(configPath), rs)
		if err != nil {
			return 2, err
		}
	}

	res, err := engine.Scan(engine.Options{
		RepoDir: repoDir,
		Base:    base,
		Head:    head,
		Cfg:     cfg,
		RS:      rs,
		Runner:  runner,
	})
	if err != nil {
		return 2, err
	}

	reveal = reveal || cfg.Output.Reveal
	block, warn := output.WriteText(os.Stdout, res.Findings, reveal)
	fmt.Fprintf(os.Stderr, "guardrail: %d finding(s) allowed by allowlist\n", res.Allowed)

	if sarifFile == "" {
		sarifFile = cfg.Output.SarifFile
	}
	if sarifFile != "" {
		sarifFile = abs(sarifFile)
		if dir := filepath.Dir(sarifFile); dir != "." {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return 2, err
			}
		}
		f, err := os.Create(sarifFile)
		if err != nil {
			return 2, err
		}
		if err := output.WriteSARIF(f, res.Findings, rs, reveal); err != nil {
			f.Close()
			return 2, err
		}
		if err := f.Close(); err != nil {
			return 2, err
		}
	}
	if jsonFile != "" {
		jsonFile = abs(jsonFile)
		f, err := os.Create(jsonFile)
		if err != nil {
			return 2, err
		}
		if err := output.WriteJSON(f, res.Findings, reveal); err != nil {
			f.Close()
			return 2, err
		}
		if err := f.Close(); err != nil {
			return 2, err
		}
	}

	if block > 0 {
		return 1, nil
	}
	_ = warn
	return 0, nil
}

func ResolveHead(runner *git.Runner, given string) (string, error) {
	if given != "" {
		if !runner.RevExists(given) {
			return "", fmt.Errorf("head revision %q does not exist", given)
		}
		return given, nil
	}
	if runner.RevExists("HEAD") {
		out, err := runner.RevParse("HEAD")
		if err != nil {
			return "", err
		}
		return out, nil
	}
	return "", fmt.Errorf("no HEAD and no --head given")
}

func ResolveBase(runner *git.Runner, head, given string) (string, error) {
	if given != "" {
		return given, nil
	}
	return runner.ParentOrEmpty(head)
}
```

Добавить метод `RevParse` в `internal/git/git.go`:
```go
func (r *Runner) RevParse(rev string) (string, error) {
	out, err := r.run("rev-parse", rev)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}
```

- [ ] **Step 4: Прогнать тесты app**

```bash
cd /home/basili4/GolandProjects/guardrail && go test ./internal/app/ -v
```

Ожидается: PASS. `Run` с пустым base даст head с одним предком → дифф ловит добавленную строку с `AKIA...` → code 1.

- [ ] **Step 5: Переписать `cmd/guardrail/main.go`**

```go
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/sarnas-it/guardrail/internal/app"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		usage()
		return 2
	}
	switch args[0] {
	case "scan":
		return runScan(args[1:])
	default:
		usage()
		return 2
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "guardrail scan --base <sha> --head <sha> [--config guardrail.yml] [--sarif out.sarif] [--json out.json]")
}

func runScan(args []string) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	var (
		base       = fs.String("base", "", "base commit SHA")
		head       = fs.String("head", "", "head commit SHA")
		configPath = fs.String("config", "guardrail.yml", "path to guardrail.yml")
		sarifFile  = fs.String("sarif", "", "write SARIF report to file")
		jsonFile   = fs.String("json", "", "write JSON report to file")
		reveal     = fs.Bool("reveal", false, "print full values")
		repoDir    = fs.String("repo", ".", "path to git repository")
	)
	if err := fs.Parse(args); err != nil {
		return 2
	}

	// Поддержка container action: GitHub передаёт inputs как env INPUT_<NAME>.
	flagOrEnv := func(flagVal, envKey string) string {
		if flagVal != "" {
			return flagVal
		}
		return os.Getenv(envKey)
	}
	*base = flagOrEnv(*base, "INPUT_BASE")
	*head = flagOrEnv(*head, "INPUT_HEAD")
	*configPath = flagOrEnv(*configPath, "INPUT_CONFIG")
	*sarifFile = flagOrEnv(*sarifFile, "INPUT_SARIF_FILE")

	if os.Getenv("GUARDRAIL_REVEAL") == "1" {
		*reveal = true
	}

	code, err := app.Run(*repoDir, *base, *head, *configPath, *sarifFile, *jsonFile, *reveal)
	if err != nil {
		fmt.Fprintf(os.Stderr, "guardrail: %v\n", err)
		return code
	}
	return code
}
```

- [ ] **Step 6: Собрать и проверить exit-код вручную**

```bash
cd /home/basili4/GolandProjects/guardrail && go build -o guardrail ./cmd/guardrail && go vet ./...
```

- [ ] **Step 7: Коммит**

```bash
cd /home/basili4/GolandProjects/guardrail
git add cmd/guardrail internal/app internal/git/git.go
git commit -m "feat: guardrail scan CLI with exit codes 0/1/2"
```

---

### Task 10: Docker-образ и action.yml

**Files:**
- Create: `/home/basili4/GolandProjects/guardrail/Dockerfile`
- Create: `/home/basili4/GolandProjects/guardrail/action.yml`
- Create: `/home/basili4/GolandProjects/guardrail/.dockerignore`

- [ ] **Step 1: Создать Dockerfile**

```dockerfile
FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /out/guardrail ./cmd/guardrail

FROM alpine:3.21
RUN apk add --no-cache git ca-certificates
COPY --from=build /out/guardrail /usr/local/bin/guardrail
WORKDIR /github/workspace
ENTRYPOINT ["/usr/local/bin/guardrail"]
```

- [ ] **Step 2: Создать `.dockerignore`**

```
.git
guardrail
docs
*.sarif
internal/**/*_test.go
```

- [ ] **Step 3: Создать `action.yml`**

```yaml
name: 'Guardrail'
description: 'Scan PR/push diff for leaked secrets and Russian personal data'
author: 'Sarnas'
branding:
  icon: 'shield'
  color: 'red'
inputs:
  base:
    description: 'Base commit SHA to diff against. Defaults to parent of head.'
    required: false
    default: ''
  head:
    description: 'Head commit SHA. Defaults to current commit.'
    required: false
    default: ''
  config:
    description: 'Path to guardrail.yml relative to repo root.'
    required: false
    default: 'guardrail.yml'
  sarif_file:
    description: 'Write SARIF report to this path.'
    required: false
    default: ''
outputs: {}
runs:
  using: 'docker'
  image: 'docker://ghcr.io/sarnas-it/guardrail:v0.1.0'
  args:
    - scan
```

- [ ] **Step 4: Собрать образ и проверить запуск**

```bash
cd /home/basili4/GolandProjects/guardrail && docker build -t guardrail:dev .
docker run --rm -v "$PWD:/github/workspace" guardrail:dev scan --repo /github/workspace --head HEAD --base '' --config /github/workspace/guardrail.yml
```

Ожидается: команда выполняется; поскольку собственный репозиторий не содержит секретов, exit=0 (или корректный вывод summary 0).

- [ ] **Step 5: Коммит**

```bash
cd /home/basili4/GolandProjects/guardrail
git add Dockerfile action.yml .dockerignore
git commit -m "feat: Docker image and container action.yml"
```

---

### Task 11: Пример, README, документация для клиента

**Files:**
- Create: `/home/basili4/GolandProjects/guardrail/examples/guardrail.yml`
- Create: `/home/basili4/GolandProjects/guardrail/examples/workflow.yml`
- Create: `/home/basili4/GolandProjects/guardrail/README.md`

- [ ] **Step 1: Создать пример конфига**

`examples/guardrail.yml`:
```yaml
severity:
  # aws_access_key: warn
ignore:
  paths:
    - "testdata/**"
  matches:
    - rule: phone_ru
      path: "internal/tests/fixtures.go"
      reason: "test fixtures"
scan:
  max_file_size_kb: 512
output:
  sarif_file: guardrail.sarif
```

- [ ] **Step 2: Создать пример workflow**

`examples/workflow.yml`:
```yaml
name: guardrail
on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: docker://ghcr.io/sarnas-it/guardrail:v0.1.0
        with:
          base: ${{ github.event.pull_request.base.sha || github.event.before }}
          head: ${{ github.sha }}
          config: guardrail.yml
          sarif_file: guardrail.sarif
      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: guardrail.sarif
```

- [ ] **Step 3: Создать README.md**

`README.md` — содержимое:
```markdown
# Guardrail

Container action для GitHub: сканирует дифф PR/push на утечки секретов и персональных данных (ПДн РФ) прямо в раннере — код репозитория наружу не отправляется.

## Быстрый старт

```yaml
steps:
  - uses: actions/checkout@v4
    with:
      fetch-depth: 0
  - uses: docker://ghcr.io/sarnas-it/guardrail:v0.1.0
    with:
      base: ${{ github.event.pull_request.base.sha || github.event.before }}
      head: ${{ github.sha }}
```

Пайплайн упадёт (exit 1), если в новых изменениях найден секрет. ПДн РФ печатаются как предупреждения (exit 0).

## Локально

```bash
go build -o guardrail ./cmd/guardrail
./guardrail scan --repo . --base HEAD~1 --head HEAD
```

## Конфиг guardrail.yml

См. `examples/guardrail.yml`. Значения находок маскируются; полные значения — `GUARDRAIL_REVEAL=1` или `output.reveal: true`.

## Правила

Секреты блокируют: AWS/GCP/слак/GitHub/telegram-ключи, PEM, JWT, строки БД, generic high-entropy. ПДн РФ (телефон, email, ИНН, СНИЛС, паспорт) — предупреждения.
```

- [ ] **Step 4: Коммит**

```bash
cd /home/basili4/GolandProjects/guardrail
git add examples README.md
git commit -m "docs: client usage example and README"
```

---

### Task 12: CI-пайплайн и публикация образа

**Files:**
- Create: `.github/workflows/ci.yml`
- Create: `.github/workflows/release.yml`

- [ ] **Step 1: CI**

`.github/workflows/ci.yml`:
```yaml
name: ci
on:
  pull_request:
  push:
    branches: [main]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.25'
      - run: go vet ./...
      - run: go build ./...
      - run: go test ./... -v
      - run: docker build -t guardrail:ci .
```

- [ ] **Step 2: Release (публикация образа по тегу)**

`.github/workflows/release.yml`:
```yaml
name: release
on:
  push:
    tags: ['v*']

permissions:
  contents: read
  packages: write

jobs:
  build-push:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: docker/setup-buildx-action@v3
      - uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}
      - uses: docker/build-push-action@v6
        with:
          context: .
          push: true
          tags: |
            ghcr.io/sarnas-it/guardrail:${{ github.ref_name }}
            ghcr.io/sarnas-it/guardrail:latest
```

- [ ] **Step 3: Проверить, что CI локально зелёный**

```bash
cd /home/basili4/GolandProjects/guardrail && go vet ./... && go build ./... && go test ./...
```

- [ ] **Step 4: Коммит**

```bash
cd /home/basili4/GolandProjects/guardrail
git add .github
git commit -m "ci: test pipeline and image release on tag"
```

---

### Task 13: Тег v0.1.0 и публикация образа

**Files:** нет (git-операции).

- [ ] **Step 1: Убедиться, что все тесты проходят**

```bash
cd /home/basili4/GolandProjects/guardrail && go vet ./... && go test ./... -v
```

- [ ] **Step 2: Пуш в GitHub**

```bash
cd /home/basili4/GolandProjects/guardrail
git push -u origin main
```

- [ ] **Step 3: Поставить тег и запустить release**

```bash
cd /home/basili4/GolandProjects/guardrail
git tag v0.1.0
git push origin v0.1.0
```

После этого GitHub Actions соберёт и опубликует `ghcr.io/sarnas-it/guardrail:v0.1.0` (и `latest`). Образ публичный (репозиторий публичный), `docker://ghcr.io/sarnas-it/guardrail:v0.1.0` доступен клиентам.

- [ ] **Step 4: Проверка на публичном тест-репозитории**

Создать временный публичный репозиторий с workflow из `examples/workflow.yml` и PR, добавляющим строку с `AKIAIOSFODNN7EXAMPLE`; убедиться, что PR-чек падает красным с сообщением `[block] aws_access_key`. Прогон также генерирует `guardrail.sarif`.

- [ ] **Step 5: Дополнительная проверка allowlist**

Добавить в тест-репозиторий `guardrail.yml` с `ignore.matches` на этот файл/строку и убедиться, что PR становится зелёным, а находка попадает в вывод как "allowed by allowlist".

---

## Self-Review

**Спека → план:**
- Полностью локальный container action на Go — Task 10, 12, 13. ✓
- Дифф-скан только новых изменений (добавленные строки) — Task 4 (`parseDiffHunks`, three-dot diff), Task 6. ✓
- Смешанная реакция: секреты блокируют, ПДн warn — Task 2 (severity), Task 6 (`effectiveSeverity`), Task 9 (exit 1). ✓
- Встроенные правила + конфиг (severity, allowlist paths/matches, extra paths, max size, sarif/reveal) — Task 2, 5, 6. ✓
- Лог + SARIF/JSON — Task 7, 8. ✓
- Маскирование значений + GUARDRAIL_REVEAL — Task 7, 9. ✓
- Exit-коды 0/1/2 — Task 9. ✓
- Без live-проверки ключей — правила чисто статические. ✓
- First-commit fallback (EmptyTree) — Task 4 (`ParentOrEmpty`), Task 9. ✓
- Бинарные файлы/мапки/sum пропускаются — Task 6 (builtinIgnoredPaths + BlobSize). ✓
- Неизвестный ключ/rule → ошибка — Task 5. ✓
- Публичный репозиторий — сделан заранее. ✓
- Пример для клиента + README — Task 11. ✓

**Плейсхолдеры:** отсутствуют (кроме копируемых в Task 2 «итоговых» блоков, которые даны полностью в финальных версиях).

**Консистентность типов:** `engine.Finding` (Task 6) используется в output/app (Task 7–9) с полями `RuleID/Category/Severity/File/Line/Value/Fingerprint` — совпадают. `rules.RuleSet.Rules()` возвращает отсортированный слайс — детектор (Task 3) идёт по нему. `git.Runner` методы: `AddedLines`, `BlobSize`, `RevExists`, `ParentOrEmpty`, `RevParse` — согласованы.
