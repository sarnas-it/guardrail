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
