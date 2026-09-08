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
