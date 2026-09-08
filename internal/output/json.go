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
