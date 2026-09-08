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
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
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
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID                   string     `json:"id"`
	ShortDescription     sarifText  `json:"shortDescription"`
	DefaultConfiguration sarifLevel `json:"defaultConfiguration"`
}

type sarifLevel struct {
	Level string `json:"level"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	Level               string            `json:"level"`
	Message             sarifText         `json:"message"`
	Locations           []sarifLoc        `json:"locations"`
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
		Runs:    []sarifRun{{Tool: buildTool(rs), Results: []sarifResult{}}},
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
			RuleID:              f.RuleID,
			Level:               level,
			Message:             sarifText{Text: msg},
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
			ID:                   r.ID,
			ShortDescription:     sarifText{Text: r.Description},
			DefaultConfiguration: sarifLevel{Level: lvl},
		})
	}
	return sarifTool{Driver: drv}
}
