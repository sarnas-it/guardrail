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

func TestRuleTypesConstants(t *testing.T) {
	if RuleTypeRegex != "regex" || RuleTypeDictionary != "dictionary" {
		t.Fatal("rule type constants mismatch")
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
