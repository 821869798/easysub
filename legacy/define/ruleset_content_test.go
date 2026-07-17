package define

import "testing"

func TestMergeAdjacentRulesets(t *testing.T) {
	contents := []*RulesetContent{
		{
			RuleGroup:     "DIRECT",
			RulePath:      []string{"one"},
			RulePathTyped: "one",
			RuleType:      RULESET_SURGE,
			RuleContent:   "DOMAIN,one.example",
		},
		{
			RuleGroup:     "DIRECT",
			RulePath:      []string{"two"},
			RulePathTyped: "two",
			RuleType:      RULESET_SURGE,
			RuleContent:   "DOMAIN,two.example",
		},
	}

	merged := mergeAdjacentRulesets(contents)
	if len(merged) != 1 {
		t.Fatalf("merged count = %d, want 1", len(merged))
	}
	if got, want := merged[0].RuleContent, "DOMAIN,one.example\nDOMAIN,two.example"; got != want {
		t.Fatalf("merged content = %q, want %q", got, want)
	}
	if len(merged[0].RulePath) != 2 {
		t.Fatalf("merged path count = %d, want 2", len(merged[0].RulePath))
	}
}

func TestMergeAdjacentRulesetsKeepsDifferentFormatsSeparate(t *testing.T) {
	contents := []*RulesetContent{
		{
			RuleGroup:     "DIRECT",
			RulePathTyped: "one",
			RuleType:      RULESET_SURGE,
			RuleContent:   "DOMAIN,one.example",
		},
		{
			RuleGroup:     "DIRECT",
			RulePathTyped: "two",
			RuleType:      RULESET_QUANX,
			RuleContent:   "HOST,two.example",
		},
	}

	if merged := mergeAdjacentRulesets(contents); len(merged) != 2 {
		t.Fatalf("different rule formats were merged; count = %d, want 2", len(merged))
	}
}

func TestMergeAdjacentRulesetsKeepsInlineRuleSeparate(t *testing.T) {
	contents := []*RulesetContent{
		{
			RuleGroup:   "DIRECT",
			RuleType:    RULESET_SURGE,
			RuleContent: "[]DOMAIN,inline.example",
		},
		{
			RuleGroup:     "DIRECT",
			RulePathTyped: "external",
			RuleType:      RULESET_SURGE,
			RuleContent:   "DOMAIN,external.example",
		},
	}

	if merged := mergeAdjacentRulesets(contents); len(merged) != 2 {
		t.Fatalf("inline and external rules were merged; count = %d, want 2", len(merged))
	}
}
