package singbox

import (
	"testing"

	"github.com/821869798/easysub/config"
	"github.com/821869798/easysub/define"
)

func TestRulesetToSingBoxHonorsMaxAllowedRules(t *testing.T) {
	previousGlobal := config.Global
	config.Global = &config.AppConfig{
		Advance:  &config.AppConfigAdvance{MaxAllowedRules: 2},
		NodePref: &config.AppConfigNodePref{},
	}
	t.Cleanup(func() {
		config.Global = previousGlobal
	})

	baseConfig := make(map[string]interface{})
	rulesetContent := []*define.RulesetContent{
		{
			RuleGroup:   "DIRECT",
			RuleType:    define.RULESET_SURGE,
			RuleContent: "DOMAIN,one.example\nDOMAIN,two.example\nDOMAIN,three.example",
		},
	}

	rulesetToSingBox(baseConfig, rulesetContent, true)

	route := baseConfig["route"].(map[string]interface{})
	rules := route["rules"].([]interface{})
	var domainValues []interface{}
	for _, item := range rules {
		rule := item.(map[string]interface{})
		if values, ok := rule["domain"].([]interface{}); ok {
			domainValues = values
			break
		}
	}
	if len(domainValues) != 2 {
		t.Fatalf("generated domain rule count = %d, want 2; rules: %#v", len(domainValues), rules)
	}
	if domainValues[0] != "one.example" || domainValues[1] != "two.example" {
		t.Fatalf("generated domain rules = %#v, want first two rules", domainValues)
	}
}
