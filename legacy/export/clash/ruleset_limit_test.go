package clash

import (
	"strings"
	"testing"

	"github.com/821869798/easysub/config"
	"github.com/821869798/easysub/define"
)

func TestRulesetToClashStrHonorsMaxAllowedRules(t *testing.T) {
	previousGlobal := config.Global
	config.Global = &config.AppConfig{
		Advance: &config.AppConfigAdvance{MaxAllowedRules: 2},
	}
	t.Cleanup(func() {
		config.Global = previousGlobal
	})

	rulesetContent := []*define.RulesetContent{
		{
			RuleGroup: "DIRECT",
			RuleType:  define.RULESET_SURGE,
			RuleContent: strings.Join([]string{
				"DOMAIN,one.example",
				"DOMAIN,two.example",
				"DOMAIN,three.example",
			}, "\n"),
		},
	}
	extraSettings := &define.ExtraSettings{OverwriteOriginalRules: true}

	output := rulesetToClashStr(map[string]interface{}{}, rulesetContent, extraSettings)
	if got := strings.Count(output, "  - "); got != 2 {
		t.Fatalf("generated rule count = %d, want 2; output:\n%s", got, output)
	}
	if strings.Contains(output, "three.example") {
		t.Fatalf("output contains a rule beyond MaxAllowedRules:\n%s", output)
	}
}
