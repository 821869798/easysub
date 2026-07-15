package define

import (
	"strings"
	"testing"
)

func BenchmarkMergeAdjacentRulesets(b *testing.B) {
	const (
		partCount = 32
		partSize  = 64 << 10
	)
	contents := make([]*RulesetContent, partCount)
	content := strings.Repeat("x", partSize)
	for i := range contents {
		contents[i] = &RulesetContent{
			RuleGroup:     "DIRECT",
			RulePath:      []string{"https://example.com/rules.txt"},
			RulePathTyped: "https://example.com/rules.txt",
			RuleType:      RULESET_SURGE,
			RuleContent:   content,
		}
	}

	b.ReportAllocs()
	b.SetBytes(partCount * partSize)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result := mergeAdjacentRulesets(contents)
		if len(result) != 1 {
			b.Fatalf("merged result count = %d, want 1", len(result))
		}
	}
}
