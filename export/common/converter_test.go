package common

import "testing"

func TestRemarkDeduplicatorMatchesLegacyBehavior(t *testing.T) {
	inputs := []string{"node", "node", "node 2", "node", "a=b", "a=b", "with,comma", "with,comma"}
	for _, procComma := range []bool{false, true} {
		legacyRemarks := make([]string, 0, len(inputs))
		deduplicator := NewRemarkDeduplicator(len(inputs))
		for _, input := range inputs {
			legacy := ProcessRemark(input, legacyRemarks, procComma)
			optimized := deduplicator.Process(input, procComma)
			if optimized != legacy {
				t.Fatalf("Process(%q, %v) = %q, legacy result %q", input, procComma, optimized, legacy)
			}
			legacyRemarks = append(legacyRemarks, legacy)
		}
	}
}
