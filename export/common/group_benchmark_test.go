package common

import (
	"strconv"
	"testing"

	"github.com/821869798/easysub/define"
)

func BenchmarkGroupGenerateOverlappingRules(b *testing.B) {
	const nodeCount = 2000
	nodes := make([]*define.Proxy, nodeCount)
	for index := range nodes {
		nodes[index] = &define.Proxy{Remark: "node-" + strconv.Itoa(index)}
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var selected []string
		selected = GroupGenerate(".*", nodes, selected, true)
		selected = GroupGenerate("node-.*", nodes, selected, true)
		selected = GroupGenerate(".*", nodes, selected, true)
		if len(selected) != nodeCount {
			b.Fatalf("selected node count = %d, want %d", len(selected), nodeCount)
		}
	}
}
