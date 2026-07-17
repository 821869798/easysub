package common

import (
	"strconv"
	"testing"
)

func BenchmarkProcessRemarkDuplicateHeavy(b *testing.B) {
	const nodeCount = 500
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		remarks := make([]string, 0, nodeCount)
		for j := 0; j < nodeCount; j++ {
			remarks = append(remarks, ProcessRemark("duplicate", remarks, false))
		}
	}
}

func BenchmarkRemarkDeduplicatorDuplicateHeavy(b *testing.B) {
	const nodeCount = 500
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		deduplicator := NewRemarkDeduplicator(nodeCount)
		for j := 0; j < nodeCount; j++ {
			deduplicator.Process("duplicate", false)
		}
	}
}

func BenchmarkRemarkDeduplicatorUnique(b *testing.B) {
	const nodeCount = 500
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		deduplicator := NewRemarkDeduplicator(nodeCount)
		for j := 0; j < nodeCount; j++ {
			deduplicator.Process("node-"+strconv.Itoa(j), false)
		}
	}
}

func BenchmarkProcessRemarkUnique(b *testing.B) {
	const nodeCount = 500
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		remarks := make([]string, 0, nodeCount)
		for j := 0; j < nodeCount; j++ {
			remark := "node-" + strconv.Itoa(j)
			remarks = append(remarks, ProcessRemark(remark, remarks, false))
		}
	}
}
