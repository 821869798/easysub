package common

import (
	"reflect"
	"testing"

	"github.com/821869798/easysub/define"
)

func TestGroupGeneratePreservesOrderAndExistingSelections(t *testing.T) {
	nodes := []*define.Proxy{
		{Remark: "alpha"},
		{Remark: "beta"},
		{Remark: "gamma"},
	}

	selected := GroupGenerate(".*", nodes, []string{"beta"}, true)
	if want := []string{"beta", "alpha", "gamma"}; !reflect.DeepEqual(selected, want) {
		t.Fatalf("selected nodes = %#v, want %#v", selected, want)
	}
}

func TestApplyMatcherSpecialRules(t *testing.T) {
	node := &define.Proxy{
		Group:    "airport-hk",
		GroupId:  2,
		Type:     define.ProxyType_VMess,
		Port:     443,
		Hostname: "edge.example.com",
	}
	tests := []struct {
		name     string
		rule     string
		matched  bool
		realRule string
	}{
		{name: "group", rule: "!!GROUP=airport.*", matched: true},
		{name: "group mismatch", rule: "!!GROUP=other", matched: false},
		{name: "group id range", rule: "!!GROUPID=1-3", matched: true},
		{name: "insert negative id", rule: "!!INSERT=-2", matched: true},
		{name: "type", rule: "!!TYPE=VMESS", matched: true},
		{name: "type mismatch", rule: "!!TYPE=TROJAN", matched: false},
		{name: "port range", rule: "!!PORT=400-500", matched: true},
		{name: "server", rule: `!!SERVER=example\.com`, matched: true},
		{name: "server mismatch", rule: "!!SERVER=example.net", matched: false},
		{name: "secondary filter", rule: "!!TYPE=VMESS!!HK.*", matched: true, realRule: "HK.*"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matched, realRule := applyMatcher(test.rule, node)
			if matched != test.matched || realRule != test.realRule {
				t.Fatalf("applyMatcher(%q) = (%v, %q), want (%v, %q)", test.rule, matched, realRule, test.matched, test.realRule)
			}
		})
	}
}

func TestMatchRange(t *testing.T) {
	tests := []struct {
		rangeExpression string
		target          int
		matched         bool
	}{
		{rangeExpression: "2", target: 2, matched: true},
		{rangeExpression: "1-3", target: 2, matched: true},
		{rangeExpression: "3-", target: 2, matched: true},
		{rangeExpression: "3+", target: 4, matched: true},
		{rangeExpression: "1,3", target: 2, matched: false},
		{rangeExpression: "!1,!2", target: 1, matched: false},
		{rangeExpression: "!1,!2", target: 3, matched: true},
		{rangeExpression: "1-3,!2", target: 2, matched: false},
		{rangeExpression: "1-3,!2", target: 3, matched: true},
		{rangeExpression: "-2", target: -2, matched: true},
	}

	for _, test := range tests {
		if got := matchRange(test.rangeExpression, test.target); got != test.matched {
			t.Errorf("matchRange(%q, %d) = %v, want %v", test.rangeExpression, test.target, got, test.matched)
		}
	}
}
