package singbox

import (
	"encoding/json"
	"testing"

	"github.com/821869798/easysub/config"
	"github.com/821869798/easysub/define"
)

func TestRulesetTagUsesSingBox114HTTPClient(t *testing.T) {
	restoreConfig := useRulesetTestConfig()
	t.Cleanup(restoreConfig)

	output, err := RenderTemplate(`{"rule_set":[{% ruleset geosite cn %}]}`, nil)
	if err != nil {
		t.Fatalf("RenderTemplate() error = %v", err)
	}

	var document struct {
		RuleSets []map[string]interface{} `json:"rule_set"`
	}
	if err := json.Unmarshal([]byte(output), &document); err != nil {
		t.Fatalf("rendered output is invalid JSON: %v", err)
	}
	if len(document.RuleSets) != 1 {
		t.Fatalf("rendered rule-set count = %d, want 1", len(document.RuleSets))
	}
	assertRuleSetHTTPClient(t, document.RuleSets[0])
}

func TestSkippedProxyDoesNotReserveSingBoxRemark(t *testing.T) {
	restoreConfig := useRulesetTestConfig()
	t.Cleanup(restoreConfig)
	nodes := []*define.Proxy{
		{Type: define.ProxyType_Unknown, Remark: "same-name"},
		{Type: define.ProxyType_VMess, Remark: "same-name"},
	}
	configObject := make(map[string]interface{})

	proxyToSingBoxInternal(nodes, configObject, nil, &define.ExtraSettings{})

	outbounds := configObject["outbounds"].([]interface{})
	if len(outbounds) != 3 {
		t.Fatalf("outbound count = %d, want 3", len(outbounds))
	}
	proxy := outbounds[2].(map[string]interface{})
	if got := proxy["tag"]; got != "same-name" {
		t.Fatalf("valid proxy tag = %v, want same-name", got)
	}
}

func TestDynamicRulesetUsesSingBox114HTTPClient(t *testing.T) {
	restoreConfig := useRulesetTestConfig()
	t.Cleanup(restoreConfig)

	ruleSets := make(map[string]interface{})
	transformRuleToSingBox("GEOSITE,CN", "DIRECT", ruleSets)

	ruleSet, ok := ruleSets["geosite-cn"].(map[string]interface{})
	if !ok {
		t.Fatalf("generated rule-set has unexpected type: %T", ruleSets["geosite-cn"])
	}
	assertRuleSetHTTPClient(t, ruleSet)
}

func TestAppendSingBoxRuleKeepsOnlyRuleTypeAndValue(t *testing.T) {
	rules := make(map[string]interface{})
	appendSingBoxRule(rules, "DOMAIN-SUFFIX,Example.COM,no-resolve")

	values, ok := rules["domain_suffix"].([]interface{})
	if !ok || len(values) != 1 {
		t.Fatalf("domain_suffix has unexpected value: %#v", rules["domain_suffix"])
	}
	if got := values[0]; got != "example.com" {
		t.Fatalf("domain_suffix value = %v, want example.com", got)
	}
}

func useRulesetTestConfig() func() {
	previousGlobal := config.Global
	config.Global = &config.AppConfig{
		NodePref: &config.AppConfigNodePref{
			SingboxRulesets: map[string]*config.AppConfigRulesetTransform{
				"geosite": {
					UrlFormat: "https://example.com/%s.srs",
				},
			},
		},
	}
	return func() {
		config.Global = previousGlobal
	}
}

func assertRuleSetHTTPClient(t *testing.T, ruleSet map[string]interface{}) {
	t.Helper()
	if _, exists := ruleSet["download_detour"]; exists {
		t.Fatal("generated rule-set contains deprecated download_detour")
	}
	httpClient, ok := ruleSet["http_client"].(map[string]interface{})
	if !ok {
		t.Fatalf("http_client has unexpected type: %T", ruleSet["http_client"])
	}
	if got := httpClient["detour"]; got != "DIRECT" {
		t.Fatalf("http_client.detour = %v, want DIRECT", got)
	}
}
