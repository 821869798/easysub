package parser

import (
	"fmt"
	"github.com/goccy/go-yaml"
	"gopkg.in/ini.v1"
	"testing"
)

func TestParseIni(t *testing.T) {
	iniContent := `[custom]
;以下两个是的自定义
ruleset=🚀 节点选择,http://127.0.0.1/file_share/custom_proxy.plist
ruleset=🎯 全球直连,http://127.0.0.1/file_share/custom_direct.plist
ruleset=💬 OpenAi,http://127.0.0.1/file_share/custom_proxy_ai.plist
ruleset=💬 OpenAi,https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/OpenAi.list
ruleset=💬 OpenAi,https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Bing.list`
	cfg, err := ini.ShadowLoad([]byte(iniContent))
	if err != nil {
		t.Error(err)
	}
	customSection := cfg.Section("custom")
	rulesets := customSection.KeysHash()["ruleset"]

	t.Log(rulesets)
	rulesets2 := customSection.Key("ruleset").ValueWithShadows()
	for i, ruleset := range rulesets2 {
		fmt.Printf("Ruleset %d: %s\n", i+1, ruleset)
	}
	t.Log(customSection.KeyStrings())

}

func TestParseYaml(t *testing.T) {
	var data = `
a: Easy!
b:
  c: 2
  d: [3, 4]
`
	ymlData := make(map[string]interface{}, 0)
	err := yaml.Unmarshal([]byte(data), &ymlData)
	if err != nil {
		t.Error(err)
	}

	t.Log(ymlData)
}
