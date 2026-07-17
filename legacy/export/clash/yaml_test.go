package clash

import (
	"github.com/goccy/go-yaml"
	"testing"
)

// 定义一个类型以控制单个对象的序列化行为
type CompactStringArray []string

type ProxyGroup struct {
	Name    string             `yaml:"name"`
	Proxies CompactStringArray `yaml:"proxies"`
	Type    QuotedString       `yaml:"type"`
	Objects []CompactObjectMap `yaml:"objets,flow"`
}

type Config struct {
	ProxyGroups []ProxyGroup `yaml:"proxy-groups"`
}

func TestYamlMarshal(t *testing.T) {
	conf := Config{
		ProxyGroups: []ProxyGroup{
			{
				Name:    "🚀 节点选择",
				Proxies: CompactStringArray{"DIRECT", "akk.89330595.xyz_trojan"},
				Type:    "select",
				Objects: []CompactObjectMap{
					map[string]interface{}{
						"Name":    "🎯 全球直连",
						"Proxies": CompactStringArray{"akk.89330595.xyz_trojan"},
					},
					map[string]interface{}{
						"Name":    "🎯 全球直连",
						"Proxies": CompactStringArray{"akk.89330595.xyz_trojan"},
					},
				},
			},
			{
				Name:    "🐟 漏网之鱼",
				Proxies: CompactStringArray{"🚀 节点选择", "🎯 全球直连", "akk.89330595.xyz_trojan"},
				Type:    "select",
			},
		},
	}

	compactStringArrayMarshaler := yaml.CustomMarshaler[CompactStringArray](func(arr CompactStringArray) ([]byte, error) {
		return yaml.MarshalWithOptions([]string(arr), yaml.Flow(true))
	})

	//compactObjectMarshal := yaml.CustomMarshaler[CompactObjectMap](func(obj CompactObjectMap) ([]byte, error) {
	//	return yaml.MarshalWithOptions(obj, yaml.Flow(true))
	//})

	//quotedstringMarshal := yaml.CustomMarshaler[QuotedString](func(q QuotedString) ([]byte, error) {
	//	return yaml.MarshalWithOptions(q, yaml.JSON())
	//})

	//_ = compactObjectMarshal
	_ = compactStringArrayMarshaler

	result, err := yaml.MarshalWithOptions(conf, yaml.IndentSequence(true))
	if err != nil {
		panic(err)
	}

	t.Log(string(result))
}
