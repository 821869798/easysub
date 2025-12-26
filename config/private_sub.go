package config

import (
	"net/url"
	"os"
	"strings"

	"github.com/821869798/fankit/fanstr"
)

type AppConfigPrivateSub struct {
	// 变量
	Vars []*AppConfigKeyValue `toml:"vars"`
	// 重定向
	Rewrites []*AppConfigKeyValue `toml:"rewrites"`
	// toml ignore
	VarsFormatMap     map[string]string `toml:"-"`
	RewritesFormatMap map[string]string `toml:"-"`
}

func (a *AppConfigPrivateSub) afterPrivateSubLoad() {
	a.VarsFormatMap = make(map[string]string)
	for _, v := range a.Vars {
		// 检查是否是 env: 开头的环境变量引用
		value := v.Value
		if strings.HasPrefix(value, "env:") {
			// 移除 env: 前缀和后面的所有斜杠
			envName := strings.TrimPrefix(value, "env:")
			envName = strings.TrimLeft(envName, "/")

			// 从环境变量读取值
			envValue := os.Getenv(envName)
			if envValue != "" {
				value = envValue
			}
			// 如果环境变量不存在或为空，保持原值
		}

		formatValue := fanstr.FormatFieldNameMap(value, a.VarsFormatMap)
		a.VarsFormatMap[v.Key] = formatValue
	}

	urlEncodedVarsMap := make(map[string]string)
	for k, v := range a.VarsFormatMap {
		urlEncodedVarsMap[k] = url.QueryEscape(v)
	}

	a.RewritesFormatMap = make(map[string]string)
	for _, v := range a.Rewrites {
		formatValue := fanstr.FormatFieldNameMap(v.Value, urlEncodedVarsMap)
		a.RewritesFormatMap[v.Key] = formatValue
	}
}
