package config

import (
	"github.com/821869798/fankit/fanstr"
	"net/url"
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
		formatValue := fanstr.FormatFieldNameMap(v.Value, a.VarsFormatMap)
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
