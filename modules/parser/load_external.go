package parser

import (
	define2 "github.com/821869798/easysub/define"
	"strings"

	"github.com/821869798/easysub/config"
	"github.com/821869798/easysub/modules/fetch"
	"github.com/821869798/easysub/modules/render"
	"github.com/821869798/easysub/modules/util"
	"gopkg.in/ini.v1"
)

func LoadExternalConfig(path string, ext *define2.ExternalConfig) error {
	configContent, err := fetch.FetchFile(path, config.Global.Common.ProxyConfig, config.Global.Advance.CacheConfig, false)
	if err != nil {
		return err
	}

	var buff string
	if buff, err = render.RenderTemplate(configContent, ext.TplArgs); err != nil {
		return err
	}
	cfg, err := ini.ShadowLoad([]byte(buff))
	if err != nil {
		return err
	}
	customSection := cfg.Section("custom")

	if customSection.HasKey("custom_proxy_group") {
		customProxyGroupStrs := customSection.Key("custom_proxy_group").ValueWithShadows()
		if len(customProxyGroupStrs) > 0 {
			ext.CustomProxyGroups = ProxyGroupFromIni(customProxyGroupStrs)
		}
	}

	var rulesetName string
	if customSection.HasKey("ruleset") {
		rulesetName = "ruleset"
	} else {
		rulesetName = "surge_ruleset"
	}

	rulesetStrs := customSection.Key(rulesetName).ValueWithShadows()
	if len(rulesetStrs) > 0 {
		ext.RulesetConfigs = RulesetFromIni(rulesetStrs)
	}

	if customSection.HasKey("clash_rule_base") {
		ext.ClashRuleBase = customSection.Key("clash_rule_base").Value()
	}

	if customSection.HasKey("singbox_rule_base") {
		ext.SingboxRuleBase = customSection.Key("singbox_rule_base").Value()
	}

	if customSection.HasKey("overwrite_original_rules") {
		ext.OverwriteOriginalRules = customSection.Key("overwrite_original_rules").MustBool()
	}
	if customSection.HasKey("enable_rule_generator") {
		ext.EnableRuleGenerator = customSection.Key("enable_rule_generator").MustBool()
	}

	return nil
}

func ProxyGroupFromIni(arr []string) []*define2.ProxyGroupConfig {
	confs := make([]*define2.ProxyGroupConfig, 0)
	for _, x := range arr {
		rulesUpperBound := 0
		conf := &define2.ProxyGroupConfig{}

		vArray := strings.Split(x, "`")
		if len(vArray) < 3 {
			continue
		}
		conf.Name = vArray[0]
		typeStr := vArray[1]

		rulesUpperBound = len(vArray)
		switch typeStr {
		case "select":
			conf.Type = define2.ProxyGroupType_Select
		case "relay":
			conf.Type = define2.ProxyGroupType_Relay
		case "url-test":
			conf.Type = define2.ProxyGroupType_URLTest
		case "fallback":
			conf.Type = define2.ProxyGroupType_Fallback
		case "load-balance":
			conf.Type = define2.ProxyGroupType_LoadBalance
		case "ssid":
			conf.Type = define2.ProxyGroupType_SSID
		default:
			continue
		}

		if conf.Type == define2.ProxyGroupType_URLTest || conf.Type == define2.ProxyGroupType_LoadBalance || conf.Type == define2.ProxyGroupType_Fallback {
			if len(vArray) < 5 {
				continue
			}
			rulesUpperBound -= 2
			conf.Url = vArray[rulesUpperBound]
			parseGroupTimes(vArray[rulesUpperBound+1], &conf.Interval, &conf.Timeout, &conf.Tolerance)
		}

		for i := 2; i < rulesUpperBound; i++ {
			if strings.HasPrefix(vArray[i], "!!PROVIDER=") {
				list := strings.Split(vArray[i][11:], ",")
				conf.UsingProvider = append(conf.UsingProvider, list...)
			} else {
				conf.Proxies = append(conf.Proxies, vArray[i])
			}
		}
		confs = append(confs, conf)
	}
	return confs
}

func parseGroupTimes(src string, args ...*int) {
	bpos := 0
	epos := strings.Index(src, ",")
	for _, x := range args {
		if x != nil {
			*x = util.Str2Int(src[bpos:epos])
		}
		if epos != -1 {
			bpos = epos + 1
			epos = strings.Index(src[bpos:], ",")
		} else {
			return
		}
	}
}

func RulesetFromIni(arr []string) []*define2.RulesetConfig {
	var confs []*define2.RulesetConfig

	for _, x := range arr {
		conf := &define2.RulesetConfig{}
		pos := strings.Index(x, ",")
		if pos == -1 {
			continue
		}
		conf.Group = x[:pos]
		if strings.HasPrefix(x[pos+1:], "[]") {
			conf.Url = x[pos+1:]
			confs = append(confs, conf)
			continue
		}
		epos := strings.LastIndex(x, ",")
		if pos != epos {
			conf.Interval = util.Str2Int(x[epos+1:])
			conf.Url = x[pos+1 : epos]
		} else {
			conf.Url = x[pos+1:]
		}
		confs = append(confs, conf)
	}

	return confs
}
