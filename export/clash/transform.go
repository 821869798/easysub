package clash

import (
	"github.com/821869798/easysub/config"
	"github.com/821869798/easysub/define"
	"net/url"
	"strconv"
	"strings"
)

const (
	rulesetInterval = 86400 * 3 // 3 days
)

func transformRuleConverterGeo(input, group string, outputContentWriter *strings.Builder, ruleProviders map[string]interface{}) {
	temp := strings.Split(input, ",")
	var builder strings.Builder

	if len(temp) < 2 {
		builder.WriteString(temp[0])
		builder.WriteString(",")
		builder.WriteString(group)
	} else {
		builder.WriteString(temp[0])
		builder.WriteString(",")
		builder.WriteString(temp[1])
		builder.WriteString(",")
		builder.WriteString(group)
		if len(temp) > 2 && temp[2] == "no-resolve" {
			builder.WriteString(",")
			builder.WriteString(temp[2])
		}
	}

	typeName := strings.ToLower(temp[0])
	rulsetConfig, ok := config.Global.NodePref.ClashRulesets[typeName]
	if ok {
		argName := strings.ToLower(temp[1])
		tagName := typeName + "_" + argName
		realUrl := strings.ReplaceAll(rulsetConfig.UrlFormat, "%s", argName)
		ruleProviders[tagName] = map[string]interface{}{
			"type":     "http",
			"format":   "mrs",
			"url":      realUrl,
			"behavior": rulsetConfig.Type,
			"interval": rulesetInterval, // 3 days
			"proxy":    "DIRECT",
			"path":     "./mrs/" + typeName + "/" + argName + ".mrs",
		}
		outputContentWriter.WriteString("  - RULE-SET," + tagName + "," + group + "\n")
	} else {
		buildStr := builder.String()
		outputContentWriter.WriteString("  - " + buildStr + "\n")
	}
}

func transformRuleToCommon(input, group string, outputContentWriter *strings.Builder) {
	temp := strings.Split(input, ",")
	var builder strings.Builder

	if len(temp) < 2 {
		builder.WriteString(temp[0])
		builder.WriteString(",")
		builder.WriteString(group)
	} else {
		builder.WriteString(temp[0])
		builder.WriteString(",")
		builder.WriteString(temp[1])
		builder.WriteString(",")
		builder.WriteString(group)
		if len(temp) > 2 && temp[2] == "no-resolve" {
			builder.WriteString(",")
			builder.WriteString(temp[2])
		}
	}

	buildStr := builder.String()
	outputContentWriter.WriteString("  - " + buildStr + "\n")
}

func transformRuleToOptimize(input, group string, outputContentWriter *strings.Builder, rulesetOp *ruleSetOptimize) {
	temp := strings.Split(input, ",")

	var builder strings.Builder

	noResolve := false
	if len(temp) < 2 {
		builder.WriteString(temp[0])
		builder.WriteString(",")
		builder.WriteString(group)
	} else {
		builder.WriteString(temp[0])
		builder.WriteString(",")
		builder.WriteString(temp[1])
		builder.WriteString(",")
		builder.WriteString(group)
		if len(temp) > 2 && temp[2] == "no-resolve" {
			builder.WriteString(",")
			builder.WriteString(temp[2])
			noResolve = true
		}
	}

	buildStr := "  - " + builder.String() + "\n"

	switch temp[0] {
	case "DOMAIN-SUFFIX":
		rulesetOp.DomainOptimize = append(rulesetOp.DomainOptimize, QuotedString("+."+temp[1]))
		if len(rulesetOp.DomainOptimize) < OptimizeMinCount {
			rulesetOp.DomainOrigin += buildStr
		}
		return
	case "DOMAIN":
		rulesetOp.DomainOptimize = append(rulesetOp.DomainOptimize, QuotedString(temp[1]))
		rulesetOp.DomainOrigin += buildStr
		if len(rulesetOp.DomainOptimize) < OptimizeMinCount {
			rulesetOp.DomainOrigin += buildStr
		}
		return
	case "IP-CIDR", "IP-CIDR6":
		if noResolve {
			// 只有noResolve的值得优化
			rulesetOp.IpCidrOptimize = append(rulesetOp.IpCidrOptimize, QuotedString(temp[1]))
			if len(rulesetOp.IpCidrOptimize) < OptimizeMinCount {
				rulesetOp.IpCidrOrigin += buildStr
			}
			return
		}
	}

	if outputContentWriter != nil {
		outputContentWriter.WriteString(buildStr)
	}
}

func transformRuleProvider(x *define.RulesetContent, behaviorType string, rules []QuotedString, ruleProviders map[string]interface{}, extraSetting *define.ExtraSettings) string {

	ruleName := behaviorType + "_" + x.GetRuleSetName()
	// create unique name
	realRuleName := ruleName
	index := 0
	_, ok := ruleProviders[realRuleName]
	for ok {
		index++
		realRuleName = ruleName + "_" + strconv.Itoa(index)
		_, ok = ruleProviders[realRuleName]
	}

	var ruleProvider map[string]interface{}
	if extraSetting.ClashRulesetOptimizeToHttp {
		// 得到最终的url,
		var sb strings.Builder
		sb.WriteString(extraSetting.RequestHostWithProtocol + "/ruleset?target=clash&")
		sb.WriteString("behavior=" + behaviorType + "&" + "url=")
		for i, path := range x.RulePath {
			if i > 0 {
				sb.WriteString("|")
			}
			// url encode
			sb.WriteString(url.QueryEscape(path))
		}
		rulesetUrl := sb.String()
		ruleProvider = map[string]interface{}{
			"type":     "http",
			"format":   "mrs",
			"url":      rulesetUrl,
			"behavior": behaviorType,
			"interval": rulesetInterval, // 3 days
			"proxy":    "DIRECT",
			"path":     "./mrs/ruleset/" + realRuleName + ".mrs",
		}
	} else {
		ruleProvider = map[string]interface{}{
			"type":     "inline",
			"behavior": behaviorType,
			"payload":  rules,
		}
	}

	ruleProviders[realRuleName] = ruleProvider
	return realRuleName
}
