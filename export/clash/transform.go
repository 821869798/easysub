package clash

import (
	"github.com/821869798/easysub/config"
	"github.com/821869798/easysub/define"
	"net/url"
	"strconv"
	"strings"
)

func getRulesetInterval() int {
	if config.Global.ManagedConfig != nil && config.Global.ManagedConfig.RulesetUpdateInterval > 0 {
		return config.Global.ManagedConfig.RulesetUpdateInterval
	}
	return 86400 * 5 // fallback: 5 days
}

func parseRuleParts(input string) (string, string, string, bool) {
	ruleType, rest, ok := strings.Cut(input, ",")
	if !ok {
		return ruleType, "", "", false
	}
	value, extra, ok := strings.Cut(rest, ",")
	if !ok {
		return ruleType, value, "", true
	}
	return ruleType, value, extra, true
}

func transformRuleConverterGeo(input, group string, outputContentWriter *strings.Builder, ruleProviders map[string]interface{}) {
	ruleType, value, extra, hasValue := parseRuleParts(input)
	var builder strings.Builder

	if !hasValue {
		builder.WriteString(ruleType)
		builder.WriteString(",")
		builder.WriteString(group)
	} else {
		builder.WriteString(ruleType)
		builder.WriteString(",")
		builder.WriteString(value)
		builder.WriteString(",")
		builder.WriteString(group)
		if extra == "no-resolve" {
			builder.WriteString(",")
			builder.WriteString(extra)
		}
	}

	typeName := strings.ToLower(ruleType)
	rulsetConfig, ok := config.Global.NodePref.ClashRulesets[typeName]
	if ok && hasValue {
		argName := strings.ToLower(value)
		tagName := typeName + "_" + argName
		realUrl := strings.ReplaceAll(rulsetConfig.UrlFormat, "%s", argName)
		ruleProviders[tagName] = map[string]interface{}{
			"type":     "http",
			"format":   "mrs",
			"url":      realUrl,
			"behavior": rulsetConfig.Type,
			"interval": getRulesetInterval(),
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
	ruleType, value, extra, hasValue := parseRuleParts(input)
	var builder strings.Builder

	if !hasValue {
		builder.WriteString(ruleType)
		builder.WriteString(",")
		builder.WriteString(group)
	} else {
		builder.WriteString(ruleType)
		builder.WriteString(",")
		builder.WriteString(value)
		builder.WriteString(",")
		builder.WriteString(group)
		if extra == "no-resolve" {
			builder.WriteString(",")
			builder.WriteString(extra)
		}
	}

	buildStr := builder.String()
	outputContentWriter.WriteString("  - " + buildStr + "\n")
}

func transformRuleToOptimize(input, group string, outputContentWriter *strings.Builder, rulesetOp *ruleSetOptimize) {
	ruleType, value, extra, hasValue := parseRuleParts(input)
	var builder strings.Builder

	noResolve := false
	if !hasValue {
		builder.WriteString(ruleType)
		builder.WriteString(",")
		builder.WriteString(group)
	} else {
		builder.WriteString(ruleType)
		builder.WriteString(",")
		builder.WriteString(value)
		builder.WriteString(",")
		builder.WriteString(group)
		if extra == "no-resolve" {
			builder.WriteString(",")
			builder.WriteString(extra)
			noResolve = true
		}
	}

	buildStr := "  - " + builder.String() + "\n"

	switch ruleType {
	case "DOMAIN-SUFFIX":
		if hasValue && value != "" {
			rulesetOp.DomainOptimize = append(rulesetOp.DomainOptimize, QuotedString("+."+value))
			if len(rulesetOp.DomainOptimize) < OptimizeMinCount {
				rulesetOp.DomainOrigin.WriteString(buildStr)
			}
			return
		}
	case "DOMAIN":
		if hasValue && value != "" {
			rulesetOp.DomainOptimize = append(rulesetOp.DomainOptimize, QuotedString(value))
			if len(rulesetOp.DomainOptimize) < OptimizeMinCount {
				rulesetOp.DomainOrigin.WriteString(buildStr)
			}
			return
		}
	case "IP-CIDR", "IP-CIDR6":
		if noResolve && hasValue && value != "" {
			// 只有noResolve的值得优化
			rulesetOp.IpCidrOptimize = append(rulesetOp.IpCidrOptimize, QuotedString(value))
			if len(rulesetOp.IpCidrOptimize) < OptimizeMinCount {
				rulesetOp.IpCidrOrigin.WriteString(buildStr)
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
			"interval": getRulesetInterval(),
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
