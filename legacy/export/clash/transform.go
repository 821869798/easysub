package clash

import (
	"net/url"
	"strconv"
	"strings"

	"github.com/821869798/easysub/config"
	"github.com/821869798/easysub/define"
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

// writeRuleLine writes a formatted rule line directly into the writer, avoiding intermediate allocations.
// Format: "  - RULETYPE,value,group[,no-resolve]\n" or "  - RULETYPE,group\n"
func writeRuleLine(w *strings.Builder, ruleType, value, extra, group string, hasValue bool) {
	w.WriteString("  - ")
	w.WriteString(ruleType)
	w.WriteString(",")
	if hasValue {
		w.WriteString(value)
		w.WriteString(",")
	}
	w.WriteString(group)
	if extra == "no-resolve" {
		w.WriteString(",no-resolve")
	}
	w.WriteByte('\n')
}

func transformRuleConverterGeo(input, group string, outputContentWriter *strings.Builder, ruleProviders map[string]interface{}) {
	ruleType, value, extra, hasValue := parseRuleParts(input)

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
		outputContentWriter.WriteString("  - RULE-SET,")
		outputContentWriter.WriteString(tagName)
		outputContentWriter.WriteByte(',')
		outputContentWriter.WriteString(group)
		outputContentWriter.WriteByte('\n')
	} else {
		writeRuleLine(outputContentWriter, ruleType, value, extra, group, hasValue)
	}
}

func transformRuleToCommon(input, group string, outputContentWriter *strings.Builder) {
	ruleType, value, extra, hasValue := parseRuleParts(input)
	writeRuleLine(outputContentWriter, ruleType, value, extra, group, hasValue)
}

func transformRuleToOptimize(input, group string, outputContentWriter *strings.Builder, rulesetOp *ruleSetOptimize) {
	ruleType, value, extra, hasValue := parseRuleParts(input)

	noResolve := extra == "no-resolve"

	switch ruleType {
	case "DOMAIN-SUFFIX":
		if hasValue && value != "" {
			rulesetOp.DomainOptimize = append(rulesetOp.DomainOptimize, QuotedString("+."+value))
			if len(rulesetOp.DomainOptimize) < OptimizeMinCount {
				writeRuleLine(&rulesetOp.DomainOrigin, ruleType, value, extra, group, hasValue)
			}
			return
		}
	case "DOMAIN":
		if hasValue && value != "" {
			rulesetOp.DomainOptimize = append(rulesetOp.DomainOptimize, QuotedString(value))
			if len(rulesetOp.DomainOptimize) < OptimizeMinCount {
				writeRuleLine(&rulesetOp.DomainOrigin, ruleType, value, extra, group, hasValue)
			}
			return
		}
	case "IP-CIDR", "IP-CIDR6":
		if noResolve && hasValue && value != "" {
			// 只有noResolve的值得优化
			rulesetOp.IpCidrOptimize = append(rulesetOp.IpCidrOptimize, QuotedString(value))
			if len(rulesetOp.IpCidrOptimize) < OptimizeMinCount {
				writeRuleLine(&rulesetOp.IpCidrOrigin, ruleType, value, extra, group, hasValue)
			}
			return
		}
	}

	if outputContentWriter != nil {
		writeRuleLine(outputContentWriter, ruleType, value, extra, group, hasValue)
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
		sb.WriteString(extraSetting.RequestHostWithProtocol)
		sb.WriteString("/ruleset?target=clash&behavior=")
		sb.WriteString(behaviorType)
		sb.WriteString("&url=")
		for i, path := range x.RulePath {
			if i > 0 {
				sb.WriteByte('|')
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
			"format":   "text",
			"behavior": behaviorType,
			"payload":  rules,
		}

		if strings.Contains(extraSetting.UserAgent, "Stash/") {
			// 如果是Stash，使用特殊的payload格式
			ruleProvider["payload"] = quotedStringArrayJoin(rules, "\n")
		}
	}

	ruleProviders[realRuleName] = ruleProvider
	return realRuleName
}
