package clash

import (
	"bufio"
	"github.com/821869798/easysub/define"
	"github.com/821869798/easysub/export/common"
	"strings"
)

type ClashRuleSetConvertType int

const (
	ClashRuleSetConvertType_Domain ClashRuleSetConvertType = iota
	ClashRuleSetConvertType_IPCIDR
)

var (
	convertRuleTypesMap = map[ClashRuleSetConvertType][]string{
		ClashRuleSetConvertType_Domain: {
			"DOMAIN-SUFFIX",
			"DOMAIN",
		},
		ClashRuleSetConvertType_IPCIDR: {
			"IP-CIDR",
			"IP-CIDR6",
		},
	}
)

func ConvertRulesetContentToText(x *define.RulesetContent, convertType ClashRuleSetConvertType) string {
	retrievedRules := common.ConvertRuleset(x.RuleContent, x.RuleType)
	scanner := bufio.NewScanner(strings.NewReader(retrievedRules))
	convertRuleTypes := convertRuleTypesMap[convertType]
	rulesetOp := &ruleSetOptimize{}
	for scanner.Scan() {
		strLine := strings.TrimSpace(scanner.Text()) // 修剪空白
		strLine = strings.TrimSuffix(strLine, "\r")  // 修剪回车
		if strLine == "" || strings.HasPrefix(strLine, ";") || strings.HasPrefix(strLine, "#") || strings.HasPrefix(strLine, "//") {
			continue
		}

		hasType := false
		for _, ruleType := range convertRuleTypes {
			if strings.HasPrefix(strLine, ruleType) {
				hasType = true
				break
			}
		}
		if !hasType {
			continue
		}

		if strings.Contains(strLine, "//") {
			strLine = strLine[:strings.Index(strLine, "//")]
			strLine = strings.TrimSpace(strLine)
		}

		transformRuleToOptimize(strLine, "", nil, rulesetOp)
	}
	switch convertType {
	case ClashRuleSetConvertType_Domain:
		return quotedStringArrayJoin(rulesetOp.DomainOptimize, "\n")
	case ClashRuleSetConvertType_IPCIDR:
		return quotedStringArrayJoin(rulesetOp.IpCidrOptimize, "\n")
	default:
		return ""
	}
}

func quotedStringArrayJoin(elems []QuotedString, sep string) string {
	if len(elems) == 0 {
		return ""
	}
	var builder strings.Builder
	for i, elem := range elems {
		if i > 0 {
			builder.WriteString(sep)
		}
		builder.WriteString(string(elem))
	}
	return builder.String()
}
