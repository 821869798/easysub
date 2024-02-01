package common

import (
	"bufio"
	"github.com/821869798/easysub/define"
	"github.com/821869798/easysub/modules/util"
	"strconv"
	"strings"
)

// basicTypes 定义基础规则类型
var basicTypes = []string{
	"DOMAIN",
	"DOMAIN-SUFFIX",
	"DOMAIN-KEYWORD",
	"IP-CIDR",
	"SRC-IP-CIDR",
	"GEOIP",
	"MATCH",
	"FINAL",
}

// Rule type arrays for different platforms
var (
	ClashRuleTypes   = append(basicTypes, "IP-CIDR6", "SRC-PORT", "DST-PORT", "PROCESS-NAME")
	Surge2RuleTypes  = append(basicTypes, "IP-CIDR6", "USER-AGENT", "URL-REGEX", "PROCESS-NAME", "IN-PORT", "DEST-PORT", "SRC-IP")
	SurgeRuleTypes   = append(basicTypes, "IP-CIDR6", "USER-AGENT", "URL-REGEX", "AND", "OR", "NOT", "PROCESS-NAME", "IN-PORT", "DEST-PORT", "SRC-IP")
	QuanXRuleTypes   = append(basicTypes, "USER-AGENT", "HOST", "HOST-SUFFIX", "HOST-KEYWORD")
	SurfRuleTypes    = append(basicTypes, "IP-CIDR6", "PROCESS-NAME", "IN-PORT", "DEST-PORT", "SRC-IP")
	SingBoxRuleTypes = append(basicTypes, "IP-VERSION", "INBOUND", "PROTOCOL", "NETWORK", "GEOSITE", "SRC-GEOIP", "DOMAIN-REGEX", "PROCESS-NAME", "PROCESS-PATH", "PACKAGE-NAME", "PORT", "PORT-RANGE", "SRC-PORT", "SRC-PORT-RANGE", "USER", "USER-ID")
)

var (
	ClashRuleTypesMap   map[string]bool
	Surge2RuleTypesMap  map[string]bool
	SurgeRuleTypesMap   map[string]bool
	QuanXRuleTypesMap   map[string]bool
	SurfRuleTypesMap    map[string]bool
	SingBoxRuleTypesMap map[string]bool
)

func init() {
	// 初始化规则类型映射
	ClashRuleTypesMap = make(map[string]bool)
	Surge2RuleTypesMap = make(map[string]bool)
	SurgeRuleTypesMap = make(map[string]bool)
	QuanXRuleTypesMap = make(map[string]bool)
	SurfRuleTypesMap = make(map[string]bool)
	SingBoxRuleTypesMap = make(map[string]bool)
	for _, ruleType := range ClashRuleTypes {
		ClashRuleTypesMap[ruleType] = true
	}
	for _, ruleType := range Surge2RuleTypes {
		Surge2RuleTypesMap[ruleType] = true
	}
	for _, ruleType := range SurgeRuleTypes {
		SurgeRuleTypesMap[ruleType] = true
	}
	for _, ruleType := range QuanXRuleTypes {
		QuanXRuleTypesMap[ruleType] = true
	}
	for _, ruleType := range SurfRuleTypes {
		SurfRuleTypesMap[ruleType] = true
	}
	for _, ruleType := range SingBoxRuleTypes {
		SingBoxRuleTypesMap[ruleType] = true
	}
}

func ConvertRuleset(content string, ruleType define.RulesetType) string {
	var output strings.Builder
	if ruleType == define.RULESET_SURGE {
		return content
	}

	if util.RegFind(content, "^payload:\\r?\\n") {
		contentFormat := util.RegReplace(util.RegReplace(content, "payload:\\r?\\n", "", true), `(\s?^\s*-\s+('|"?)(.*)\1$)`, "\n$2", true)
		if ruleType == define.RULESET_CLASH_CLASSICAL {
			return contentFormat
		}

		scanner := bufio.NewScanner(strings.NewReader(contentFormat))
		for scanner.Scan() {
			strLine := strings.TrimSpace(scanner.Text()) // 修剪空白
			strLine = strings.TrimSuffix(strLine, "\r")  // 修剪回车

			if idx := strings.Index(strLine, "//"); idx != -1 {
				strLine = strings.TrimSpace(strLine[:idx])
			}

			// 跳过空行或注释行
			if strLine == "" || strings.HasPrefix(strLine, ";") || strings.HasPrefix(strLine, "#") || strings.HasPrefix(strLine, "//") {
				continue
			}

			if idx := strings.Index(strLine, "/"); idx != -1 {
				if util.IsIPv4(strLine[:idx]) {
					output.WriteString("IP-CIDR,")
				} else {
					output.WriteString("IP-CIDR,")
				}
			} else if strings.HasPrefix(strLine, ".") || strings.HasPrefix(strLine, "+.") {
				keywordFlag := false
				for strings.HasSuffix(strLine, ".*") {
					keywordFlag = true
					strLine = strings.TrimSuffix(strLine, ".*")
				}
				output.WriteString("DOMAIN-")
				if keywordFlag {
					output.WriteString("KEYWORD,")
				} else {
					output.WriteString("SUFFIX,")
				}
				if len(strLine) > 0 && strLine[0] == '.' {
					// 如果第一个字符是'.'，删除第一个字符
					strLine = strLine[1:]
				} else if len(strLine) >= 2 {
					// 如果第一个字符不是'.'，删除前两个字符
					strLine = strLine[2:]
				} else {
					// 长度不足2，清空字符串
					strLine = ""
				}
			} else {
				output.WriteString("DOMAIN,")
			}
			output.WriteString(strLine)
			output.WriteRune('\n')
		}
		return output.String()
	} else {
		// QuanX type
		contentFormat := util.RegReplace(content, "^(?i:host)", "DOMAIN", true) //translate type
		contentFormat = util.RegReplace(contentFormat, "^(?i:ip6-cidr)", "IP-CIDR6", true)
		contentFormat = util.RegReplace(contentFormat, "^((?i:DOMAIN(?:-(?:SUFFIX|KEYWORD))?|IP-CIDR6?|USER-AGENT),)\\s*?(\\S*?)(?:,(?!no-resolve).*?)(,no-resolve)?$", "\\U$1\\E$2${3:-}", true) //remove group
		return contentFormat
	}
}

func TransformRuleToCommon(input, group string, noResolveOnly bool) string {
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
		if len(temp) > 2 && (!noResolveOnly || temp[2] == "no-resolve") {
			builder.WriteString(",")
			builder.WriteString(temp[2])
		}
	}

	return builder.String()
}

func ProcessRemark(remark string, remarksList []string, procComma bool) string {
	// Replace every '=' with '-' in the remark string to avoid parse errors from the clients.
	// Surge is tested to yield an error when handling '=' in the remark string,
	// not sure if other clients have the same problem.
	remark = strings.ReplaceAll(remark, "=", "-")

	if procComma {
		if strings.Contains(remark, ",") {
			remark = "\"" + remark + "\""
		}
	}

	tempRemark := remark
	cnt := 2
	for contains(remarksList, tempRemark) {
		tempRemark = remark + " " + strconv.Itoa(cnt)
		cnt++
	}
	return tempRemark
}

// Helper function to check if a slice contains a string
func contains(slice []string, str string) bool {
	for _, s := range slice {
		if s == str {
			return true
		}
	}
	return false
}
