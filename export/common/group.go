package common

import (
	"github.com/821869798/easysub/define"
	"github.com/821869798/easysub/modules/util"
	"strconv"
	"strings"
)

const (
	groupIDMatcherPattern = `(^!!(?:GROUPID|INSERT)=([\d\-+!,]+)(?:!!(.*))?$)`
	groupMatcherPattern   = `(^!!(?:GROUP)=(.+?)(?:!!(.*))?$)`
	typeMatcherPattern    = `(^!!(?:TYPE)=(.+?)(?:!!(.*))?$)`
	portMatcherPattern    = `(^!!(?:PORT)=(.+?)(?:!!(.*))?$)`
	serverMatcherPattern  = `(^!!(?:SERVER)=(.+?)(?:!!(.*))?$)`
)

var proxyTypeNames = map[define.ProxyType]string{
	define.ProxyType_Shadowsocks: "SS",
	define.ProxyType_VMess:       "VMESS",
	define.ProxyType_Trojan:      "TROJAN",
	define.ProxyType_Snell:       "SNELL",
	define.ProxyType_HTTP:        "HTTP",
	define.ProxyType_HTTPS:       "HTTPS",
	define.ProxyType_SOCKS5:      "SOCKS5",
	define.ProxyType_WireGuard:   "WIREGUARD",
	define.ProxyType_VLESS:       "VLESS",
	define.ProxyType_TUIC:        "TUIC",
	define.ProxyType_ANYTLS:      "ANYTLS",
	define.ProxyType_Hysteria2:   "HYSTERIA2",
}

func GroupGenerate(rule string, nodeList []*define.Proxy, filteredNodeList []string, addDirect bool) []string {
	if strings.HasPrefix(rule, "[]") && addDirect {
		filteredNodeList = append(filteredNodeList, rule[2:])
	} else {
		selected := make(map[string]struct{}, len(filteredNodeList))
		for _, remark := range filteredNodeList {
			selected[remark] = struct{}{}
		}
		for _, x := range nodeList {
			b, realRule := applyMatcher(rule, x)
			if _, exists := selected[x.Remark]; b && !exists && (realRule == "" || util.RegMatch(x.Remark, realRule)) {
				filteredNodeList = append(filteredNodeList, x.Remark)
				selected[x.Remark] = struct{}{}
			}
		}
	}
	return filteredNodeList
}

func applyMatcher(rule string, node *define.Proxy) (bool, string) {
	emptyStr := ""
	retRealRule := ""
	target := ""

	if strings.HasPrefix(rule, "!!GROUP=") {
		if util.RegGetMatch(rule, groupMatcherPattern, &emptyStr, &target, &retRealRule) == nil {
			return util.RegFind(node.Group, target), retRealRule
		}
		return false, ""
	} else if strings.HasPrefix(rule, "!!GROUPID=") || strings.HasPrefix(rule, "!!INSERT=") {
		dir := 1
		if strings.HasPrefix(rule, "!!INSERT=") {
			dir = -1
		}

		if util.RegGetMatch(rule, groupIDMatcherPattern, &emptyStr, &target, &retRealRule) == nil {
			return matchRange(target, dir*int(node.GroupId)), retRealRule
		}
		return false, ""
	} else if strings.HasPrefix(rule, "!!TYPE=") {
		if node.Type == define.ProxyType_Unknown {
			return false, ""
		}
		if util.RegGetMatch(rule, typeMatcherPattern, &emptyStr, &target, &retRealRule) == nil {
			return util.RegMatch(proxyTypeNames[node.Type], target), retRealRule
		}
		return false, ""
	} else if strings.HasPrefix(rule, "!!PORT=") {
		if util.RegGetMatch(rule, portMatcherPattern, &emptyStr, &target, &retRealRule) == nil {
			return matchRange(target, int(node.Port)), retRealRule
		}
		return false, ""
	} else if strings.HasPrefix(rule, "!!SERVER=") {
		if util.RegGetMatch(rule, serverMatcherPattern, &emptyStr, &target, &retRealRule) == nil {
			return util.RegFind(node.Hostname, target), retRealRule
		}
		return false, ""
	} else {
		retRealRule = rule
	}

	return true, retRealRule
}

func matchRange(rangeStr string, target int) bool {
	hasPositive := false
	matchedPositive := false
	for _, item := range strings.Split(rangeStr, ",") {
		item = strings.TrimSpace(item)
		negated := strings.HasPrefix(item, "!")
		if negated {
			item = strings.TrimPrefix(item, "!")
		}

		itemMatches := matchRangeItem(item, target)
		if negated {
			if itemMatches {
				return false
			}
			continue
		}
		hasPositive = true
		if itemMatches {
			matchedPositive = true
		}
	}
	return !hasPositive || matchedPositive
}

func matchRangeItem(item string, target int) bool {
	if strings.HasSuffix(item, "+") {
		minimum, err := strconv.Atoi(strings.TrimSuffix(item, "+"))
		return err == nil && target >= minimum
	}
	if strings.HasSuffix(item, "-") && !strings.HasPrefix(item, "-") {
		maximum, err := strconv.Atoi(strings.TrimSuffix(item, "-"))
		return err == nil && target <= maximum
	}
	if beginText, endText, ok := strings.Cut(item, "-"); ok && beginText != "" && endText != "" {
		begin, beginErr := strconv.Atoi(beginText)
		end, endErr := strconv.Atoi(endText)
		return beginErr == nil && endErr == nil && target >= begin && target <= end
	}
	value, err := strconv.Atoi(item)
	return err == nil && target == value
}
