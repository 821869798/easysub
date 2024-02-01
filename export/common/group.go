package common

import (
	"github.com/821869798/easysub/define"
	"github.com/821869798/easysub/modules/util"
	"strconv"
	"strings"
)

func GroupGenerate(rule string, nodeList []*define.Proxy, filteredNodeList []string, addDirect bool) []string {
	if strings.HasPrefix(rule, "[]") && addDirect {
		filteredNodeList = append(filteredNodeList, rule[2:])
	} else {
		for _, x := range nodeList {
			b, realRule := applyMatcher(rule, x)
			if b && (realRule == "" || util.RegMatch(x.Remark, realRule)) && util.FindString(filteredNodeList, x.Remark) == -1 {
				filteredNodeList = append(filteredNodeList, x.Remark)
			}
		}
	}
	return filteredNodeList
}

func applyMatcher(rule string, node *define.Proxy) (bool, string) {
	groupIdRegex := `(^!!(?:GROUPID|INSERT)=([\d\-+!,]+)(?:!!(.*))?$)`
	groupRegex := `(^!!(?:GROUP)=(.+?)(?:!!(.*))?$)`
	typeRegex := `(^!!(?:TYPE)=(.+?)(?:!!(.*))?$)`
	portRegex := `(^!!(?:PORT)=(.+?)(?:!!(.*))?$)`
	serverRegex := `(^!!(?:SERVER)=(.+?)(?:!!(.*))?$)`
	types := map[define.ProxyType]string{
		define.ProxyType_Shadowsocks: "SS",
		define.ProxyType_VMess:       "VMESS",
		define.ProxyType_Trojan:      "TROJAN",
		define.ProxyType_Snell:       "SNELL",
		define.ProxyType_HTTP:        "HTTP",
		define.ProxyType_HTTPS:       "HTTPS",
		define.ProxyType_SOCKS5:      "SOCKS5",
		define.ProxyType_WireGuard:   "WIREGUARD",
		//define.HY:               "HYSTERIA",
		//define.Hysteria2:              "HYSTERIA2",
	}

	emptyStr := ""
	retRealRule := ""
	target := ""

	if strings.HasPrefix(rule, "!!GROUP=") {
		if util.RegGetMatch(rule, groupRegex, &emptyStr, &target, &retRealRule) != nil {
			return util.RegFind(node.Group, target), retRealRule
		} else {
			return false, ""
		}
	} else if strings.HasPrefix(rule, "!!GROUPID=") || strings.HasPrefix(rule, "!!INSERT=") {
		dir := 1
		if strings.HasPrefix(rule, "!!INSERT=") {
			dir = -1
		}

		if util.RegGetMatch(rule, groupIdRegex, &emptyStr, &target, &retRealRule) != nil {
			return matchRange(target, dir*int(node.GroupId)), retRealRule
		} else {
			return false, ""
		}
	} else if strings.HasPrefix(rule, "!!TYPE=") {
		if node.Type == define.ProxyType_Unknown {
			return false, ""
		}
		if util.RegGetMatch(rule, typeRegex, &emptyStr, &target, &retRealRule) != nil {
			return util.RegMatch(types[node.Type], target), retRealRule
		} else {
			return false, ""
		}
	} else if strings.HasPrefix(rule, "!!PORT=") {
		if util.RegGetMatch(rule, portRegex, &emptyStr, &target, &retRealRule) != nil {
			return matchRange(target, int(node.Port)), retRealRule
		} else {
			return false, ""
		}
	} else if strings.HasPrefix(rule, "!!SERVER=") {
		if util.RegGetMatch(rule, serverRegex, &emptyStr, &target, &retRealRule) != nil {
			return util.RegFind(node.Hostname, target), retRealRule
		}
	} else {
		retRealRule = rule
	}

	return true, retRealRule
}

func matchRange(rangeStr string, target int) bool {
	vArray := strings.Split(rangeStr, ",")
	match := false
	rangeBeginStr, rangeEndStr := "", ""
	rangeBegin, rangeEnd := 0, 0
	regNum := `(-?\d+)`
	regRange := `(\d+)-(\d+)`
	regNot := `\!(-?\d+)`
	regNotRange := `\!(\d+)-(\d+)`
	regLess := `(\d+)-`
	regMore := `(\d+)\+`
	emptyStr := ""
	for _, x := range vArray {
		if util.RegMatch(x, regNum) {
			intX, _ := strconv.Atoi(x)
			if intX == target {
				match = true
			}
		} else if util.RegMatch(x, regRange) {
			_ = util.RegGetMatch(x, regRange, &emptyStr, &rangeBeginStr, &rangeEndStr)
			rangeBegin, _ = strconv.Atoi(rangeBeginStr)
			rangeEnd, _ = strconv.Atoi(rangeEndStr)
			if target >= rangeBegin && target <= rangeEnd {
				match = true
			}
		} else if util.RegMatch(x, regNot) {
			match = true
			intX, _ := strconv.Atoi(util.RegReplace(x, regNot, "$1", false))
			if intX == target {
				match = false
			}
		} else if util.RegMatch(x, regNotRange) {
			match = true
			_ = util.RegGetMatch(x, regRange, &emptyStr, &rangeBeginStr, &rangeEndStr)
			rangeBegin, _ = strconv.Atoi(rangeBeginStr)
			rangeEnd, _ = strconv.Atoi(rangeEndStr)
			if target >= rangeBegin && target <= rangeEnd {
				match = false
			}
		} else if util.RegMatch(x, regLess) {
			v := util.RegReplace(x, regLess, "$1", false)
			intV, _ := strconv.Atoi(v)
			if intV >= target {
				match = true
			}
		} else if util.RegMatch(x, regMore) {
			v := util.RegReplace(x, regMore, "$1", false)
			intV, _ := strconv.Atoi(v)
			if intV <= target {
				match = true
			}
		}
	}
	return match
}
