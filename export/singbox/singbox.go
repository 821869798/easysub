package singbox

import (
	"bufio"
	"encoding/json"
	"errors"
	"github.com/821869798/easysub/config"
	"github.com/821869798/easysub/define"
	"github.com/821869798/easysub/export/common"
	"github.com/821869798/easysub/modules/tpl"
	"github.com/osteele/liquid"
	"github.com/osteele/liquid/render"
	"log/slog"
	"strconv"
	"strings"
)

var (
	singboxTplEngine *liquid.Engine
)

func init() {
	singboxTplEngine = tpl.CreateDefaultEngine()
	singboxTplEngine.RegisterTag("ruleset", func(c render.Context) (string, error) {
		argString := c.TagArgs()
		// 通过空白分割argString
		args := strings.Fields(argString)
		if len(args) < 2 {
			return "", errors.New("invalid ruleset tag,arg count < 2")
		}
		typeName := strings.ToLower(args[0])
		value := strings.ToLower(args[1])
		tagName := typeName + "-" + value
		rulsetConfig, ok := config.Global.NodePref.SingboxRulesets[typeName]
		if !ok {
			return "", errors.New("config not found for ruleset: " + typeName)
		}
		realUrl := strings.ReplaceAll(rulsetConfig.UrlFormat, "%s", value)
		rulesetObject := map[string]interface{}{
			"tag":             tagName,
			"type":            "remote",
			"format":          "binary",
			"url":             realUrl,
			"download_detour": "DIRECT",
			"update_interval": "3d",
		}
		// json 序列化
		rulesetJson, err := json.Marshal(rulesetObject)
		if err != nil {
			return "", err
		}

		return string(rulesetJson), nil
	})
}

func RenderTemplate(content string, tplArgs map[string]interface{}) (string, error) {
	out, err := singboxTplEngine.ParseAndRenderString(content, tplArgs)
	if err != nil {
		return "", err
	}
	return out, err
}

func ProxyToSingBox(nodes []*define.Proxy, baseConf string, rulesetContent []*define.RulesetContent, extraProxyGroup []*define.ProxyGroupConfig, extraSetting *define.ExtraSettings) (string, error) {
	// 尝试解析baseConf，看看有没有错
	var jsonObject map[string]interface{}
	err := json.Unmarshal([]byte(baseConf), &jsonObject)
	if err != nil {
		slog.Error("sing-box base loader failed with error: " + err.Error())
	}

	proxyToSingBoxInternal(nodes, jsonObject, extraProxyGroup, extraSetting)

	if !extraSetting.EnableRuleGenerator {
		jsBytes, err := json.Marshal(jsonObject)
		if err != nil {
			slog.Error("sing-box json marshal failed with error: " + err.Error())
			return "", err
		}
		return string(jsBytes), nil
	}

	rulesetToSingBox(jsonObject, rulesetContent, extraSetting.OverwriteOriginalRules)

	jsBytes, err := json.Marshal(jsonObject)
	if err != nil {
		slog.Error("sing-box json marshal failed with error: " + err.Error())
		return "", err
	}
	return string(jsBytes), nil
}

func proxyToSingBoxInternal(nodes []*define.Proxy, jsonObject map[string]interface{}, extraProxyGroup []*define.ProxyGroupConfig, extraSetting *define.ExtraSettings) {
	outbounds := make([]interface{}, 0, 3)
	nodeList := make([]*define.Proxy, 0)
	remarksList := make([]string, 0)

	direct := map[string]interface{}{
		"type": "direct",
		"tag":  "DIRECT",
	}
	outbounds = append(outbounds, direct)
	reject := map[string]interface{}{
		"type": "block",
		"tag":  "REJECT",
	}
	outbounds = append(outbounds, reject)
	dns := map[string]interface{}{
		"type": "dns",
		"tag":  "dns-out",
	}
	outbounds = append(outbounds, dns)

	jsonObject["outbounds"] = outbounds

	for _, x := range nodes {
		proxyType := x.Type.String()
		if extraSetting.AppendProxyType.Bool() {
			x.Remark = "[" + proxyType + "] " + x.Remark
		}

		x.Remark = common.ProcessRemark(x.Remark, remarksList, false)

		udp := extraSetting.UDP
		tfo := extraSetting.TFO
		scv := extraSetting.SkipCertVerify

		udp.DefineTriBool(x.UDP)
		tfo.DefineTriBool(x.TCPFastOpen)
		scv.DefineTriBool(x.AllowInsecure)
		proxy := make(map[string]interface{})
		switch x.Type {
		case define.ProxyType_Shadowsocks:
			addSingBoxCommonMembers(proxy, x, "shadowsocks")
			proxy["method"] = x.EncryptMethod
			proxy["password"] = x.Password
			if x.Plugin != "" && x.PluginOption != "" {
				if x.Plugin == "simple-obfs" {
					x.Plugin = "obfs-local"
				}
				proxy["plugin"] = x.Plugin
				proxy["plugin_opts"] = x.PluginOption
			}
		case define.ProxyType_VMess:
			addSingBoxCommonMembers(proxy, x, "vmess")
			proxy["uuid"] = x.UserId
			proxy["alter_id"] = x.AlterId
			proxy["security"] = x.EncryptMethod

			transport := buildSingBoxTransport(x)
			if len(transport) > 0 {
				proxy["transport"] = transport
			}
		case define.ProxyType_VLESS:
			addSingBoxCommonMembers(proxy, x, "vless")
			proxy["uuid"] = x.UserId
			if x.Flow != "" {
				proxy["flow"] = x.Flow
			}

			transport := buildSingBoxTransport(x)
			if len(transport) > 0 {
				proxy["transport"] = transport
			}

		case define.ProxyType_Trojan:
			addSingBoxCommonMembers(proxy, x, "trojan")
			proxy["password"] = x.Password
			transport := buildSingBoxTransport(x)
			if len(transport) > 0 {
				proxy["transport"] = transport
			}
		case define.ProxyType_WireGuard:
			proxy["type"] = "wireguard"
			proxy["tag"] = x.Remark
			address := []interface{}{
				x.SelfIP,
			}
			if x.SelfIPv6 != "" {
				address = append(address, x.SelfIPv6)
			}
			proxy["local_address"] = address
			proxy["private_key"] = x.PrivateKey

			peer := make(map[string]interface{})
			peer["server"] = x.Hostname
			peer["server_port"] = x.Port
			peer["public_key"] = x.PublicKey
			if x.PreSharedKey != "" {
				peer["pre_shared_key"] = x.PreSharedKey
			}

			if x.AllowedIPs != "" {
				allowedIPs := strings.Split(x.AllowedIPs, ",")
				peer["allowed_ips"] = allowedIPs
			}

			if x.ClientId != "" {
				reserved := strings.Split(x.ClientId, ",")
				peer["reserved"] = reserved
			}

			peers := []interface{}{
				peer,
			}
			proxy["peers"] = peers
			proxy["mtu"] = x.Mtu
		case define.ProxyType_HTTP, define.ProxyType_HTTPS:
			addSingBoxCommonMembers(proxy, x, "http")
			proxy["username"] = x.Username
			proxy["password"] = x.Password
		case define.ProxyType_SOCKS5:
			addSingBoxCommonMembers(proxy, x, "socks")
			proxy["version"] = "5"
			proxy["username"] = x.Username
			proxy["password"] = x.Password
		default:
		}
		if x.TLSSecure {
			tls := make(map[string]interface{})
			tls["enabled"] = true
			if x.ServerName != "" {
				tls["server_name"] = x.ServerName
			} else if x.Host != "" {
				tls["server_name"] = x.Host
			}
			tls["insecure"] = scv.Bool()
			proxy["tls"] = tls
		}
		if !udp.IsUndef() && !udp.Bool() {
			proxy["network"] = "tcp"
		}
		if !tfo.IsUndef() {
			proxy["tcp_fast_open"] = tfo.Bool()
		}
		nodeList = append(nodeList, x)
		remarksList = append(remarksList, x.Remark)
		outbounds = append(outbounds, proxy)
	}
	for _, x := range extraProxyGroup {
		filteredNodeList := make([]string, 0)
		typeName := ""
		switch x.Type {
		case define.ProxyGroupType_Select:
			typeName = "selector"
		case define.ProxyGroupType_URLTest, define.ProxyGroupType_Fallback, define.ProxyGroupType_LoadBalance:
			typeName = "urltest"
		default:
		}
		for _, y := range x.Proxies {
			filteredNodeList = common.GroupGenerate(y, nodeList, filteredNodeList, true)
		}

		if len(filteredNodeList) == 0 {
			filteredNodeList = append(filteredNodeList, "DIRECT")
		}

		group := make(map[string]interface{})
		group["type"] = typeName
		group["tag"] = x.Name

		groupOutbounds := make([]interface{}, 0, len(filteredNodeList))
		for _, y := range filteredNodeList {
			groupOutbounds = append(groupOutbounds, y)
		}
		group["outbounds"] = groupOutbounds
		if x.Type == define.ProxyGroupType_URLTest {
			group["url"] = x.Url
			group["interval"] = formatSingBoxInterval(x.Interval)
			if x.Tolerance > 0 {
				group["tolerance"] = x.Tolerance
			}
		}
		outbounds = append(outbounds, group)
	}

	if config.Global.NodePref.SingboxAddClashModes {
		globalGroup := make(map[string]interface{}, 4)
		globalGroup["type"] = "selector"
		globalGroup["tag"] = "GLOBAL"
		groupOutbounds := make([]interface{}, 0, 1)
		groupOutbounds = append(groupOutbounds, "DIRECT")
		for _, x := range remarksList {
			groupOutbounds = append(groupOutbounds, x)
		}
		globalGroup["outbounds"] = groupOutbounds
		outbounds = append(outbounds, globalGroup)
	}

	jsonObject["outbounds"] = outbounds
}

func formatSingBoxInterval(interval int) string {
	result := ""
	if interval >= 3600 {
		result += strconv.Itoa(interval/3600) + "h"
		interval %= 3600
	}
	if interval >= 60 {
		result += strconv.Itoa(interval/60) + "m"
		interval %= 60
	}
	if interval > 0 {
		result += strconv.Itoa(interval) + "s"
	}
	return result
}

func addSingBoxCommonMembers(objectMap map[string]interface{}, x *define.Proxy, typeName string) {
	objectMap["type"] = typeName
	objectMap["tag"] = x.Remark
	objectMap["server"] = x.Hostname
	objectMap["server_port"] = x.Port
}

func buildSingBoxTransport(proxy *define.Proxy) map[string]interface{} {
	transport := make(map[string]interface{})
	switch proxy.TransferProtocol {
	case "http":
		if proxy.Host != "" {
			transport["host"] = proxy.Host
		}
		fallthrough
	case "ws":
		transport["type"] = proxy.TransferProtocol
		if proxy.Path == "" {
			transport["path"] = "/"
		} else {
			transport["path"] = proxy.Path
		}
		header := make(map[string]interface{})
		if proxy.Host != "" {
			header["Host"] = proxy.Host
		}
		if proxy.Edge != "" {
			header["Edge"] = proxy.Edge
		}
		transport["headers"] = header
	case "grpc":
		transport["type"] = "grpc"
		if proxy.Path != "" {
			transport["service_name"] = proxy.Path
		}
	default:
	}
	return transport
}

func rulesetToSingBox(baseRule map[string]interface{}, rulesetContentArray []*define.RulesetContent, overwriteOriginalRules bool) {
	var final string
	totalRules := 0
	var rules []interface{}
	if !overwriteOriginalRules {
		route, ok := baseRule["route"].(map[string]interface{})
		if ok {
			rulesTmp, ok := route["rules"].([]interface{})
			if ok {
				rules = rulesTmp
				route["rules"] = nil
			}
		}
	}

	routeMap, ok := baseRule["route"].(map[string]interface{})
	if !ok {
		routeMap = make(map[string]interface{})
		baseRule["route"] = routeMap
	}
	rulesetsArray, ok := routeMap["rule_set"].([]interface{})
	rulesets := make(map[string]interface{})
	if ok {
		for _, v := range rulesetsArray {
			vmap, ok := v.(map[string]interface{})
			if !ok || v == nil {
				continue
			}
			tagName, ok := vmap["tag"].(string)
			if ok && tagName != "" {
				rulesets[tagName] = vmap
			}
		}
	}

	if config.Global.NodePref.SingboxAddClashModes {
		globalObject := map[string]interface{}{
			"clash_mode": "Global",
			"outbound":   "GLOBAL",
		}
		directObject := map[string]interface{}{
			"clash_mode": "Direct",
			"outbound":   "DIRECT",
		}
		rules = append(rules, globalObject)
		rules = append(rules, directObject)
	}

	dnsObject := map[string]interface{}{
		"protocol": "dns",
		"outbound": "dns-out",
	}
	rules = append(rules, dnsObject)

	for _, x := range rulesetContentArray {
		if config.Global.Advance.MaxAllowedRules > 0 && totalRules > config.Global.Advance.MaxAllowedRules {
			break
		}
		ruleGroup := x.RuleGroup
		retrievedRules := x.RuleContent
		if retrievedRules == "" {
			slog.Warn("Failed to fetch ruleset or ruleset is empty!", slog.Any("RulePath", x.RulePath))
			continue
		}
		if strings.HasPrefix(retrievedRules, "[]") {
			strLine := retrievedRules[2:]
			if strings.HasPrefix(strLine, "FINAL") || strings.HasPrefix(strLine, "MATCH") {
				final = ruleGroup
				continue
			}
			rules = append(rules, transformRuleToSingBox(strLine, ruleGroup, rulesets))
			totalRules++
			continue
		}
		retrievedRules = common.ConvertRuleset(retrievedRules, x.RuleType)
		rule := make(map[string]interface{})

		scanner := bufio.NewScanner(strings.NewReader(retrievedRules))
		for scanner.Scan() {
			if config.Global.Advance.MaxAllowedRules > 0 && totalRules > config.Global.Advance.MaxAllowedRules {
				break
			}
			strLine := strings.TrimSpace(scanner.Text()) // 修剪空白
			strLine = strings.TrimSuffix(strLine, "\r")  // 修剪回车
			if strLine == "" || strings.HasPrefix(strLine, ";") || strings.HasPrefix(strLine, "#") || strings.HasPrefix(strLine, "//") {
				continue
			}

			if strings.Contains(strLine, "//") {
				strLine = strLine[:strings.Index(strLine, "//")]
				strLine = strings.TrimSpace(strLine)
			}
			appendSingBoxRule(rule, strLine)
		}
		if len(rule) == 0 {
			continue
		}
		rule["outbound"] = ruleGroup
		rules = append(rules, rule)
	}
	routeMap["rules"] = rules
	routeMap["final"] = final
	if len(rulesets) > 0 {
		// rulesets 转为slice
		rulesetsArray := make([]interface{}, 0, len(rulesets))
		for _, v := range rulesets {
			rulesetsArray = append(rulesetsArray, v)
		}
		routeMap["rule_set"] = rulesetsArray
	}
}

func transformRuleToSingBox(rule, group string, rulesets map[string]interface{}) map[string]interface{} {
	args := strings.Split(rule, ",")
	if len(args) < 2 {
		return nil
	}
	typeName := strings.ToLower(args[0])
	value := strings.ToLower(args[1])
	typeName = strings.ReplaceAll(typeName, "-", "_")
	typeName = strings.ReplaceAll(typeName, "ip_cidr6", "ip_cidr")
	typeName = strings.ReplaceAll(typeName, "src_", "source_")

	ruleObj := make(map[string]interface{})
	if typeName == "match" || typeName == "final" {
		ruleObj["outbound"] = value
	} else {
		// 判断是否是geoip和geosite
		match := false
		rulsetConfig, ok := config.Global.NodePref.SingboxRulesets[typeName]
		if ok {
			tagName := typeName + "-" + value
			rulesetObject, ok := rulesets[tagName]
			if !ok {
				realUrl := strings.ReplaceAll(rulsetConfig.UrlFormat, "%s", value)
				rulesetObject = map[string]interface{}{
					"tag":             tagName,
					"type":            "remote",
					"format":          "binary",
					"url":             realUrl,
					"download_detour": "DIRECT",
					"update_interval": "3d",
				}
				rulesets[tagName] = rulesetObject
			}
			ruleObj["rule_set"] = tagName
			ruleObj["outbound"] = group

			match = true
		}

		if !match {
			ruleObj[typeName] = value
			ruleObj["outbound"] = group
		}
	}
	return ruleObj
}

func appendSingBoxRule(rules map[string]interface{}, rule string) {
	args := strings.Split(rule, ",")
	if len(args) < 2 {
		return
	}
	typeName := args[0]

	_, hasOne := common.SingBoxRuleTypesMap[typeName]
	if !hasOne {
		return
	}

	realType := strings.ToLower(typeName)
	value := strings.ToLower(args[1])
	realType = strings.ReplaceAll(realType, "-", "_")
	realType = strings.ReplaceAll(realType, "ip_cidr6", "ip_cidr")

	realTypeArray, ok := rules[realType].([]interface{})
	if !ok {
		realTypeArray = make([]interface{}, 0, 1)
	}
	realTypeArray = append(realTypeArray, value)
	rules[realType] = realTypeArray
}
