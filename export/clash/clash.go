package clash

import (
	"bufio"
	"log/slog"
	"strconv"
	"strings"

	"github.com/821869798/easysub/config"
	"github.com/821869798/easysub/define"
	"github.com/821869798/easysub/export/common"

	"github.com/821869798/easysub/modules/util"
	"github.com/goccy/go-yaml"
)

const (
	// OptimizeMinCount 使用ruleset inline模式优化要求的最小数量
	OptimizeMinCount = 8
)

var (
	compactObjectMarshal, quotedStringMarshal, commonStringMarshal yaml.EncodeOption
)

type QuotedString string
type CompactObjectMap map[string]interface{}

type ruleSetOptimize struct {
	DomainOptimize []QuotedString
	DomainOrigin   string
	IpCidrOptimize []QuotedString
	IpCidrOrigin   string
}

func init() {
	compactObjectMarshal = yaml.CustomMarshaler[CompactObjectMap](func(obj CompactObjectMap) ([]byte, error) {
		return yaml.MarshalWithOptions(obj, yaml.Flow(true), quotedStringMarshal, commonStringMarshal)
	})
	quotedStringMarshal = yaml.CustomMarshaler[QuotedString](func(obj QuotedString) ([]byte, error) {
		return yaml.MarshalWithOptions(obj, yaml.JSON())
	})

	commonStringMarshal = yaml.CustomMarshaler[string](func(obj string) ([]byte, error) {
		if strings.ContainsRune(obj, '?') {
			return []byte(strconv.Quote(obj)), nil
		}
		return yaml.MarshalWithOptions(obj)
	})
}

func ProxyToClash(nodes []*define.Proxy, baseConf string, rulesetContent []*define.RulesetContent, extraProxyGroup []*define.ProxyGroupConfig, extraSetting *define.ExtraSettings) (string, error) {
	var yamlNode map[string]interface{}
	if err := yaml.Unmarshal([]byte(baseConf), &yamlNode); err != nil {
		return "", err
	}

	err := proxyToClashInternal(nodes, yamlNode, extraProxyGroup, extraSetting)
	if err != nil {
		return "", err
	}

	if !extraSetting.EnableRuleGenerator {
		bytes, err := yaml.MarshalWithOptions(yamlNode, yaml.IndentSequence(true), compactObjectMarshal)
		if err != nil {
			return "", err
		}
		return string(bytes), nil
	}

	outputContent := rulesetToClashStr(yamlNode, rulesetContent, extraSetting)

	bytes, err := yaml.MarshalWithOptions(yamlNode, yaml.IndentSequence(true), compactObjectMarshal, quotedStringMarshal, commonStringMarshal)
	if err != nil {
		return "", err
	}
	result := string(bytes) + outputContent

	return result, nil
}

func proxyToClashInternal(nodes []*define.Proxy, yamlNode map[string]interface{}, extraProxyGroup []*define.ProxyGroupConfig, extraSetting *define.ExtraSettings) error {

	nodeList := make([]*define.Proxy, 0)
	remarksList := make([]string, 0)
	proxies := make([]CompactObjectMap, 0)
	originalGroups := make([]interface{}, 0)

	for _, x := range nodes {
		singleProxy := make(map[string]interface{})
		proxyType := x.Type.String()
		pluginOpts := strings.ReplaceAll(x.PluginOption, ";", "&")
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

		singleProxy["name"] = x.Remark
		singleProxy["server"] = x.Hostname
		singleProxy["port"] = x.Port

		switch x.Type {
		case define.ProxyType_Shadowsocks:
			if extraSetting.FilterDeprecated.Bool() && x.EncryptMethod == "chacha20" {
				continue
			}
			singleProxy["type"] = "ss"
			singleProxy["cipher"] = x.EncryptMethod
			singleProxy["password"] = x.Password
			switch x.Plugin {
			case "simple-obfs", "obfs-local":
				singleProxy["plugin"] = "obfs"
				singleProxy["plugin-opts"] = map[string]interface{}{
					"mode": util.GetUrlArgUnescape(pluginOpts, "obfs"),
					"host": util.GetUrlArgUnescape(pluginOpts, "obfs-host"),
				}
			case "v2ray-plugin":
				singleProxy["plugin"] = "v2ray-plugin"
				singleProxy["plugin-opts"] = map[string]interface{}{
					"mode": util.GetUrlArgUnescape(pluginOpts, "mode"),
					"host": util.GetUrlArgUnescape(pluginOpts, "host"),
					"path": util.GetUrlArgUnescape(pluginOpts, "path"),
					"tls":  strings.Contains(pluginOpts, "tls"),
					"mux":  strings.Contains(pluginOpts, "mux"),
				}
				if !scv.IsUndef() {
					singleProxy["plugin-opts"].(map[string]interface{})["skip-cert-verify"] = scv.Bool()
				}
			}
		case define.ProxyType_VMess:
			singleProxy["type"] = "vmess"
			singleProxy["uuid"] = x.UserId
			singleProxy["alterId"] = x.AlterId
			singleProxy["cipher"] = x.EncryptMethod
			singleProxy["tls"] = x.TLSSecure
			if !scv.IsUndef() {
				singleProxy["skip-cert-verify"] = scv.Bool()
			}
			if x.ServerName != "" {
				singleProxy["servername"] = x.ServerName
			}
			switch x.TransferProtocol {
			case "tcp":
			case "ws":
				singleProxy["network"] = x.TransferProtocol
				wsOpts := make(map[string]interface{})
				singleProxy["ws-opts"] = wsOpts
				wsOpts["path"] = x.Path
				wsOptsHeaders := make(map[string]interface{})
				wsOpts["headers"] = wsOptsHeaders
				if x.Host != "" {
					wsOptsHeaders["Host"] = x.Host
				}
				if x.Edge != "" {
					wsOptsHeaders["Edge"] = x.Edge
				}
			case "http":
				singleProxy["network"] = x.TransferProtocol
				httpOpts := make(map[string]interface{})
				singleProxy["http-opts"] = httpOpts
				httpOpts["path"] = []string{x.Path}
				httpOpts["method"] = "GET"
				httpOptsHeaders := make(map[string]interface{})
				httpOpts["headers"] = httpOptsHeaders
				if x.Host != "" {
					httpOptsHeaders["Host"] = []string{x.Host}
				}
				if x.Edge != "" {
					httpOptsHeaders["Edge"] = []string{x.Edge}
				}
			case "h2":
				singleProxy["network"] = x.TransferProtocol
				h2Opts := make(map[string]interface{})
				singleProxy["h2-opts"] = h2Opts
				h2Opts["path"] = x.Path
				if x.Host != "" {
					h2Opts["host"] = []string{x.Host}
				}
			case "grpc":
				singleProxy["network"] = x.TransferProtocol
				singleProxy["servername"] = x.Host
				singleProxy["grpc-opts"] = map[string]interface{}{
					"grpc-service-name": x.Path,
					"grpc-mode":         x.GRPCMode,
				}
			}
		case define.ProxyType_VLESS:
			singleProxy["type"] = "vless"
			singleProxy["uuid"] = x.UserId
			singleProxy["tls"] = x.TLSSecure
			if !tfo.IsUndef() {
				singleProxy["tfo"] = tfo.Bool()
			}
			if x.Host != "" {
				singleProxy["servername"] = x.Host
			}
			if x.Flow != "" {
				singleProxy["flow"] = x.Flow
			}
			if !scv.IsUndef() {
				singleProxy["skip-cert-verify"] = scv.Bool()
			}
			switch x.TransferProtocol {
			case "tcp":
				break
			case "ws":
				singleProxy["network"] = x.TransferProtocol
				wsOpts := make(map[string]interface{})
				singleProxy["ws-opts"] = wsOpts
				wsOpts["path"] = x.Path
				wsOptsHeaders := make(map[string]interface{})
				wsOpts["headers"] = wsOptsHeaders
				if x.Host != "" {
					wsOptsHeaders["Host"] = x.Host
				}
				if x.Edge != "" {
					wsOptsHeaders["Edge"] = x.Edge
				}
			case "http":
				singleProxy["network"] = x.TransferProtocol
				httpOpts := make(map[string]interface{})
				singleProxy["http-opts"] = httpOpts
				httpOpts["path"] = []string{x.Path}
				httpOpts["method"] = "GET"
				httpOptsHeaders := make(map[string]interface{})
				httpOpts["headers"] = httpOptsHeaders
				if x.Host != "" {
					httpOptsHeaders["Host"] = []string{x.Host}
				}
				if x.Edge != "" {
					httpOptsHeaders["Edge"] = []string{x.Edge}
				}
			case "grpc":
				singleProxy["network"] = x.TransferProtocol
				singleProxy["grpc-opts"] = map[string]interface{}{
					"grpc-service-name": x.Path,
					"grpc-mode":         x.GRPCMode,
				}
			}
		case define.ProxyType_Trojan:
			singleProxy["type"] = "trojan"
			singleProxy["password"] = x.Password
			if x.Host != "" {
				singleProxy["sni"] = x.Host
			}
			if !scv.IsUndef() {
				singleProxy["skip-cert-verify"] = scv.Bool()
			}
			switch x.TransferProtocol {
			case "tcp":
			case "grpc":
				singleProxy["network"] = x.TransferProtocol
				if x.Path != "" {
					singleProxy["grpc-opts"] = map[string]interface{}{"grpc-service-name": x.Path}
				}
			case "ws":
				singleProxy["network"] = x.TransferProtocol
				singleProxy["ws-opts"] = map[string]interface{}{"path": x.Path}
				if x.Host != "" {
					singleProxy["ws-opts"].(map[string]interface{})["headers"] = map[string]interface{}{"Host": x.Host}
				}
			}
		case define.ProxyType_TUIC:
			singleProxy["type"] = "tuic"
			singleProxy["version"] = 5
			singleProxy["uuid"] = x.UUID
			singleProxy["password"] = x.Password
			if x.ServerName != "" {
				singleProxy["sni"] = x.ServerName
			}
			if x.HeartbeatInterval != "" {
				singleProxy["heartbeat-interval"] = x.HeartbeatInterval
			}
			if x.DisableSNI == "1" || x.DisableSNI == "true" {
				singleProxy["disable-sni"] = true
			}
			if x.ReduceRTT == "1" || x.ReduceRTT == "true" {
				singleProxy["reduce-rtt"] = true
			}
			if x.RequestTimeout > 0 {
				singleProxy["request-timeout"] = x.RequestTimeout
			}
			if x.UdpRelayMode != "" {
				singleProxy["udp-relay-mode"] = x.UdpRelayMode
			}
			if x.CongestionController != "" {
				singleProxy["congestion-controller"] = x.CongestionController
			}
			if x.MaxUdpRelayPacketSize > 0 {
				singleProxy["max-udp-relay-packet-size"] = x.MaxUdpRelayPacketSize
			}
			if x.MaxOpenStreams > 0 {
				singleProxy["max-open-streams"] = x.MaxOpenStreams
			}
			if len(x.Alpn) > 0 {
				singleProxy["alpn"] = x.Alpn
			}
			if x.FastOpen.Bool() {
				singleProxy["fast-open"] = x.FastOpen.Bool()
			}
			if !scv.IsUndef() {
				singleProxy["skip-cert-verify"] = scv.Bool()
			}
			if !tfo.IsUndef() {
				singleProxy["tfo"] = tfo.Bool()
			}
		case define.ProxyType_ANYTLS:
			singleProxy["type"] = "anytls"
			if x.Password != "" {
				singleProxy["password"] = x.Password
			}
			if x.ServerName != "" {
				singleProxy["sni"] = x.ServerName
			}
			if len(x.Alpn) > 0 {
				singleProxy["alpn"] = x.Alpn
			}
			if x.Fingerprint != "" {
				singleProxy["fingerprint"] = x.Fingerprint
			}
			if x.IdleSessionCheckInterval > 0 {
				singleProxy["idle-session-check-interval"] = x.IdleSessionCheckInterval
			}
			if x.IdleSessionTimeout > 0 {
				singleProxy["idle-session-timeout"] = x.IdleSessionTimeout
			}
			if x.MinIdleSession > 0 {
				singleProxy["min-idle-session"] = x.MinIdleSession
			}
			if !scv.IsUndef() {
				singleProxy["skip-cert-verify"] = scv.Bool()
			}
		case define.ProxyType_Hysteria2:
			singleProxy["type"] = "hysteria2"
			if x.Password != "" {
				singleProxy["password"] = x.Password
			}
			if x.Ports != "" {
				singleProxy["ports"] = x.Ports
			}
			if x.UpSpeed > 0 {
				singleProxy["up"] = x.UpSpeed
			}
			if x.DownSpeed > 0 {
				singleProxy["down"] = x.DownSpeed
			}
			if x.OBFS != "" {
				singleProxy["obfs"] = x.OBFS
			}
			if x.OBFSParam != "" {
				singleProxy["obfs-password"] = x.OBFSParam
			}
			if x.ServerName != "" {
				singleProxy["sni"] = x.ServerName
			}
			if len(x.Alpn) > 0 {
				singleProxy["alpn"] = x.Alpn
			}
			if x.Ca != "" {
				singleProxy["ca"] = x.Ca
			}
			if x.CaStr != "" {
				singleProxy["ca-str"] = x.CaStr
			}
			if x.CWND > 0 {
				singleProxy["cwnd"] = x.CWND
			}
			if x.HopInterval > 0 {
				singleProxy["hop-interval"] = x.HopInterval
			}
			if !scv.IsUndef() {
				singleProxy["skip-cert-verify"] = scv.Bool()
			}
		default:
		}

		if udp.Bool() && x.Type != define.ProxyType_Snell {
			singleProxy["udp"] = true
		}
		if !tfo.IsUndef() {
			singleProxy["tfo"] = tfo.Bool()
		}
		proxies = append(proxies, singleProxy)
		remarksList = append(remarksList, x.Remark)
		nodeList = append(nodeList, x)
	}

	yamlNode["proxies"] = proxies

	for _, x := range extraProxyGroup {
		singleGroup := make(map[string]interface{})
		filteredNodeList := make([]string, 0)

		singleGroup["name"] = x.Name
		if x.Type == define.ProxyGroupType_URLTest {
			singleGroup["type"] = "url-test"
		} else {
			singleGroup["type"] = x.TypeStr()
		}

		switch x.Type {
		case define.ProxyGroupType_Select, define.ProxyGroupType_Relay:

		case define.ProxyGroupType_LoadBalance:
			singleGroup["strategy"] = x.StrategyStr()
			fallthrough
		case define.ProxyGroupType_Smart:
		case define.ProxyGroupType_URLTest:
			if !x.Lazy.IsUndef() {
				singleGroup["lazy"] = x.Lazy.Bool()
			}
			fallthrough
		case define.ProxyGroupType_Fallback:
			singleGroup["url"] = x.Url
			if x.Interval > 0 {
				singleGroup["interval"] = x.Interval
			}
			if x.Tolerance > 0 {
				singleGroup["tolerance"] = x.Tolerance
			}
		default:
		}

		if !x.DisableUdp.IsUndef() {
			singleGroup["disable-udp"] = x.DisableUdp.Bool()
		}

		for _, y := range x.Proxies {
			filteredNodeList = common.GroupGenerate(y, nodeList, filteredNodeList, true)
		}

		if len(x.UsingProvider) > 0 {
			singleGroup["use"] = x.UsingProvider
		} else {
			if len(filteredNodeList) == 0 {
				filteredNodeList = append(filteredNodeList, "DIRECT")
			}
		}

		if len(filteredNodeList) > 0 {
			singleGroup["proxies"] = filteredNodeList
		}

		replaceFlag := false
		for oi, originalGroup := range originalGroups {
			originalGroupValue := originalGroup.(map[string]interface{})
			v, ok := originalGroupValue["name"]
			if ok && v.(string) == x.Name {
				originalGroups[oi] = singleGroup
				replaceFlag = true
				break
			}
		}

		if !replaceFlag {
			originalGroups = append(originalGroups, singleGroup)
		}

	}

	yamlNode["proxy-groups"] = originalGroups
	return nil
}

func rulesetToClashStr(baseRule map[string]interface{}, rulesetContent []*define.RulesetContent, extraSetting *define.ExtraSettings) string {
	var strLine string
	ruleProviders := make(map[string]interface{})
	fieldName := "rules"
	outputContentWriter := &strings.Builder{}
	outputContentWriter.WriteString(fieldName)
	outputContentWriter.WriteString(":\n")
	totalRules := 0

	useRulesetOptimize := extraSetting.ClashRuleSetOptimize

	originRules, defined := baseRule[fieldName]
	if originRules == nil {
		originRules = make([]interface{}, 0)
		baseRule[fieldName] = originRules
	}
	if !extraSetting.OverwriteOriginalRules && defined {
		rules := originRules.([]interface{})
		for _, x := range rules {
			outputContentWriter.WriteString("  - " + x.(string) + "\n")
		}
	}
	delete(baseRule, fieldName)

	for _, x := range rulesetContent {
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
			strLine = retrievedRules[2:]
			if strings.HasPrefix(strLine, "FINAL") {
				strLine = strings.Replace(strLine, "FINAL", "MATCH", 1)
			}
			if extraSetting.ClashGeoConvertRuleSet {
				transformRuleConverterGeo(strLine, ruleGroup, outputContentWriter, ruleProviders)
			} else {
				transformRuleToCommon(strLine, ruleGroup, outputContentWriter)
			}

			totalRules++
			continue
		}
		retrievedRules = common.ConvertRuleset(retrievedRules, x.RuleType)

		var rulesetOp *ruleSetOptimize
		if useRulesetOptimize {
			rulesetOp = &ruleSetOptimize{}
		}

		currentRuleContentWriter := &strings.Builder{}
		scanner := bufio.NewScanner(strings.NewReader(retrievedRules))
		for scanner.Scan() {
			strLine := strings.TrimSpace(scanner.Text()) // 修剪空白
			strLine = strings.TrimSuffix(strLine, "\r")  // 修剪回车
			if strLine == "" || strings.HasPrefix(strLine, ";") || strings.HasPrefix(strLine, "#") || strings.HasPrefix(strLine, "//") {
				continue
			}

			hasType := false
			for _, ruleType := range common.ClashRuleTypes {
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

			if useRulesetOptimize {
				transformRuleToOptimize(strLine, ruleGroup, currentRuleContentWriter, rulesetOp)
			} else {
				transformRuleToCommon(strLine, ruleGroup, currentRuleContentWriter)
			}
			totalRules++
		}

		if rulesetOp != nil {
			if len(rulesetOp.DomainOptimize) < OptimizeMinCount {
				// no enough count to optimize
				currentRuleContentWriter.WriteString(rulesetOp.DomainOrigin)
			} else {
				realRuleName := transformRuleProvider(x, "domain", rulesetOp.DomainOptimize, ruleProviders, extraSetting)
				outputContentWriter.WriteString("  - RULE-SET," + realRuleName + "," + ruleGroup + "\n")
			}

			if len(rulesetOp.IpCidrOptimize) < OptimizeMinCount {
				currentRuleContentWriter.WriteString(rulesetOp.IpCidrOrigin)
			} else {
				realRuleName := transformRuleProvider(x, "ipcidr", rulesetOp.IpCidrOptimize, ruleProviders, extraSetting)
				outputContentWriter.WriteString("  - RULE-SET," + realRuleName + "," + ruleGroup + ",no-resolve" + "\n")
			}
		}
		outputContentWriter.WriteString(currentRuleContentWriter.String())
	}
	if len(ruleProviders) > 0 {
		baseRule["rule-providers"] = ruleProviders
	}
	return outputContentWriter.String()
}
