package v1

import (
	"github.com/821869798/easysub/config"
	"github.com/821869798/easysub/define"
	"github.com/821869798/easysub/export/clash"
	"github.com/821869798/easysub/export/singbox"
	"github.com/821869798/easysub/modules/fetch"
	"github.com/821869798/easysub/modules/parser"
	"github.com/821869798/easysub/modules/tpl"
	"github.com/821869798/easysub/modules/util"
	"github.com/gin-gonic/gin"
	"log/slog"
	"strings"
)

func Sub(c *gin.Context) {
	argTarget := c.Query("target")
	argUrls := strings.Split(c.Query("url"), "|")
	token := c.Query("token")
	argExternalConfig := c.Query("config")
	argEnableInsert := queryArgOrDefaultTriBool(c, "insert", config.Global.Common.EnableInsert)
	argAppendType := queryArgOrDefaultTriBool(c, "append_type", config.Global.Common.AppendProxyType)
	argSkipCertVerify := queryArgOrDefaultTriBool(c, "scv", config.Global.NodePref.SkipCertVerify)
	argFilterDeprecated := queryArgOrDefaultTriBool(c, "fdn", config.Global.NodePref.FilterDeprecatedNodes)
	argUDP := queryArgOrDefaultTriBool(c, "udp", config.Global.NodePref.UDPFlag)
	argTFO := queryArgOrDefaultTriBool(c, "tfo", config.Global.NodePref.TCPFastOpenFlag)
	argClashRSO := queryArgOrDefaultBool(c, "clashRSO", config.Global.NodePref.ClashRulesetOptimize)
	argClashRSO2H := queryArgOrDefaultBool(c, "clashRSOH", config.Global.NodePref.ClashRulesetOptimizeToHttp)
	argClashGVR := queryArgOrDefaultBool(c, "clashGVR", config.Global.NodePref.ClashGeoConvertRuleSet)

	ext := define.NewExtraSettings()
	ext.RequestHost = c.Request.Host
	if c.Request.TLS != nil {
		ext.RequestHostWithProtocol = "https://" + c.Request.Host
	} else {
		ext.RequestHostWithProtocol = "http://" + c.Request.Host
	}
	ext.NodePref = config.Global.NodePref
	ext.AppendProxyType = argAppendType
	ext.SkipCertVerify = argSkipCertVerify
	ext.FilterDeprecated = argFilterDeprecated
	ext.ClashRuleSetOptimize = argClashRSO
	ext.ClashGeoConvertRuleSet = argClashGVR
	ext.ClashRulesetOptimizeToHttp = argClashRSO2H
	ext.UDP = argUDP
	ext.TFO = argTFO
	ext.ManagedConfigPrefix = config.Global.ManagedConfig.ManagedConfigPrefix

	// 解析所有参数
	var reqMap = make(map[string]string)
	for k, kv := range c.Request.URL.Query() {
		reqMap[k] = kv[0]
	}

	authorized := !config.Global.Common.ApiMode || config.Global.Common.ApiAccessToken == token
	if len(argUrls) == 0 && (!config.Global.Common.ApiMode || authorized) {
		argUrls = config.Global.Common.DefaultUrl
	}
	if (len(argTarget) == 0 && !(len(config.Global.Common.InsertUrl) > 0 && argEnableInsert.Bool())) || argTarget == "" {
		c.String(400, "Invalid request!")
		return
	}

	tplArgs := map[string]interface{}{
		"Request": util.ConvertToNestedMap(reqMap),
		"Global":  util.ConvertKVToNestedMap(config.Global.Template.Globals),
	}

	var lRulesetContent []*define.RulesetContent
	var lCustomProxyGroups []*define.ProxyGroupConfig
	//var lClashBase, lSingBoxBase string

	// 解析config ---------------------------
	if argExternalConfig == "" {
		argExternalConfig = config.Global.Common.DefaultExternalConfig
	}
	if argExternalConfig != "" {
		slog.Info("External configuration file provided. Loading...")
		extconf := define.NewExternalConfig()
		extconf.TplArgs = tplArgs
		if err := parser.LoadExternalConfig(argExternalConfig, extconf); err != nil {
			slog.Error(err.Error())
			c.String(400, err.Error())
			return
		}
		slog.Info("External configuration file loaded.")

		lRulesetContent = define.ParseRulesetContents(extconf.RulesetConfigs)
		lCustomProxyGroups = extconf.CustomProxyGroups
		//lClashBase = extconf.ClashRuleBase
		//lSingBoxBase = extconf.SingboxRuleBase
		ext.EnableRuleGenerator = extconf.EnableRuleGenerator
		ext.OverwriteOriginalRules = extconf.OverwriteOriginalRules
	} else {
		c.String(400, "No external config file provided.")
		return
	}

	// 解析 代理node ------------------------
	var nodes []*define.Proxy
	settings := &parser.ParseSettings{}

	groupId := uint32(0)
	if argEnableInsert.Bool() {
		for _, url := range config.Global.Common.InsertUrl {
			node, err := parser.ParseNode(url, groupId, settings)
			if err != nil {
				slog.Error(err.Error())
				c.String(400, err.Error())
				return
			}
			nodes = append(nodes, node)
			groupId++
		}
	}
	for _, url := range argUrls {
		node, err := parser.ParseNode(url, groupId, settings)
		if err != nil {
			slog.Error(err.Error())
			c.String(400, err.Error())
			return
		}
		nodes = append(nodes, node)
		groupId++
	}

	// 根据target类型做相应的处理
	switch argTarget {
	case "clash":
		slog.Info("Generate target: Clash")
		fileContent, err := fetch.FetchFile(config.Global.Common.ClashRuleBase, config.Global.Common.ProxyConfig, config.Global.Advance.CacheConfig, true)
		if err != nil {
			slog.Error(err.Error())
			c.String(400, err.Error())
			return
		}
		outRender, err := tpl.RenderTemplate(fileContent, tplArgs)
		if err != nil {
			slog.Error(err.Error())
			c.String(400, err.Error())
			return
		}

		outputContent, err := clash.ProxyToClash(nodes, outRender, lRulesetContent, lCustomProxyGroups, ext)
		if err != nil {
			slog.Error(err.Error())
			c.String(400, err.Error())
			return
		}
		c.String(200, outputContent)

	case "singbox":
		slog.Info("Generate target: sing-box")
		fileContent, err := fetch.FetchFile(config.Global.Common.SingboxRuleBase, config.Global.Common.ProxyConfig, config.Global.Advance.CacheConfig, true)
		if err != nil {
			slog.Error(err.Error())
			c.String(400, err.Error())
			return
		}
		outRender, err := singbox.RenderTemplate(fileContent, tplArgs)
		if err != nil {
			slog.Error(err.Error())
			c.String(400, err.Error())
			return
		}
		outputContent, err := singbox.ProxyToSingBox(nodes, outRender, lRulesetContent, lCustomProxyGroups, ext)
		if err != nil {
			slog.Error(err.Error())
			c.String(400, err.Error())
			return
		}
		c.String(200, outputContent)
	default:
		// 未知的目标，返回错误
		c.String(400, "Invalid target!")
		return
	}

	//c.JSON(200, gin.H{
	//	"message": "sub",
	//})
}
