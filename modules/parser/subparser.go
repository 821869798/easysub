package parser

import (
	"encoding/json"
	define "github.com/821869798/easysub/define"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/821869798/easysub/modules/util"
	"log/slog"
)

func explode(link string, node *define.Proxy) {
	if strings.HasPrefix(link, "vmess://") || strings.HasPrefix(link, "vmess1://") {
		explodeVmess(link, node)
	} else if strings.HasPrefix(link, "vless://") || strings.HasPrefix(link, "vless1://") {
		explodeVless(link, node)
	} else if strings.HasPrefix(link, "ss://") {
		explodeSS(link, node)
	} else if strings.HasPrefix(link, "socks://") || strings.HasPrefix(link, "https://t.me/socks") || strings.HasPrefix(link, "tg://socks") {
		explodeSocks(link, node)
	} else if strings.HasPrefix(link, "https://t.me/http") || strings.HasPrefix(link, "tg://http") {
		explodeHTTP(link, node)
	} else if strings.HasPrefix(link, "Netch://") {
		explodeNetch(link, node)
	} else if strings.HasPrefix(link, "trojan://") {
		explodeTrojan(link, node)
	} else if util.IsLink(link) {
		explodeHTTPSub(link, node)
	}
}

func explodeSS(link string, node *define.Proxy) {
	ss := strings.ReplaceAll(link[5:], "/?", "?")
	var ps, password, method, server, port, plugins, plugin, pluginopts, addition, group string

	if strings.Contains(ss, "#") {
		sspos := strings.Index(ss, "#")
		ps, _ = url.QueryUnescape(ss[sspos+1:])
		ss = ss[:sspos]
	}

	if strings.Contains(ss, "?") {
		addition = ss[strings.Index(ss, "?")+1:]
		plugins, _ = url.QueryUnescape(util.GetUrlArg(addition, "plugin"))
		pluginpos := strings.Index(plugins, ";")
		if pluginpos != -1 {
			plugin = plugins[:pluginpos]
			pluginopts = plugins[pluginpos+1:]
		} else {
			plugin = plugins
		}
		group, _ = util.UrlSafeBase64Decode(util.GetUrlArg(addition, "group"))
		ss = ss[:strings.Index(ss, "?")]
	}

	if strings.Contains(ss, "@") {
		var secret string
		if util.RegGetMatch(ss, `(\S+?)@(\S+):(\d+)`, &secret, &server, &port) != nil {
			return
		}
		secret, _ = util.UrlSafeBase64Decode(secret)
		if util.RegGetMatch(secret, `(\S+?):(\S+)`, &method, &password) != nil {
			return
		}
	} else {
		ssNew, _ := util.UrlSafeBase64Decode(ss)
		if util.RegGetMatch(ssNew, `(\S+?):(\S+)@(\S+):(\d+)`, &method, &password, &server, &port) != nil {
			return
		}
	}
	if port == "0" {
		return
	}
	if ps == "" {
		ps = server + ":" + port
	}

	define.SSProxyInit(node, group, ps, server, port, password, method, plugin, pluginopts, define.NewTribool(), define.NewTribool(), define.NewTribool(), define.NewTribool())
}

func explodeVmess(vmess string, node *define.Proxy) {
	if ok, _ := regexp.MatchString("vmess://([A-Za-z0-9-_]+)\\?(.*)", vmess); ok {
		explodeStdVMess(vmess, node)
		return
	} else if ok, _ := regexp.MatchString("vmess://(.*?)@(.*)", vmess); ok {
		explodeStdVMess(vmess, node)
		return
	} else if ok, _ := regexp.MatchString("vmess1://(.*?)\\?(.*)", vmess); ok {
		explodeKitsunebi(vmess, node)
		return
	}

	vmess, _ = util.UrlSafeBase64Decode(util.RegReplace(vmess, "(vmess|vmess1)://", "", true))
	if ok1, _ := regexp.MatchString("(.*?) = (.*)", vmess); ok1 {
		explodeQuan(vmess, node)
		return
	}

	var jsondata map[string]interface{}
	if err := json.Unmarshal([]byte(vmess), &jsondata); err != nil {
		return
	}

	version := "1"
	if v, ok := jsondata["v"].(string); ok {
		version = v
	}

	ps := ""
	if v, ok := jsondata["ps"].(string); ok {
		ps = v
	}

	add := ""
	if v, ok := jsondata["add"].(string); ok {
		add = v
	}

	port := ""
	if v, ok := jsondata["port"].(string); ok {
		port = v
	}
	if port == "0" {
		return
	}

	typeStr := ""
	if v, ok := jsondata["type"].(string); ok {
		typeStr = v
	}

	id := ""
	if v, ok := jsondata["id"].(string); ok {
		id = v
	}

	aid := ""
	if v, ok := jsondata["aid"].(string); ok {
		aid = v
	}

	net := ""
	if v, ok := jsondata["net"].(string); ok {
		net = v
	}

	tls := ""
	if v, ok := jsondata["tls"].(string); ok {
		tls = v
	}

	host := ""
	if v, ok := jsondata["host"].(string); ok {
		host = v
	}

	sni := ""
	if v, ok := jsondata["sni"].(string); ok {
		sni = v
	}

	path := ""
	switch version {
	case "1":
		if host != "" {
			vArray := strings.Split(host, ";")
			if len(vArray) == 2 {
				host = vArray[0]
				path = vArray[1]
			}
		}
	case "2":
		if v, ok := jsondata["path"].(string); ok {
			path = v
		}
	}

	add = strings.TrimSpace(add)

	define.VMessProxyInit(node, V2RAY_DEFAULT_GROUP, ps, add, port, typeStr, id, aid, net, "auto", path, host, "", tls, sni, define.NewTribool(), define.NewTribool(), define.NewTribool(), define.NewTribool())
}

func explodeStdVMess(vmess string, node *define.Proxy) {
	add, port, typeStr, id, aid, net, path, host, tls, remarks := "", "", "", "", "", "", "", "", "", ""
	addition := ""

	vmess = vmess[8:]
	pos := strings.Index(vmess, "#")
	if pos != -1 {
		remarks, _ = url.QueryUnescape(vmess[pos+1:])
		vmess = vmess[:pos]
	}

	const stdvmessMatcher = `^([a-z]+)(?:\+([a-z]+))?:([\da-f]{8}(?:[\da-f]{4}-){3}[\da-f]{12})-(\d+)@(.+):(\d+)(?:\/?\?(.*))?$`
	if util.RegGetMatch(vmess, stdvmessMatcher, &net, &tls, &id, &aid, &add, &port, &addition) != nil {
		return
	}

	switch net {
	case "tcp", "kcp":
		typeStr = util.GetUrlArg(addition, "type")
	case "http", "ws":
		host = util.GetUrlArg(addition, "host")
		path = util.GetUrlArg(addition, "path")
	case "quic":
		typeStr = util.GetUrlArg(addition, "security")
		host = util.GetUrlArg(addition, "type")
		path = util.GetUrlArg(addition, "key")
	default:
		return
	}

	if remarks == "" {
		remarks = add + ":" + port
	}

	define.VMessProxyInit(node, "", remarks, add, port, typeStr, id, aid, net, "", path, host, "", tls, "", define.NewTribool(), define.NewTribool(), define.NewTribool(), define.NewTribool())
}

func explodeShadowrocket(rocket string, node *define.Proxy) {
	add, port, cipher, id, net, path, host, tls, remarks := "", "", "", "", "tcp", "", "", "", ""
	obfs := ""
	addition := ""

	rocket = rocket[8:]

	pos := strings.Index(rocket, "?")
	if pos != -1 {
		addition = rocket[pos+1:]
		rocket = rocket[:pos]
	}
	rocket, _ = util.UrlSafeBase64Decode(rocket)
	if util.RegGetMatch(rocket, `(.*?):(.*)@(.*):(.*)`, &cipher, &id, &add, &port) != nil {
		return
	}
	if port == "0" {
		return
	}

	remarks, _ = url.QueryUnescape(util.GetUrlArg(addition, "remarks"))
	obfs = util.GetUrlArg(addition, "obfs")
	if obfs != "" {
		if obfs == "websocket" {
			net = "ws"
			host = util.GetUrlArg(addition, "obfsParam")
			path = util.GetUrlArg(addition, "path")
		}
	} else {
		net = util.GetUrlArg(addition, "network")
		host = util.GetUrlArg(addition, "wsHost")
		path = util.GetUrlArg(addition, "wspath")
	}
	tls = util.GetUrlArg(addition, "tls")
	b, _ := strconv.ParseBool(tls)
	if b {
		tls = "tls"
	} else {
		tls = ""
	}
	aid := util.GetUrlArg(addition, "aid")
	if aid == "" {
		aid = "0"
	}

	if remarks == "" {
		remarks = add + ":" + port
	}

	define.VMessProxyInit(node, V2RAY_DEFAULT_GROUP, remarks, add, port, "", id, aid, net, cipher, path, host, "", tls, "", define.NewTribool(), define.NewTribool(), define.NewTribool(), define.NewTribool())
}

func explodeKitsunebi(kit string, node *define.Proxy) {
	add := ""
	port := ""
	id := ""
	aid := "0"
	net := "tcp"
	path := ""
	host := ""
	tls := ""
	cipher := "auto"
	remarks := ""
	addition := ""

	kit = kit[9:]

	pos := strings.Index(kit, "#")
	if pos != -1 {
		remarks = kit[pos+1:]
		kit = kit[:pos]
	}

	pos = strings.Index(kit, "?")
	if pos != -1 {
		addition = kit[pos+1:]
		kit = kit[:pos]
	}

	if util.RegGetMatch(kit, `(.*?)@(.*):(.*)`, &id, &add, &port) != nil {
		return
	}
	pos = strings.Index(port, "/")
	if pos != -1 {
		path = port[pos:]
		port = port[:pos]
	}
	if port == "0" {
		return
	}
	net = util.GetUrlArg(addition, "network")
	if util.GetUrlArg(addition, "tls") == "true" {
		tls = "tls"
	}
	host = util.GetUrlArg(addition, "ws.host")

	if remarks == "" {
		remarks = add + ":" + port
	}

	define.VMessProxyInit(node, V2RAY_DEFAULT_GROUP, remarks, add, port, "", id, aid, net, cipher, path, host, "", tls, "", define.NewTribool(), define.NewTribool(), define.NewTribool(), define.NewTribool())

}

func explodeQuan(quan string, node *define.Proxy) {
	strTemp := util.RegReplace(quan, "(.*?) = (.*)", "$1,$2", true)
	configs := strings.Split(strTemp, ",")

	if configs[1] == "vmess" {
		if len(configs) < 6 {
			return
		}
		ps := strings.TrimSpace(configs[0])
		add := strings.TrimSpace(configs[2])
		port := strings.TrimSpace(configs[3])
		if port == "0" {
			return
		}
		cipher := strings.TrimSpace(configs[4])
		id := strings.Trim(strings.ReplaceAll(configs[5], "\"", ""), " ")

		group := V2RAY_DEFAULT_GROUP
		tls := ""
		host := ""
		path := "/"
		net := "tcp"
		edge := ""

		for i := 6; i < len(configs); i++ {
			vArray := strings.Split(configs[i], "=")
			if len(vArray) < 2 {
				continue
			}
			itemName := strings.TrimSpace(vArray[0])
			itemVal := strings.TrimSpace(vArray[1])
			switch itemName {
			case "group":
				group = itemVal
			case "over-tls":
				if itemVal == "true" {
					tls = "tls"
				}
			case "tls-host":
				host = itemVal
			case "obfs-path":
				path = strings.ReplaceAll(itemVal, "\"", "")
			case "obfs-header":
				headers := strings.Split(strings.ReplaceAll(strings.ReplaceAll(itemVal, "\"", ""), "[Rr][Nn]", "|"), "|")
				for _, x := range headers {
					if strings.HasPrefix(strings.ToLower(x), "host: ") {
						host = x[6:]
					} else if strings.HasPrefix(strings.ToLower(x), "edge: ") {
						edge = x[6:]
					}
				}
			case "obfs":
				if itemVal == "ws" {
					net = "ws"
				}
			default:
				continue
			}
		}

		define.VMessProxyInit(node, group, ps, add, port, "none", id, "0", net, cipher, path, host, edge, tls, "", define.NewTribool(), define.NewTribool(), define.NewTribool(), define.NewTribool())
	}

}

func explodeSocks(link string, node *define.Proxy) {
	var group, remarks, server, port, username, password string

	if strings.HasPrefix(link, "socks://") {
		if strings.Contains(link, "#") {
			pos := strings.Index(link, "#")
			remarks, _ = url.QueryUnescape(link[pos+1:])
			link = link[:pos]
		}
		link, _ = util.UrlSafeBase64Decode(link[8:])
		if strings.Contains(link, "@") {
			userinfo := strings.Split(link, "@")
			if len(userinfo) < 2 {
				return
			}
			link = userinfo[1]
			userinfo = strings.Split(userinfo[0], ":")
			if len(userinfo) < 2 {
				return
			}
			username = userinfo[0]
			password = userinfo[1]
		}
		arguments := strings.Split(link, ":")
		if len(arguments) < 2 {
			return
		}
		server = arguments[0]
		port = arguments[1]
	} else if strings.HasPrefix(link, "https://t.me/socks") || strings.HasPrefix(link, "tg://socks") {
		server = util.GetUrlArg(link, "server")
		port = util.GetUrlArg(link, "port")
		username, _ = url.QueryUnescape(util.GetUrlArg(link, "user"))
		password, _ = url.QueryUnescape(util.GetUrlArg(link, "pass"))
		remarks, _ = url.QueryUnescape(util.GetUrlArg(link, "remarks"))
		group, _ = url.QueryUnescape(util.GetUrlArg(link, "group"))
	}

	if group == "" {
		group = SOCKS_DEFAULT_GROUP
	}
	if remarks == "" {
		remarks = server + ":" + port
	}
	if port == "0" {
		return
	}

	define.SocksProxyInit(node, group, remarks, server, port, username, password, define.NewTribool(), define.NewTribool(), define.NewTribool())
}

func explodeHTTP(link string, node *define.Proxy) {
	var group, remarks, server, port, username, password string
	server = util.GetUrlArg(link, "server")
	port = util.GetUrlArg(link, "port")
	username, _ = url.QueryUnescape(util.GetUrlArg(link, "user"))
	password, _ = url.QueryUnescape(util.GetUrlArg(link, "pass"))
	remarks, _ = url.QueryUnescape(util.GetUrlArg(link, "remarks"))
	group, _ = url.QueryUnescape(util.GetUrlArg(link, "group"))

	if group == "" {
		group = HTTP_DEFAULT_GROUP
	}
	if remarks == "" {
		remarks = server + ":" + port
	}
	if port == "0" {
		return
	}

	define.HttpProxyInit(node, group, remarks, server, port, username, password, strings.Contains(link, "/https"), define.NewTribool(), define.NewTribool(), define.NewTribool())
}

func explodeHTTPSub(link string, node *define.Proxy) {
	var group, remarks, server, port, username, password string
	var addition string
	tls := strings.Contains(link, "https://")
	pos := strings.Index(link, "?")
	if pos != -1 {
		addition = link[pos+1:]
		link = link[:pos]
		remarks, _ = url.QueryUnescape(util.GetUrlArg(addition, "remarks"))
		group, _ = url.QueryUnescape(util.GetUrlArg(addition, "group"))
	}
	link = link[strings.Index(link, "://")+3:]
	link, _ = util.UrlSafeBase64Decode(link)
	if strings.Contains(link, "@") {
		if err := util.RegGetMatch(link, `(.*?):(.*?)@(.*):(.*)`, &username, &password, &server, &port); err != nil {
			return
		}
	} else {
		if err := util.RegGetMatch(link, `(.*):(.*)`, &server, &port); err != nil {
			return
		}
	}

	if group == "" {
		group = HTTP_DEFAULT_GROUP
	}
	if remarks == "" {
		remarks = server + ":" + port
	}
	if port == "0" {
		return
	}

	define.HttpProxyInit(node, group, remarks, server, port, username, password, tls, define.NewTribool(), define.NewTribool(), define.NewTribool())
}

func explodeTrojan(trojan string, node *define.Proxy) {
	trojan = trojan[9:]
	pos := strings.LastIndex(trojan, "#")

	var remark, group, server, port, psk, addition, host, path, network string
	var tfo, scv define.Tribool

	if pos != -1 {
		remark, _ = url.QueryUnescape(trojan[pos+1:])
		trojan = trojan[:pos]
	}
	pos = strings.Index(trojan, "?")
	if pos != -1 {
		addition = trojan[pos+1:]
		trojan = trojan[:pos]
	}

	if err := util.RegGetMatch(trojan, `(.*?)@(.*):(.*)`, &psk, &server, &port); err != nil {
		return
	}
	if port == "0" {
		return
	}

	host = util.GetUrlArg(addition, "sni")
	if host == "" {
		host = util.GetUrlArg(addition, "peer")
	}
	tfo = define.NewTriboolFromString(util.GetUrlArg(addition, "tfo"))
	scv = define.NewTriboolFromString(util.GetUrlArg(addition, "allowInsecure"))
	group, _ = url.QueryUnescape(util.GetUrlArg(addition, "group"))

	isWs, _ := strconv.ParseBool(util.GetUrlArg(addition, "ws"))
	if isWs {
		path = util.GetUrlArg(addition, "wspath")
		network = "ws"
	} else if util.GetUrlArg(addition, "type") == "ws" {
		path = util.GetUrlArg(addition, "path")
		if strings.HasPrefix(path, "%2F") {
			path, _ = url.QueryUnescape(path)
		}
		network = "ws"
	}

	if remark == "" {
		remark = server + ":" + port
	}
	if group == "" {
		group = TROJAN_DEFAULT_GROUP
	}

	define.TrojanProxyInit(node, group, remark, server, port, psk, network, host, path, true, tfo, scv, define.NewTribool(), define.NewTribool())
}

func explodeNetch(netch string, node *define.Proxy) {
	var jsonData map[string]interface{}
	var typeStr, group, remark, address, port, username, password, method, plugin, pluginopts string
	var obfs, id, aid, transprot, faketype, host, edge, path, tls, sni string
	var udp, tfo, scv define.Tribool

	decodedNetch, err := util.UrlSafeBase64Decode(netch[8:])
	if err != nil {
		slog.Error("explodeNetch decode error: " + err.Error())
		return
	}

	if err := json.Unmarshal([]byte(decodedNetch), &jsonData); err != nil {
		slog.Error("explodeNetch unmarshal error: " + err.Error())
		return
	}

	typeStr = jsonData["Type"].(string)
	group = jsonData["Group"].(string)
	remark = jsonData["Remark"].(string)
	address = jsonData["Hostname"].(string)
	udp = define.GetTriboolFromMap(jsonData, "EnableUDP")
	tfo = define.GetTriboolFromMap(jsonData, "EnableTFO")
	scv = define.GetTriboolFromMap(jsonData, "AllowInsecure")
	port = jsonData["Port"].(string)
	if port == "0" {
		return
	}
	method = jsonData["EncryptMethod"].(string)
	password = jsonData["Password"].(string)
	if remark == "" {
		remark = address + ":" + port
	}

	switch typeStr {
	case "SS":
		plugin = jsonData["Plugin"].(string)
		pluginopts = jsonData["PluginOption"].(string)
		if group == "" {
			group = SS_DEFAULT_GROUP
		}
		define.SSProxyInit(node, group, remark, address, port, password, method, plugin, pluginopts, udp, tfo, scv, define.NewTribool())
	case "VMess":
		id = jsonData["UserID"].(string)
		aid = jsonData["AlterID"].(string)
		transprot = jsonData["TransferProtocol"].(string)
		faketype = jsonData["FakeType"].(string)
		host = jsonData["Host"].(string)
		path = jsonData["Path"].(string)
		edge = jsonData["Edge"].(string)
		tls = jsonData["TLSSecure"].(string)
		sni = jsonData["ServerName"].(string)
		if group == "" {
			group = V2RAY_DEFAULT_GROUP
		}
		define.VMessProxyInit(node, group, remark, address, port, faketype, id, aid, transprot, method, path, host, edge, tls, sni, udp, tfo, scv, define.NewTribool())
	case "Socks5":
		username = jsonData["Username"].(string)
		if group == "" {
			group = SOCKS_DEFAULT_GROUP
		}
		define.SocksProxyInit(node, group, remark, address, port, username, password, udp, tfo, scv)
	case "HTTP", "HTTPS":
		if group == "" {
			group = HTTP_DEFAULT_GROUP
		}
		define.HttpProxyInit(node, group, remark, address, port, username, password, typeStr == "HTTPS", tfo, scv, define.NewTribool())
	case "Trojan":
		host = jsonData["Host"].(string)
		path = jsonData["Path"].(string)
		transprot = jsonData["TransferProtocol"].(string)
		tls = jsonData["TLSSecure"].(string)
		if group == "" {
			group = TROJAN_DEFAULT_GROUP
		}
		define.TrojanProxyInit(node, group, remark, address, port, password, transprot, host, path, tls == "true", udp, tfo, scv, define.NewTribool())
	case "Snell":
		obfs = jsonData["OBFS"].(string)
		host = jsonData["Host"].(string)
		aid = jsonData["SnellVersion"].(string)
		if group == "" {
			group = SNELL_DEFAULT_GROUP
		}
		define.SnellProxyInit(node, group, remark, address, port, password, obfs, host, util.Str2UInt16(aid), udp, tfo, scv)
	default:
		return
	}

}

func explodeVless(vless string, node *define.Proxy) {
	if ok, _ := regexp.MatchString("vless://(.*?)@(.*)", vless); ok {
		explodeStdVless(vless, node)
		return
	}
}

func explodeStdVless(vless string, node *define.Proxy) {
	var add, port, id, aid, net, flow, pbk, sid, fp, mode, path, host, tls, remarks string
	var addition string

	vless = vless[8:]
	pos := strings.LastIndex(vless, "#")
	if pos != -1 {
		remarks, _ = url.QueryUnescape(vless[pos+1:])
		vless = vless[:pos]
	}

	const stdvlessMatcher = `^([\da-f]{8}(?:-[\da-f]{4}){3}-[\da-f]{12})@\[?([\d\-a-zA-Z:.]+)\]?:(\d+)(?:\/?\?(.*))?$`
	if util.RegGetMatch(vless, stdvlessMatcher, &id, &add, &port, &addition) != nil {
		return
	}

	tls = util.GetUrlArg(addition, "security")
	net = util.GetUrlArg(addition, "type")
	flow = util.GetUrlArg(addition, "flow")
	pbk = util.GetUrlArg(addition, "pbk")
	sid = util.GetUrlArg(addition, "sid")
	fp = util.GetUrlArg(addition, "fp")

	if net == "" {
		net = "tcp"
	}

	switch net {
	case "tcp", "ws", "h2":
		host = util.GetUrlArg(addition, "sni")
		path = util.GetUrlArg(addition, "path")
	case "grpc":
		host = util.GetUrlArg(addition, "sni")
		path = util.GetUrlArg(addition, "serviceName")
		mode = util.GetUrlArg(addition, "mode")
	case "quic":
		host = util.GetUrlArg(addition, "sni")
		path = util.GetUrlArg(addition, "key")
	default:
		return
	}

	if remarks == "" {
		remarks = add + ":" + port
	}

	define.VlessProxyInit(node, XRAY_DEFAULT_GROUP, remarks, add, port, "", id, aid, net, "auto", flow, mode, path, host, "", tls, pbk, sid, fp, define.NewTribool(), define.NewTribool(), define.NewTribool(), define.NewTribool())
}
