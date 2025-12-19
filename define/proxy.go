package define

import (
	"net/url"
	"strconv"
	"strings"

	"github.com/821869798/easysub/modules/util"
)

type ProxyType int

const (
	ProxyType_Unknown ProxyType = iota
	ProxyType_Shadowsocks
	ProxyType_VMess
	ProxyType_Trojan
	ProxyType_Snell
	ProxyType_HTTP
	ProxyType_HTTPS
	ProxyType_SOCKS5
	ProxyType_WireGuard
	ProxyType_VLESS
	ProxyType_TUIC
	ProxyType_ANYTLS
)

func (p ProxyType) String() string {
	return [...]string{
		"Unknown",
		"Shadowsocks",
		"VMess",
		"Trojan",
		"Snell",
		"HTTP",
		"HTTPS",
		"SOCKS5",
		"WireGuard",
		"VLESS",
		"TUIC",
		"ANYTLS",
	}[p]
}

type Proxy struct {
	Type ProxyType

	Id      uint32
	GroupId uint32
	Group   string
	Remark  string

	Hostname string
	Port     uint16

	Username         string
	Password         string
	EncryptMethod    string
	Plugin           string
	PluginOption     string
	Protocol         string
	ProtocolParam    string
	OBFS             string
	OBFSParam        string
	UserId           string
	AlterId          uint16
	TransferProtocol string
	FakeType         string
	TLSSecure        bool

	Flow     string
	FlowShow bool

	Host string
	Path string
	Edge string

	QUICSecure      string
	QUICSecret      string
	GRPCServiceName string
	GRPCMode        string

	UDP           Tribool
	TCPFastOpen   Tribool
	AllowInsecure Tribool
	TLS13         Tribool

	SnellVersion uint16
	ServerName   string

	SelfIP       string
	SelfIPv6     string
	PublicKey    string
	PrivateKey   string
	PreSharedKey string
	DnsServers   []string
	Mtu          uint16
	AllowedIPs   string
	KeepAlive    uint16
	TestUrl      string
	ClientId     string

	Fingerprint string
	ShortId     string

	// TUIC fields
	UUID                  string
	HeartbeatInterval     string
	DisableSNI            string
	ReduceRTT             string
	RequestTimeout        uint32
	UdpRelayMode          string
	CongestionController  string
	MaxUdpRelayPacketSize uint32
	MaxOpenStreams        uint32
	FastOpen              Tribool
	Alpn                  []string

	// ANYTLS session management fields
	IdleSessionCheckInterval uint32
	IdleSessionTimeout       uint32
	MinIdleSession           uint32
}

func NewProxy() *Proxy {
	return &Proxy{
		AllowedIPs: "0.0.0.0/0, ::/0",
		Type:       ProxyType_Unknown,
	}
}

func TuicProxyInit(node *Proxy, group, remarks, server, port, uuid, password, ip, heartbeatInterval, alpn, disableSNI, reduceRTT, requestTimeout, udpRelayMode, congestionController, maxUdpRelayPacketSize, maxOpenStreams, sni, fastOpen string, tfo, scv Tribool) {
	proxyCommonInit(node, ProxyType_TUIC, group, remarks, server, port, NewTribool(), tfo, scv, NewTribool())
	node.UUID = uuid
	node.Password = password
	// node.IP = ip  // C++中存在这个字段，但Go结构中没有
	if alpn != "" {
		node.Alpn = []string{alpn}
	}
	node.HeartbeatInterval = heartbeatInterval
	node.DisableSNI = disableSNI
	node.ReduceRTT = reduceRTT
	if requestTimeout != "" {
		if val, err := strconv.ParseUint(requestTimeout, 10, 32); err == nil {
			node.RequestTimeout = uint32(val)
		}
	}
	node.UdpRelayMode = udpRelayMode
	node.CongestionController = congestionController
	if maxUdpRelayPacketSize != "" {
		if val, err := strconv.ParseUint(maxUdpRelayPacketSize, 10, 32); err == nil {
			node.MaxUdpRelayPacketSize = uint32(val)
		}
	}
	if maxOpenStreams != "" {
		if val, err := strconv.ParseUint(maxOpenStreams, 10, 32); err == nil {
			node.MaxOpenStreams = uint32(val)
		}
	}
	node.ServerName = sni
	if fastOpen != "" {
		node.FastOpen = NewTriboolFromString(fastOpen)
	}
	node.TLSSecure = true
}

func AnyTLSProxyInit(node *Proxy, group, remarks, server, port, password, sni, alpn, fingerprint, idleSessionCheckInterval, idleSessionTimeout, minIdleSession string, tfo, scv Tribool) {
	proxyCommonInit(node, ProxyType_ANYTLS, group, remarks, server, port, NewTribool(), tfo, scv, NewTribool())
	node.Password = password
	node.ServerName = sni
	if alpn != "" {
		node.Alpn = []string{alpn}
	}
	node.Fingerprint = fingerprint

	if idleSessionCheckInterval != "" {
		if val, err := strconv.ParseUint(idleSessionCheckInterval, 10, 32); err == nil {
			node.IdleSessionCheckInterval = uint32(val)
		}
	}
	if idleSessionTimeout != "" {
		if val, err := strconv.ParseUint(idleSessionTimeout, 10, 32); err == nil {
			node.IdleSessionTimeout = uint32(val)
		}
	}
	if minIdleSession != "" {
		if val, err := strconv.ParseUint(minIdleSession, 10, 32); err == nil {
			node.MinIdleSession = uint32(val)
		}
	}
	node.TLSSecure = true
}

func proxyCommonInit(node *Proxy, proxyType ProxyType, group, remarks, server, port string, udp, tfo, scv, tls13 Tribool) {

	node.Type = proxyType
	node.Group = group
	node.Remark = remarks
	node.Hostname = server
	node.Port = util.Str2UInt16(port)
	node.UDP = udp
	node.TCPFastOpen = tfo
	node.AllowInsecure = scv
	node.TLS13 = tls13

}

func VMessProxyInit(node *Proxy, group, remarks, server, port, fakeType, id, aid, net, cipher, path, host, edge, tls, sni string, udp, tfo, scv, tls13 Tribool) {
	proxyCommonInit(node, ProxyType_VMess, group, remarks, server, port, udp, tfo, scv, tls13)
	if id == "" {
		id = "00000000-0000-0000-0000-000000000000"
	}
	node.UserId = id
	node.AlterId = util.Str2UInt16(aid)
	node.EncryptMethod = cipher
	if net == "" {
		net = "tcp"
	}
	node.TransferProtocol = net
	node.Edge = edge
	node.ServerName = sni

	if net == "quic" {
		node.QUICSecure = host
		node.QUICSecret = path
	} else {
		if host == "" && !util.IsIPv4(server) && !util.IsIPv6(server) {
			node.Host = server
		} else {
			node.Host = strings.TrimSpace(host)
		}
		if path == "" {
			node.Path = "/"
		} else {
			node.Path = strings.TrimSpace(path)
		}
	}

	node.FakeType = fakeType
	node.TLSSecure = tls == "tls"
}

func SSProxyInit(node *Proxy, group, remarks, server, port, password, method, plugin, pluginopts string, udp, tfo, scv, tls13 Tribool) {
	proxyCommonInit(node, ProxyType_Shadowsocks, group, remarks, server, port, udp, tfo, scv, tls13)
	node.Password = password
	node.EncryptMethod = method
	node.Plugin = plugin
	node.PluginOption = pluginopts
}

func SocksProxyInit(node *Proxy, group, remarks, server, port, username, password string, udp, tfo, scv Tribool) {
	proxyCommonInit(node, ProxyType_SOCKS5, group, remarks, server, port, udp, tfo, scv, NewTribool())
	node.Username = username
	node.Password = password
}

func HttpProxyInit(node *Proxy, group, remarks, server, port, username, password string, tls bool, tfo, scv, tls13 Tribool) {
	var proxyType ProxyType = ProxyType_HTTP
	if tls {
		proxyType = ProxyType_HTTPS
	}
	proxyCommonInit(node, proxyType, group, remarks, server, port, NewTribool(), tfo, scv, tls13)
	node.Username = username
	node.Password = password
	node.TLSSecure = tls
}

func TrojanProxyInit(node *Proxy, group, remarks, server, port, password, network, host, path string, tlssecure bool, udp, tfo, scv, tls13 Tribool) {
	proxyCommonInit(node, ProxyType_Trojan, group, remarks, server, port, udp, tfo, scv, tls13)
	node.Password = password
	node.Host = host
	node.TLSSecure = tlssecure
	if network == "" {
		network = "tcp"
	}
	node.TransferProtocol = network
	node.Path = path
}

func SnellProxyInit(node *Proxy, group, remarks, server, port, password, obfs, host string, version uint16, udp, tfo, scv Tribool) {
	proxyCommonInit(node, ProxyType_Snell, group, remarks, server, port, udp, tfo, scv, NewTribool())
	node.Password = password
	node.OBFS = obfs
	node.Host = host
	node.SnellVersion = version
}

func WireGuardProxyInit(node *Proxy, group, remarks, server, port, selfIp, selfIpv6, privKey, pubKey, psk string, dns []string, mtu, keepalive, testUrl, clientId string, udp Tribool) {
	proxyCommonInit(node, ProxyType_WireGuard, group, remarks, server, port, udp, NewTribool(), NewTribool(), NewTribool())
	node.SelfIP = selfIp
	node.SelfIPv6 = selfIpv6
	node.PrivateKey = privKey
	node.PublicKey = pubKey
	node.PreSharedKey = psk
	node.DnsServers = dns
	node.Mtu = util.Str2UInt16(mtu)
	node.KeepAlive = util.Str2UInt16(keepalive)
	node.TestUrl = testUrl
	node.ClientId = clientId
}

func VlessProxyInit(node *Proxy, group, remarks, address, port, fakeType, id, aid, net, cipher, flow, mode, path, host, edge, tls, pbk, sid, fp string, udp, tfo, scv, tls13 Tribool) {
	proxyCommonInit(node, ProxyType_VLESS, group, remarks, address, port, udp, tfo, scv, tls13)
	if id == "" {
		node.UserId = "00000000-0000-0000-0000-000000000000"
	} else {
		node.UserId = id
	}
	node.AlterId = util.Str2UInt16(aid)
	node.EncryptMethod = cipher
	if net == "" {
		node.TransferProtocol = "tcp"
	} else if fakeType == "http" {
		node.TransferProtocol = "http"
	} else {
		node.TransferProtocol = net
	}
	node.Edge = edge
	node.Flow = flow
	node.FakeType = fakeType
	node.TLSSecure = tls == "tls" || tls == "xtls" || tls == "reality"
	node.PublicKey = pbk
	node.ShortId = sid
	node.Fingerprint = fp

	switch net {
	case "grpc":
		node.Host = host
		if mode == "" {
			node.GRPCMode = "gun"
		} else {
			node.GRPCMode = mode
		}
		if path == "" {
			node.GRPCServiceName = "/"
		} else {
			pathNew, _ := url.QueryUnescape(strings.TrimSpace(path))
			node.GRPCServiceName = url.QueryEscape(pathNew)
		}
	case "quic":
		node.QUICSecure = host
		if path == "" {
			node.QUICSecret = "/"
		} else {
			node.QUICSecret = strings.TrimSpace(path)
		}
	default:
		if host == "" && !util.IsIPv4(address) && !util.IsIPv6(address) {
			node.Host = address
		} else {
			node.Host = strings.TrimSpace(host)
		}
		if path == "" {
			node.Path = "/"
		} else {
			node.Path, _ = url.QueryUnescape(strings.TrimSpace(path))
		}
	}
}
