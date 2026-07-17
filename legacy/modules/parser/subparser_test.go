package parser

import (
	"github.com/821869798/easysub/define"
	"testing"
)

func TestExplodeSS(t *testing.T) {
	ss := "ss://YWVzLTI1Ni1jZmI6S1NYTmhuWnBqd0M2UGM2Q0A1NC4xNjkuMzUuMjI4OjMxNDQ0"
	node := define.NewProxy()
	explodeSS(ss, node)
	if node.Type == define.ProxyType_Unknown {
		t.Error("explodeSS error")
	}
	t.Log(node)
}

func TestExplodeVmess(t *testing.T) {
	vmess := "vmess://ew0KICAicHMiOiAicnVzc2lhbi1jbG91ZCIsDQogICJhZGQiOiAiMTg1LjE3Ny4yMTYuMTM0IiwNCiAgInBvcnQiOiAiMjI1MzUiLA0KICAiaWQiOiAiNTIwNTAwNTctZjVlMS00YjllLWI3OGItNWY0OWI1NDlmZDIxIiwNCiAgImFpZCI6ICI2NCIsDQogICJuZXQiOiAia2NwIiwNCiAgInR5cGUiOiAic3J0cCIsDQogICJob3N0IjogIiIsDQogICJ0bHMiOiAiIg0KfQ=="
	node := define.NewProxy()
	explodeVmess(vmess, node)
	if node.Type == define.ProxyType_Unknown {
		t.Error("explodeVmess error")
	}
	t.Log(node)
}

func TestExplodeTrojan(t *testing.T) {
	trojan := "trojan://F16e3M7wrC@bwg.bvps.eu.org:443?ws=1&peer=bwg.bvps.eu.org&sni=bwg.bvps.eu.org#bwg.bvps.eu.org_trojan"
	node := define.NewProxy()
	explodeTrojan(trojan, node)
	if node.Type == define.ProxyType_Unknown {
		t.Error("explodeTrojan error")
	}
	t.Log(node)
}

func TestExplodeVless(t *testing.T) {
	vless := "vless://b0dd64e4-0fbd-4038-9139-d1f32a68a0dc@qv2ray.net:3279?security=xtls&flow=rprx-xtls-splice#VLESSTCPXTLSSplice"
	node := define.NewProxy()
	explodeVless(vless, node)
	if node.Type == define.ProxyType_Unknown {
		t.Error("explodeVless error")
	}
	t.Log(node)
}

func TestExplodeTUIC(t *testing.T) {
	tuic := "tuic://d220a622-2226-4a9d-8c06-bd1907348705:password@example.com:8080?heartbeat_interval=10000&disable_sni=false&reduce_rtt=true&request_timeout=8000&udp_relay_mode=native&congestion_control=bbr&max_udp_relay_packet_size=1500&max_open_streams=100&sni=example.com&fast_open=true&insecure=false#TUICExample"
	node := define.NewProxy()
	explodeTUIC(tuic, node)
	if node.Type == define.ProxyType_Unknown {
		t.Error("explodeTUIC error")
	}
	t.Log(node)
}
