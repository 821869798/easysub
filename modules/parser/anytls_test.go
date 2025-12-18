package parser

import (
	"testing"

	"github.com/821869798/easysub/define"
)

func TestExplodeAnyTLS(t *testing.T) {
	tests := []struct {
		name     string
		link     string
		wantType define.ProxyType
		wantHost string
		wantPort uint16
		wantPass string
		wantSNI  string
	}{
		{
			name:     "anytls with password@host:port format",
			link:     "anytls://testpass@example.com:443?peer=sni.example.com&alpn=h2&hpkp=sha256fingerprint&insecure=true#Test%20Node",
			wantType: define.ProxyType_ANYTLS,
			wantHost: "example.com",
			wantPort: 443,
			wantPass: "testpass",
			wantSNI:  "sni.example.com",
		},
		{
			name:     "anytls with password parameter",
			link:     "anytls://example.com:443?password=testpass&peer=sni.example.com&alpn=h2#Test",
			wantType: define.ProxyType_ANYTLS,
			wantHost: "example.com",
			wantPort: 443,
			wantPass: "testpass",
			wantSNI:  "sni.example.com",
		},
		{
			name:     "anytls with session management parameters",
			link:     "anytls://mypass@192.168.1.1:8443?peer=test.com&idle_session_check_interval=30&idle_session_timeout=60&min_idle_session=2",
			wantType: define.ProxyType_ANYTLS,
			wantHost: "192.168.1.1",
			wantPort: 8443,
			wantPass: "mypass",
			wantSNI:  "test.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			node := define.NewProxy()
			explodeAnyTLS(tt.link, node)

			if node.Type != tt.wantType {
				t.Errorf("Type = %v, want %v", node.Type, tt.wantType)
			}
			if node.Hostname != tt.wantHost {
				t.Errorf("Hostname = %v, want %v", node.Hostname, tt.wantHost)
			}
			if node.Port != tt.wantPort {
				t.Errorf("Port = %v, want %v", node.Port, tt.wantPort)
			}
			if node.Password != tt.wantPass {
				t.Errorf("Password = %v, want %v", node.Password, tt.wantPass)
			}
			if node.ServerName != tt.wantSNI {
				t.Errorf("ServerName = %v, want %v", node.ServerName, tt.wantSNI)
			}
		})
	}
}
