package parser

const (
	SS_DEFAULT_GROUP        = "SSProvider"
	SSR_DEFAULT_GROUP       = "SSRProvider"
	V2RAY_DEFAULT_GROUP     = "V2RayProvider"
	SOCKS_DEFAULT_GROUP     = "SocksProvider"
	HTTP_DEFAULT_GROUP      = "HTTPProvider"
	TROJAN_DEFAULT_GROUP    = "TrojanProvider"
	SNELL_DEFAULT_GROUP     = "SnellProvider"
	WG_DEFAULT_GROUP        = "WireGuardProvider"
	XRAY_DEFAULT_GROUP      = "XRayProvider"
	HYSTERIA_DEFAULT_GROUP  = "HysteriaProvider"
	HYSTERIA2_DEFAULT_GROUP = "Hysteria2Provider"
	TUIC_DEFAULT_GROUP      = "TuicProvider"
	ANYTLS_DEFAULT_GROUP    = "AnyTLSProvider"
)

var (
	ssCipersMapping = map[string]bool{
		"rc4-md5":                       true,
		"aes-128-gcm":                   true,
		"aes-192-gcm":                   true,
		"aes-256-gcm":                   true,
		"aes-128-cfb":                   true,
		"aes-192-cfb":                   true,
		"aes-256-cfb":                   true,
		"aes-128-ctr":                   true,
		"aes-192-ctr":                   true,
		"aes-256-ctr":                   true,
		"camellia-128-cfb":              true,
		"camellia-192-cfb":              true,
		"camellia-256-cfb":              true,
		"bf-cfb":                        true,
		"chacha20-ietf-poly1305":        true,
		"xchacha20-ietf-poly1305":       true,
		"salsa20":                       true,
		"chacha20":                      true,
		"chacha20-ietf":                 true,
		"2022-blake3-aes-128-gcm":       true,
		"2022-blake3-aes-256-gcm":       true,
		"2022-blake3-chacha20-poly1305": true,
		"2022-blake3-chacha12-poly1305": true,
		"2022-blake3-chacha8-poly1305":  true,
	}
	ssrCipersMapping = map[string]bool{
		"none":             true,
		"table":            true,
		"rc4":              true,
		"rc4-md5":          true,
		"aes-128-cfb":      true,
		"aes-192-cfb":      true,
		"aes-256-cfb":      true,
		"aes-128-ctr":      true,
		"aes-192-ctr":      true,
		"aes-256-ctr":      true,
		"bf-cfb":           true,
		"camellia-128-cfb": true,
		"camellia-192-cfb": true,
		"camellia-256-cfb": true,
		"cast5-cfb":        true,
		"des-cfb":          true,
		"idea-cfb":         true,
		"rc2-cfb":          true,
		"seed-cfb":         true,
		"salsa20":          true,
		"chacha20":         true,
		"chacha20-ietf":    true,
	}
)

func containSSCiper(ciper string) bool {
	_, ok := ssCipersMapping[ciper]
	return ok
}

func containSSRCiper(ciper string) bool {
	_, ok := ssrCipersMapping[ciper]
	return ok
}
