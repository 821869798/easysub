package define

type ConfType int

const (
	ConfType_Unknow ConfType = iota
	ConfType_SS
	ConfType_SSR
	ConfType_V2Ray
	ConfType_SSConf
	ConfType_SSTap
	ConfType_Netch
	ConfType_SOCKS
	ConfType_HTTP
	ConfType_SUB
	ConfType_Local
)
