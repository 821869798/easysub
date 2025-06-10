package config

import (
	"os"
	"strconv"
)

type GlobalEnvConfig struct {
	SubForceHttps bool
}

var GlobalEnv *GlobalEnvConfig

func init() {
	GlobalEnv = &GlobalEnvConfig{}
	GlobalEnv.SubForceHttps, _ = strconv.ParseBool(os.Getenv("SUB_FORCE_HTTPS")) // Ensure the environment variable is set
}
