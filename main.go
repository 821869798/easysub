package main

import (
	"github.com/821869798/easysub/config"
	"github.com/821869798/easysub/routers"
	"github.com/821869798/fankit/fanpath"
	"github.com/gin-gonic/gin"
	"github.com/gookit/slog"
	"os"
	"strconv"
	"strings"
)

func main() {

	loadConfig()

	r := gin.Default()
	gin.SetMode(gin.ReleaseMode)

	routers.Setup(r)

	portStr := strings.TrimSpace(os.Getenv(config.Global.Advance.PortEnvVar))
	if portStr == "" {
		portStr = strconv.Itoa(config.Global.Advance.DefaultPort)
	}

	err := r.Run(":" + portStr)
	if err != nil {
		slog.Error(err)
	}
}

func loadConfig() {
	configPath := ""
	if fanpath.ExistFile("pref.toml") {
		configPath = "pref.toml"
	} else if fanpath.ExistFile("pref.example.toml") {
		// 拷贝一份pref.example.toml 到 pref.toml，不是重命名
		_ = fanpath.CopyFile("pref.example.toml", "pref.toml")
		configPath = "pref.toml"
	} else {
		slog.Panic("no config file found")
		os.Exit(1)
	}
	config.LoadConfig(configPath)
	switch config.Global.Advance.LogLevel {
	case "debug":
		slog.SetLogLevel(slog.DebugLevel)
	case "info":
		slog.SetLogLevel(slog.InfoLevel)
	case "warn":
		slog.SetLogLevel(slog.WarnLevel)
	case "error":
		slog.SetLogLevel(slog.ErrorLevel)
	default:
		slog.SetLogLevel(slog.InfoLevel)
	}
}
