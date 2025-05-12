package main

import (
	"github.com/821869798/easysub/config"
	"github.com/821869798/easysub/routers"
	"github.com/821869798/fankit/fanpath"
	"github.com/gin-gonic/gin"
	"github.com/lmittmann/tint"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"
)

func main() {

	loadConfig()
	setupLog()

	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()

	routers.Setup(r)

	portStr := strings.TrimSpace(os.Getenv(config.Global.Advance.PortEnvVar))
	if portStr == "" {
		portStr = strconv.Itoa(config.Global.Advance.DefaultPort)
	}

	// server run log
	slog.Info("server run start", slog.String("port", portStr))

	err := r.Run(":" + portStr)
	if err != nil {
		slog.Error(err.Error())
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
		slog.Error("no config file found")
		os.Exit(1)
	}
	config.LoadConfig(configPath)

}

func setupLog() {

	var logLevel slog.Level
	switch config.Global.Advance.LogLevel {
	case "debug":
		logLevel = slog.LevelDebug
	case "info":
		logLevel = slog.LevelInfo
	case "warn":
		logLevel = slog.LevelWarn
	case "error":
		logLevel = slog.LevelError
	default:
		logLevel = slog.LevelInfo
	}

	slog.SetDefault(slog.New(
		tint.NewHandler(os.Stdout, &tint.Options{
			Level:      logLevel,
			TimeFormat: time.DateTime,
			AddSource:  true,
		}),
	))
}
