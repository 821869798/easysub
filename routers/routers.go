package routers

import (
	v1 "github.com/821869798/easysub/routers/api/v1"
	"github.com/gin-gonic/gin"
)

func Setup(r *gin.Engine) {
	r.GET("/sub", v1.Sub)
	//r.Static(config.Global.Advance.FileServerUrlPath, config.Global.Advance.FileServerPath)
	//r.StaticFS("/files", gin.Dir(config.Global.Advance.FileServerPath, true))
}
