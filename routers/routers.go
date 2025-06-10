package routers

import (
	"github.com/821869798/easysub/config"
	v1 "github.com/821869798/easysub/routers/api/v1"
	"github.com/gin-gonic/gin"
)

func Setup(r *gin.Engine) {
	r.GET("/sub", v1.Sub)

	// hello easysub
	r.GET("/", func(c *gin.Context) {
		c.String(200, "hello easysub")
	})

	r.GET("/ruleset", v1.Ruleset)

	// private sub
	if config.PrivateSub != nil {
		r.GET("/p/*path", func(c *gin.Context) {
			v1.PrivateSub(c, r)
		})
	}

	//r.Static(config.Global.Advance.FileServerUrlPath, config.Global.Advance.FileServerPath)
	//r.StaticFS("/files", gin.Dir(config.Global.Advance.FileServerPath, true))
}
