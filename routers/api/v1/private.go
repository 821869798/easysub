package v1

import (
	"github.com/821869798/easysub/config"
	"github.com/gin-gonic/gin"
	"net/url"
)

func PrivateSub(c *gin.Context, r *gin.Engine) {
	path := c.Param("path")
	rewritePath := config.PrivateSub.RewritesFormatMap[path]
	if rewritePath == "" {
		c.String(404, "Not Found")
		return
	}
	internalRedirect(c, rewritePath, r)
}

// 封装的内部重定向函数
func internalRedirect(c *gin.Context, target string, router *gin.Engine) {
	u, err := url.Parse(target)
	if err != nil {
		c.AbortWithStatusJSON(400, gin.H{"error": "invalid redirect url"})
		return
	}

	c.Request.URL.Path = "/" + u.Path
	c.Request.URL.RawQuery = u.RawQuery

	router.HandleContext(c)
}
