package v1

import (
	"bytes"
	"fmt"
	"github.com/821869798/easysub/config"
	"github.com/821869798/easysub/define"
	"github.com/821869798/easysub/export/clash"
	"github.com/821869798/easysub/modules/cache"
	"github.com/gin-gonic/gin"
	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/rules/provider"
	"strings"
	"sync"
	"time"
)

// add global buffer pool
var bufPool = sync.Pool{New: func() interface{} { return &bytes.Buffer{} }}

// add buffer capacity limit
const maxBufCap = 1 << 20 // 1MB

func Ruleset(c *gin.Context) {
	argTarget := c.Query("target")
	argUrls := strings.Split(c.Query("url"), "|")
	argBehavior := c.Query("behavior")
	if len(argUrls) == 0 {
		c.String(400, "Invalid request! no url provided")
		return
	}
	if argTarget == "" {
		c.String(400, "Invalid request! no target provided")
		return
	}

	requestURI := c.Request.RequestURI
	bs, found, err := cache.FileGet(requestURI)
	if err != nil {
		c.String(500, "Error retrieving cached data: %v", err)
		return
	}
	if found {
		c.Header("Content-Type", "application/octet-stream")
		c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s.mrs", define.GetRulesetContentName(argUrls)))
		c.Data(200, "application/octet-stream", bs)
		return
	}

	switch argTarget {
	case "clash":
		var convertType clash.ClashRuleSetConvertType
		var ruleBehavior P.RuleBehavior
		switch argBehavior {
		case "domain":
			convertType = clash.ClashRuleSetConvertType_Domain
			ruleBehavior = P.Domain
		case "ipcidr":
			convertType = clash.ClashRuleSetConvertType_IPCIDR
			ruleBehavior = P.IPCIDR
		default:
			c.String(400, "Invalid request! no behavior provided")
			return
		}
		rulesetContent := define.CreateRulesetContentFromUrls(argUrls, "", define.RULESET_SURGE)
		rulesetName := rulesetContent.GetRuleSetName()
		content := clash.ConvertRulesetContentToText(rulesetContent, convertType)
		buf := bufPool.Get().(*bytes.Buffer)
		buf.Reset()

		err := provider.ConvertToMrs([]byte(content), ruleBehavior, P.TextRule, buf)
		if err != nil {
			c.String(500, "Error converting ruleset: %v", err)
			return
		}

		// 缓存
		data := buf.Bytes()
		err = cache.FileSet(requestURI, data, time.Duration(config.Global.Advance.CacheConfig)*time.Second)
		if err != nil {
			c.String(500, "Error caching ruleset: %v", err)
			return
		}

		c.Header("Content-Type", "application/octet-stream")
		c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s.mrs", rulesetName))
		c.Data(200, "application/octet-stream", data)

		// only return buf to pool if capacity not exceeding limit
		if buf.Cap() <= maxBufCap {
			bufPool.Put(buf)
		}
	default:
		c.String(400, "Invalid request! no target provided")
		return
	}

}
