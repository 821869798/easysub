package limiter

import (
	"github.com/gin-gonic/gin"
	"net/http"
)

// ConcurrencyLimiter 定义了我们的并发和队列控制器
type ConcurrencyLimiter struct {
	concurrencyChannel chan struct{} // 用于控制并发的信号量
	queueChannel       chan struct{} // 用于控制等待队列长度
}

// NewConcurrencyLimiter 创建一个新的控制器实例
// maxConcurrency: 最大并发数
// maxQueueSize: 最大等待队列长度
func NewConcurrencyLimiter(maxConcurrency, maxQueueSize int) *ConcurrencyLimiter {
	return &ConcurrencyLimiter{
		concurrencyChannel: make(chan struct{}, maxConcurrency),
		queueChannel:       make(chan struct{}, maxQueueSize),
	}
}

// Middleware 创建一个 Gin 中间件
func (cl *ConcurrencyLimiter) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 1. 尝试获取一个排队名额
		select {
		case cl.queueChannel <- struct{}{}:
			// 获取排队名额成功，继续下一步
		default:
			// 如果 queueChannel 已满，说明等待队列已满，直接拒绝服务
			c.JSON(http.StatusTooManyRequests, gin.H{
				"code":    http.StatusTooManyRequests,
				"message": "Too Many Requests, the waiting queue is full.",
			})
			c.Abort()
			return
		}

		// 函数返回前，必须释放排队名额
		defer func() {
			<-cl.queueChannel
		}()

		// 2. 尝试获取一个并发处理名额 (如果并发满了，这里会阻塞，实现排队)
		cl.concurrencyChannel <- struct{}{}

		// 函数返回前，必须释放并发名额
		defer func() {
			<-cl.concurrencyChannel
		}()

		// 3. 已成功获取处理名额，执行后续处理
		c.Next()
	}
}
