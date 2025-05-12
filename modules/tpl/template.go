package tpl

import (
	"github.com/osteele/liquid"
	"github.com/osteele/liquid/values"
	"strconv"
)

var (
	defaultEngine *liquid.Engine
)

func init() {
	defaultEngine = CreateDefaultEngine()
}

func CreateDefaultEngine() *liquid.Engine {
	engine := liquid.NewEngine()
	engine.RegisterFilter("bool", func(value interface{}) interface{} {
		if value == nil || value == false || values.IsEmpty(value) {
			return false
		}
		switch v := value.(type) {
		case int:
			return v != 0
		case string:
			b, _ := strconv.ParseBool(v)
			return b
		case bool:
			return v
		default:
			return true
		}
	})
	return engine
}

func RenderTemplate(content string, tplArgs map[string]interface{}) (string, error) {
	out, err := defaultEngine.ParseAndRenderString(content, tplArgs)
	if err != nil {
		return "", err
	}
	return out, err
}
