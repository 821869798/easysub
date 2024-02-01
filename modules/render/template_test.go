package render

import (
	"github.com/821869798/easysub/modules/util"
	"github.com/osteele/liquid"
	"github.com/osteele/liquid/values"
	"log"
	"strconv"
	"testing"
)

func TestTemplateLiquid(t *testing.T) {
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
	engine.RegisterFilter("test", func(value interface{}) interface{} {
		if value == nil || value == false || values.IsEmpty(value) {
			return ""
		}
		test, ok := value.(*KeyGroup)
		if ok {
			return test.Test()
		}
		return ""
	})
	template := `<h1> {{ Key | test }} {{ page.title }} {{ MapData.key1 }} {{ MapData.key3.asd_qwe }} {% if (Bool | bool) == false %}xxx{% endif %}</h1>`
	bindings := map[string]interface{}{
		"page": map[string]string{
			"title": "Introduction",
		},
		"MapData": util.ConvertToNestedMap(map[string]string{
			"key1":         "value1",
			"key2":         "value2",
			"key3.asd_qwe": "value3",
		}),
		"Bool": "false",
		"Key": &KeyGroup{
			Key1: "key1",
			Key2: "key2",
		},
	}
	out, err := engine.ParseAndRenderString(template, bindings)
	if err != nil {
		log.Fatalln(err)
	}
	t.Log(out)
}

type KeyGroup struct {
	Key1 string
	Key2 string
}

func (t *KeyGroup) Test() string {
	return t.Key1 + t.Key2
}
