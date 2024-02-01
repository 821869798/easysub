package define

import (
	"strconv"
	"strings"
)

// Tribool 表示三态布尔类型
type Tribool struct {
	value valueType
}

// valueType 是 Tribool 的内部枚举类型
type valueType int

const (
	indeterminate valueType = iota // 不确定状态
	falseValue                     // 假
	trueValue                      // 真
)

// NewTribool 创建一个新的 Tribool，默认为 indeterminate
func NewTribool() Tribool {
	return Tribool{value: indeterminate}
}

// NewTriboolFromBool 从 bool 创建 Tribool
func NewTriboolFromBool(b bool) Tribool {
	if b {
		return Tribool{value: trueValue}
	}
	return Tribool{value: falseValue}
}

// NewTriboolFromString 从字符串创建 Tribool
func NewTriboolFromString(str string) Tribool {
	t := NewTribool()
	t.Set(str)
	return t
}

// Set 从字符串设置 Tribool 的值
func (t *Tribool) Set(str string) bool {
	switch strings.ToLower(str) {
	case "true", "1":
		t.value = trueValue
	case "false", "0":
		t.value = falseValue
	default:
		if val, err := strconv.Atoi(str); err == nil && val > 1 {
			t.value = trueValue
		} else {
			t.value = indeterminate
		}
	}
	return !t.IsUndef()
}

// IsUndef 检查是否为不确定状态
func (t Tribool) IsUndef() bool {
	return t.value == indeterminate
}

// Get 获取 Tribool 的值，如果为不确定状态则返回默认值
func (t Tribool) Get(defValue bool) bool {
	if t.IsUndef() {
		return defValue
	}
	return t.value == trueValue
}

// GetStr 获取 Tribool 的字符串表示
func (t Tribool) GetStr() string {
	switch t.value {
	case indeterminate:
		return "undef"
	case falseValue:
		return "false"
	case trueValue:
		return "true"
	default:
		return ""
	}
}

// Reverse 反转 Tribool 的值
func (t *Tribool) Reverse() *Tribool {
	if t.value == falseValue {
		t.value = trueValue
	} else if t.value == trueValue {
		t.value = falseValue
	}
	return t
}

// Clear 将 Tribool 重置为不确定状态
func (t *Tribool) Clear() {
	t.value = indeterminate
}

// Define 如果当前为不确定状态，则设置为指定值
func (t *Tribool) Define(value bool) *Tribool {
	if t.IsUndef() {
		if value {
			t.value = trueValue
		} else {
			t.value = falseValue
		}
	}
	return t
}

func (t *Tribool) DefineTriBool(value Tribool) *Tribool {
	if t.IsUndef() {
		t.value = value.value
	}
	return t
}

// Parse 是 Define 的别名
func (t *Tribool) Parse(value bool) *Tribool {
	return t.Define(value)
}

// Equal 检查两个 Tribool 是否相等
func (t Tribool) Equal(other Tribool) bool {
	return t.value == other.value
}

// Bool 将 Tribool 转换为 bool（不确定状态视为 false）
func (t Tribool) Bool() bool {
	return t.value == trueValue
}

func GetTriboolFromMap(jsonData map[string]interface{}, key string) Tribool {
	v, ok := jsonData[key]
	if !ok {
		return NewTribool()
	}
	switch value := v.(type) {
	case bool:
		return NewTriboolFromBool(value)
	case string:
		return NewTriboolFromString(value)
	default:
		return NewTribool()
	}
}
