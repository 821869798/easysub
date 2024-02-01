package v1

import (
	"github.com/821869798/easysub/define"
	"github.com/gin-gonic/gin"
	"strconv"
)

func queryArgOrDefaultBool(c *gin.Context, argName string, def bool) bool {
	argValue := c.Query(argName)
	if argValue == "" {
		return def
	}
	boolValue, err := strconv.ParseBool(argValue)
	if err != nil {
		return def
	}
	return boolValue
}

func queryArgOrDefaultTriBool(c *gin.Context, argName string, def bool) define.Tribool {
	argValue := c.Query(argName)
	if argValue == "" {
		return define.NewTriboolFromBool(def)
	}
	boolValue, err := strconv.ParseBool(argValue)
	if err != nil {
		return define.NewTriboolFromBool(def)
	}
	return define.NewTriboolFromBool(boolValue)
}

func queryArgOrDefaultString(c *gin.Context, argName string, def string) string {
	argValue := c.Query(argName)
	if argValue == "" {
		return def
	} else {
		return argValue
	}
}

func queryArgOrDefaultInt(c *gin.Context, argName string, def int) int {
	argValue := c.Query(argName)
	if argValue == "" {
		return def
	}
	intValue, err := strconv.Atoi(argValue)
	if err != nil {
		return def
	}
	return intValue
}

func queryArgOrDefaultFloat(c *gin.Context, argName string, def float64) float64 {
	argValue := c.Query(argName)
	if argValue == "" {
		return def
	}
	floatValue, err := strconv.ParseFloat(argValue, 64)
	if err != nil {
		return def
	}
	return floatValue
}
