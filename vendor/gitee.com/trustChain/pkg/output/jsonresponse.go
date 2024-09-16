package output

import (
	"github.com/gin-gonic/gin"
	"net/http"
)

type Response struct {
	Msg  string      `json:"msg"`
	Code int64       `json:"code"`
	Data interface{} `json:"data,omitempty"`
}

// ReturnSuccessResponse 接口返回数据信息
func ReturnSuccessResponse(ctx *gin.Context, data interface{}) {
	response := &Response{
		Msg:  "success",
		Code: 0,
		Data: data,
	}
	ctx.JSON(http.StatusOK, response)
	return
}

// ReturnErrorResponse 返回错误
func ReturnErrorResponse(ctx *gin.Context, code int64, errmsg string) {
	response := &Response{
		Msg:  errmsg,
		Code: code,
	}
	ctx.JSON(http.StatusOK, response)
	return
}
