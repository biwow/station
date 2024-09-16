package api

import (
	"gitee.com/trustChain/blockchain/tools/key/ethkey"
	"gitee.com/trustChain/pkg/logger"
	"gitee.com/trustChain/pkg/output"
	"github.com/biwow/station/models"
	"github.com/biwow/station/tool"
	"github.com/gin-gonic/gin"
)

func CreateHostHandler(ctx *gin.Context) {
	json := make(map[string]interface{})
	_ = ctx.BindJSON(&json)
	hostname := output.ParamToString(json["hostname"])
	ip := output.ParamToString(json["ip"])
	// 验证hostname是否都是字母
	ok := tool.IsAllAlphabet(hostname)
	if !ok {
		output.ReturnErrorResponse(ctx, 9999, "host必须全是英文字母~")
		return
	}
	// 验证ip规则是否合法
	ok = tool.ValidateIPAddress(ip)
	if !ok {
		output.ReturnErrorResponse(ctx, 9999, "ip地址不合法~")
		return
	}
	// 随机生成私钥
	key := ethkey.GenerateKey()
	// 保存
	err := models.CreateAndUpdateHost(hostname, key.PublicKey.ToAddress(), key.ToHex(), ip)
	if err != nil {
		logger.Error("CreateHostHandler", "step", "CreateAndUpdateHost", "err", err)
		output.ReturnErrorResponse(ctx, 9999, "系统错误~")
	} else {
		output.ReturnSuccessResponse(ctx, "success")
	}
}
func UpdateHostHandler(ctx *gin.Context) {
	json := make(map[string]interface{})
	_ = ctx.BindJSON(&json)
	hostname := output.ParamToString(json["hostname"])
	ip := output.ParamToString(json["ip"])
	// 验证hostname是否都是字母
	ok := tool.IsAllAlphabet(hostname)
	if !ok {
		output.ReturnErrorResponse(ctx, 9999, "host必须全是英文字母~")
		return
	}
	// 验证ip规则是否合法
	ok = tool.ValidateIPAddress(ip)
	if !ok {
		output.ReturnErrorResponse(ctx, 9999, "ip地址不合法~")
		return
	}
	// 查询当前数据
	h, err := models.ViewHost()
	if err != nil {
		logger.Error("UpdateHostHandler", "step", "ViewHost", "err", err)
		output.ReturnErrorResponse(ctx, 9999, "系统错误~")
		return
	}
	// 判读数据是否一致
	if hostname == h.HostName && ip == h.HostIP {
		output.ReturnErrorResponse(ctx, 9999, "数据未发生变化~")
		return
	}
	// 更新数据
	err = models.CreateAndUpdateHost(hostname, h.HostID, h.HostMasterKey, ip)
	if err != nil {
		logger.Error("UpdateHostHandler", "step", "CreateAndUpdateHost", "err", err)
		output.ReturnErrorResponse(ctx, 9999, "系统错误~")
	} else {
		output.ReturnSuccessResponse(ctx, "success")
	}
}
func ViewHostHandler(ctx *gin.Context) {
	h, err := models.ViewHost()
	if err != nil {
		logger.Error("ViewHostHandler", "step", "ViewHost", "err", err)
		output.ReturnErrorResponse(ctx, 9999, "系统错误~")
	} else {
		output.ReturnSuccessResponse(ctx, h)
	}
}
