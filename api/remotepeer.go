package api

import (
	"gitee.com/trustChain/pkg/logger"
	"gitee.com/trustChain/pkg/output"
	"github.com/biwow/station/models"
	"github.com/biwow/station/tool"
	"github.com/gin-gonic/gin"
)

func CreateRemotePeerHandler(ctx *gin.Context) {
	json := make(map[string]interface{})
	_ = ctx.BindJSON(&json)
	peerId := output.ParamToString(json["peerId"])
	remotePeerName := output.ParamToString(json["remotePeerName"])
	remotePeerId := output.ParamToString(json["remotePeerId"])
	remotePeerPubKey := output.ParamToString(json["remotePeerPubKey"])
	ip := output.ParamToString(json["ip"])
	port := output.ParamToString(json["port"])
	cp := output.ParamToString(json["cp"])
	tp := output.ParamToString(json["tp"])
	// 验证remote peer name是否都是字母
	ok := tool.IsAllAlphabet(remotePeerName)
	if !ok {
		output.ReturnErrorResponse(ctx, 9999, "remote peer必须全是英文字母~")
		return
	}
	// 验证peer id 是否合法
	ok = tool.ValidateEthereumAddress(peerId)
	if !ok {
		output.ReturnErrorResponse(ctx, 9999, "peer id格式不合法~")
		return
	}
	// 验证remote peer id 是否合法
	ok = tool.ValidateEthereumAddress(remotePeerId)
	if !ok {
		output.ReturnErrorResponse(ctx, 9999, "remote peer id格式不合法~")
		return
	}
	// 验证remote peer PubKey是否合法
	ok = tool.ValidateEthereumCompressedPublicKey(remotePeerPubKey)
	if !ok {
		output.ReturnErrorResponse(ctx, 9999, "remote peer pubKey格式不合法~")
		return
	}
	// 验证ip规则是否合法
	ok = tool.ValidateIPAddress(ip)
	if !ok {
		output.ReturnErrorResponse(ctx, 9999, "ip地址格式不合法~")
		return
	}
	// 验证port规则是否合法
	ok = tool.ValidatePort(port)
	if !ok {
		output.ReturnErrorResponse(ctx, 9999, "port格式不合法~")
		return
	}
	// 验证cp是否合法
	ok = tool.ValidateCP(cp)
	if !ok {
		output.ReturnErrorResponse(ctx, 9999, "通信协议格式不合法~")
		return
	}
	// 验证tp是否合法
	ok = tool.ValidateTP(tp)
	if !ok {
		output.ReturnErrorResponse(ctx, 9999, "传输协议格式不合法~")
		return
	}
	// 保存
	err := models.CreateAndUpdateRemotePeer(peerId, remotePeerName, remotePeerId,
		remotePeerPubKey, ip+":"+port, cp, tp)
	if err != nil {
		logger.Error("CreateRemotePeerHandler", "step", "CreateAndUpdateRemotePeer", "err", err)
		output.ReturnErrorResponse(ctx, 9999, "系统错误~")
	} else {
		output.ReturnSuccessResponse(ctx, "success")
	}
}
func UpdateRemotePeerHandler(ctx *gin.Context) {
	json := make(map[string]interface{})
	_ = ctx.BindJSON(&json)
	peerId := output.ParamToString(json["peerId"])
	remotePeerName := output.ParamToString(json["remotePeerName"])
	remotePeerId := output.ParamToString(json["remotePeerId"])
	// 验证peer id 是否合法
	ok := tool.ValidateEthereumAddress(peerId)
	if !ok {
		output.ReturnErrorResponse(ctx, 9999, "peer id格式不合法~")
		return
	}
	// 验证remote peer name是否都是字母
	ok = tool.IsAllAlphabet(remotePeerName)
	if !ok {
		output.ReturnErrorResponse(ctx, 9999, "remote peer必须全是英文字母~")
		return
	}
	// 验证remote peer id 是否合法
	ok = tool.ValidateEthereumAddress(remotePeerId)
	if !ok {
		output.ReturnErrorResponse(ctx, 9999, "remote peer id格式不合法~")
		return
	}
	// 查询当前数据
	p, err := models.ViewRemotePeer(peerId, remotePeerId)
	if err != nil {
		logger.Error("UpdateRemotePeerHandler", "step", "ViewRemotePeer", "err", err)
		output.ReturnErrorResponse(ctx, 9999, "系统错误~")
		return
	}
	// 更新数据
	err = models.CreateAndUpdateRemotePeer(peerId, remotePeerName, p.RemotePeerId,
		p.RemotePeerPubKey, p.RemotePeerAddr, p.CommunicationProtocol, p.TransportProtocol)
	if err != nil {
		logger.Error("UpdateRemotePeerHandler", "step", "CreateAndUpdateRemotePeer", "err", err)
		output.ReturnErrorResponse(ctx, 9999, "系统错误~")
	} else {
		output.ReturnSuccessResponse(ctx, "success")
	}
}
func DeleteRemotePeerHandler(ctx *gin.Context) {
	peerId := output.ParamToString(ctx.Query("peerId"))
	remotePeerId := output.ParamToString(ctx.Query("remotePeerId"))
	err := models.DeleteRemotePeer(peerId, remotePeerId)
	if err != nil {
		logger.Error("DeleteRemotePeerHandler", "step", "DeleteRemotePeer", "err", err)
		output.ReturnErrorResponse(ctx, 9999, "系统错误~")
	} else {
		output.ReturnSuccessResponse(ctx, "success")
	}
}
func ListRemotePeerHandler(ctx *gin.Context) {
	peerId := output.ParamToString(ctx.Query("peerId"))
	rps, err := models.ListRemotePeer(peerId)
	if err != nil {
		if err.Error() == "leveldb: not found" {
			output.ReturnSuccessResponse(ctx, nil)
			return
		} else {
			logger.Error("ListRemotePeerHandler", "step", "ListRemotePeer", "err", err)
			output.ReturnErrorResponse(ctx, 9999, "系统错误~")
			return
		}
	}
	// map转数组
	var arr []models.RemotePeer
	for _, item := range rps {
		arr = append(arr, item)
	}

	output.ReturnSuccessResponse(ctx, arr)
}
func ViewRemotePeerHandler(ctx *gin.Context) {
	peerId := output.ParamToString(ctx.Query("peerId"))
	remotePeerId := output.ParamToString(ctx.Query("remotePeerId"))
	rp, err := models.ViewRemotePeer(peerId, remotePeerId)
	if err != nil {
		if err.Error() == "leveldb: not found" {
			output.ReturnSuccessResponse(ctx, nil)
			return
		} else {
			logger.Error("ViewRemotePeerHandler", "step", "ViewRemotePeer", "err", err)
			output.ReturnErrorResponse(ctx, 9999, "系统错误~")
			return
		}
	}
	output.ReturnSuccessResponse(ctx, rp)
}
