package api

import (
	"gitee.com/trustChain/blockchain/tools/key/ethkey"
	"gitee.com/trustChain/pkg/logger"
	"gitee.com/trustChain/pkg/output"
	"github.com/biwow/station/core/host"
	"github.com/biwow/station/models"
	"github.com/biwow/station/tool"
	"github.com/gin-gonic/gin"
	"strings"
)

func CreatePeerHandler(ctx *gin.Context) {
	json := make(map[string]interface{})
	_ = ctx.BindJSON(&json)
	peerName := output.ParamToString(json["peerName"])
	ip := output.ParamToString(json["ip"])
	port := output.ParamToString(json["port"])
	cp := output.ParamToString(json["cp"])
	tp := output.ParamToString(json["tp"])
	// 验证peer name 是否都是字母
	ok := tool.IsAllAlphabet(peerName)
	if !ok {
		output.ReturnErrorResponse(ctx, 9999, "peer必须全是英文字母~")
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
	// 随机生成私钥
	key := ethkey.GenerateKey()
	// 保存
	err := models.CreateAndUpdatePeer(peerName, key.PublicKey.ToAddress(),
		key.PublicKey.ToHex(), key.ToHex(), ip+":"+port, cp, tp)
	if err != nil {
		logger.Error("CreatePeerHandler", "step", "CreateAndUpdatePeer", "err", err)
		output.ReturnErrorResponse(ctx, 9999, "系统错误~")
	} else {
		output.ReturnSuccessResponse(ctx, "success")
	}
}

func UpdatePeerHandler(ctx *gin.Context) {
	json := make(map[string]interface{})
	_ = ctx.BindJSON(&json)
	peerName := output.ParamToString(json["peerName"])
	peerId := output.ParamToString(json["peerId"])
	ip := output.ParamToString(json["ip"])
	port := output.ParamToString(json["port"])
	cp := output.ParamToString(json["cp"])
	tp := output.ParamToString(json["tp"])
	// 验证peer name是否都是字母
	ok := tool.IsAllAlphabet(peerName)
	if !ok {
		output.ReturnErrorResponse(ctx, 9999, "peer必须全是英文字母~")
		return
	}
	// 验证ip规则是否合法
	ok = tool.ValidateIPAddress(ip)
	if !ok {
		output.ReturnErrorResponse(ctx, 9999, "ip地址不合法~")
		return
	}
	// 验证port规则是否合法
	ok = tool.ValidatePort(port)
	if !ok {
		output.ReturnErrorResponse(ctx, 9999, "port不合法~")
		return
	}
	// 验证cp是否合法
	ok = tool.ValidateCP(cp)
	if !ok {
		output.ReturnErrorResponse(ctx, 9999, "通信协议不合法~")
		return
	}
	// 验证tp是否合法
	ok = tool.ValidateTP(tp)
	if !ok {
		output.ReturnErrorResponse(ctx, 9999, "传输协议不合法~")
		return
	}
	// 查询当前数据
	p, err := models.ViewPeer(peerId)
	if err != nil {
		logger.Error("UpdatePeerHandler", "step", "ViewPeer", "err", err)
		output.ReturnErrorResponse(ctx, 9999, "系统错误~")
		return
	}
	// 更新数据
	err = models.CreateAndUpdatePeer(peerName, p.PeerId,
		p.PeerPubKey, p.PeerPriKey, ip+":"+port, cp, tp)
	if err != nil {
		logger.Error("UpdatePeerHandler", "step", "CreateAndUpdatePeer", "err", err)
		output.ReturnErrorResponse(ctx, 9999, "系统错误~")
	} else {
		output.ReturnSuccessResponse(ctx, "success")
	}
}

func DeletePeerHandler(ctx *gin.Context) {
	peerId := output.ParamToString(ctx.Query("peerId"))
	err := models.DeletePeer(peerId)
	if err != nil {
		logger.Error("DeletePeerHandler", "step", "DeletePeer", "err", err)
		output.ReturnErrorResponse(ctx, 9999, "系统错误~")
	} else {
		output.ReturnSuccessResponse(ctx, "success")
	}
}

func ListPeerHandler(ctx *gin.Context) {
	ps, err := models.ListPeer()
	if err != nil {
		if err.Error() == "leveldb: not found" {
			output.ReturnSuccessResponse(ctx, nil)
			return
		} else {
			logger.Error("ListPeerHandler", "step", "ListPeer", "err", err)
			output.ReturnErrorResponse(ctx, 9999, "系统错误~")
			return
		}
	}
	// map转数组
	var arr []models.Peer
	for _, item := range ps {
		arr = append(arr, item)
	}

	output.ReturnSuccessResponse(ctx, arr)
}

func ViewPeerHandler(ctx *gin.Context) {
	peerId := output.ParamToString(ctx.Query("peerId"))
	p, err := models.ViewPeer(peerId)
	if err != nil {
		if err.Error() == "leveldb: not found" {
			output.ReturnSuccessResponse(ctx, nil)
			return
		} else {
			logger.Error("ViewPeerHandler", "step", "ViewPeer", "err", err)
			output.ReturnErrorResponse(ctx, 9999, "系统错误~")
			return
		}
	}
	output.ReturnSuccessResponse(ctx, p)
}

// PeerListenStartHandler 启动peer节点监听
func PeerListenStartHandler(ctx *gin.Context) {
	json := make(map[string]interface{})
	_ = ctx.BindJSON(&json)
	peerId := output.ParamToString(json["peerId"])
	// 从leveldb取出peer信息
	p, err := models.ViewPeer(peerId)
	if err != nil {
		logger.Error("PeerListenStartHandler", "step", "ViewPeer", "err", err)
		output.ReturnErrorResponse(ctx, 9999, "系统错误~")
		return
	}
	err = host.InstanceHost().PeerListenStart(p)
	if err != nil {
		logger.Error("PeerListenStartHandler", "step", "PeerListenStart", "err", err)
		output.ReturnErrorResponse(ctx, 9999, "系统错误~")
	} else {
		output.ReturnSuccessResponse(ctx, "success")
	}
}

func PeerListenStopHandler(ctx *gin.Context) {
	json := make(map[string]interface{})
	_ = ctx.BindJSON(&json)
	peerId := output.ParamToString(json["peerId"])
	err := host.InstanceHost().PeerListenStop(peerId)
	if err != nil {
		logger.Error("PeerListenStopHandler", "step", "PeerListenStop", "err", err)
		output.ReturnErrorResponse(ctx, 9999, "系统错误~")
	} else {
		output.ReturnSuccessResponse(ctx, "success")
	}
}

func PeerDialStartHandler(ctx *gin.Context) {
	json := make(map[string]interface{})
	_ = ctx.BindJSON(&json)
	peerId := output.ParamToString(json["peerId"])
	remotePeerId := output.ParamToString(json["remotePeerId"])
	// 从leveldb取出peer信息
	p, err := models.ViewPeer(peerId)
	if err != nil {
		logger.Error("PeerDialStartHandler", "step", "ViewPeer", "err", err)
		output.ReturnErrorResponse(ctx, 9999, "系统错误~")
		return
	}
	// 从leveldb取出remote peer信息
	rp, err := models.ViewRemotePeer(peerId, remotePeerId)
	if err != nil {
		logger.Error("PeerDialStartHandler", "step", "ViewRemotePeer", "err", err)
		output.ReturnErrorResponse(ctx, 9999, "系统错误~")
		return
	}
	err = host.InstanceHost().PeerDialStart(p.PeerId, rp)
	if err != nil {
		logger.Error("PeerDialStartHandler", "step", "PeerDialStart", "err", err)
		output.ReturnErrorResponse(ctx, 9999, "系统错误~")
	} else {
		output.ReturnSuccessResponse(ctx, "success")
	}
}

func PeerDialStopHandler(ctx *gin.Context) {
	json := make(map[string]interface{})
	_ = ctx.BindJSON(&json)
	peerId := output.ParamToString(json["peerId"])
	remotePeerId := output.ParamToString(json["remotePeerId"])
	err := host.InstanceHost().PeerDialStop(peerId, remotePeerId)
	if err != nil {
		logger.Error("PeerDialStopHandler", "step", "PeerDialStop", "err", err)
		output.ReturnErrorResponse(ctx, 9999, "系统错误~")
	} else {
		output.ReturnSuccessResponse(ctx, "success")
	}
}

func SendPeerMessageHandler(ctx *gin.Context) {
	json := make(map[string]interface{})
	_ = ctx.BindJSON(&json)
	peerId := output.ParamToString(json["peerId"])
	remotePeerIds := output.ParamToString(json["remotePeerIds"])
	message := output.ParamToString(json["message"])
	remotePeerIdsArr := strings.Split(remotePeerIds, ",")
	host.InstanceHost().Peers[peerId].Publish(remotePeerIdsArr, []byte(message))

	output.ReturnSuccessResponse(ctx, "success")
}

func ListPeerMessageHandler(ctx *gin.Context) {
	pageSize := output.ParamToInt(ctx.Query("pageSize"))
	pageNum := output.ParamToInt(ctx.Query("pageNum"))
	peerId := output.ParamToString(ctx.Query("peerId"))
	count, list, err := host.InstanceHost().Peers[peerId].GetMessage(pageNum, pageSize)
	if err != nil {
		logger.Error("ListPeerMessageHandler", "step", "GetMessage", "err", err)
		output.ReturnErrorResponse(ctx, 9999, "系统错误~")
		return
	} else {
		res := make(map[string]interface{})
		res["records"] = list
		res["total"] = count
		output.ReturnSuccessResponse(ctx, res)
	}
}
