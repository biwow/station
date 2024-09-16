package invoke

import (
	"gitee.com/trustChain/blockchain/tools/key/ethkey"
	"gitee.com/trustChain/pkg/cache"
	"gitee.com/trustChain/pkg/cache/typecache"
	"gitee.com/trustChain/pkg/logger"
	"github.com/biwow/station/core/host"
	"github.com/biwow/station/global"
	"github.com/biwow/station/models"
	"github.com/biwow/station/tool"
	"strings"
)

func init() {
	global.Cache = LevelDBInstance()
}

func CreatePeer(peerName, ip, port, tp, cp string) string {
	logger.Info("CreatePeer", "peerName", peerName, "ip", ip, "port", port, "tp", tp, "cp", cp)
	// 验证peer name 是否都是字母
	ok := tool.IsAllAlphabet(peerName)
	if !ok {
		logger.Error("CreatePeer", "step", "IsAllAlphabet", "err", "peer必须全是英文字母~")
		return "peer必须全是英文字母~"
	}
	// 验证ip规则是否合法
	ok = tool.ValidateIPAddress(ip)
	if !ok {
		logger.Error("CreatePeer", "step", "ValidateIPAddress", "err", "ip地址格式不合法~")
		return "ip地址格式不合法~"
	}
	// 验证port规则是否合法
	ok = tool.ValidatePort(port)
	if !ok {
		logger.Error("CreatePeer", "step", "ValidatePort", "err", "port格式不合法~")
		return "port格式不合法~"
	}
	// 验证cp是否合法
	ok = tool.ValidateCP(cp)
	if !ok {
		logger.Error("CreatePeer", "step", "ValidateCP", "err", "通信协议格式不合法~")
		return "通信协议格式不合法~"
	}
	// 验证tp是否合法
	ok = tool.ValidateTP(tp)
	if !ok {
		logger.Error("CreatePeer", "step", "ValidateTP", "err", "传输协议格式不合法~")
		return "传输协议格式不合法~"
	}
	// 随机生成私钥
	key := ethkey.GenerateKey()
	// 保存
	err := models.CreateAndUpdatePeer(peerName, key.PublicKey.ToAddress(),
		key.PublicKey.ToHex(), key.ToHex(), ip+":"+port, cp, tp)
	if err != nil {
		return err.Error()
	}
	return ""
}
func ListPeer() []models.Peer {
	var arr []models.Peer
	ps, err := models.ListPeer()
	if err != nil {
		logger.Error("ListPeerHandler", "step", "ListPeer", "err", err)
		return arr
	}
	// map转数组
	for _, item := range ps {
		arr = append(arr, item)
	}
	return arr
}
func ViewPeer(peerId string) models.Peer {
	logger.Info("ViewPeer", "peerId", peerId)

	var p models.Peer
	p, err := models.ViewPeer(peerId)
	if err != nil {
		logger.Error("ViewPeerHandler", "step", "ViewPeer", "err", err)
		return p
	}
	return p
}
func CreateRemotePeer(peerId, remotePeerName, remotePeerId, remotePeerPubKey, ip, port, tp, cp string) string {
	logger.Info("CreateRemotePeer", "peerId", peerId, "remotePeerName", remotePeerName, "remotePeerId", remotePeerId,
		"remotePeerPubKey", remotePeerPubKey, "ip", ip, "port", port, "tp", tp, "cp", cp)
	// 验证remote peer name是否都是字母
	ok := tool.IsAllAlphabet(remotePeerName)
	if !ok {
		logger.Error("CreateRemotePeer", "step", "IsAllAlphabet", "err", "remotePeerName必须全是英文字母~")
		return "remotePeerName必须全是英文字母~"
	}
	// 验证peer id 是否合法
	ok = tool.ValidateEthereumAddress(peerId)
	if !ok {
		logger.Error("CreateRemotePeer", "step", "ValidateEthereumAddress", "err", "peer id格式不合法~")
		return "peer id格式不合法~"
	}
	// 验证remote peer id 是否合法
	ok = tool.ValidateEthereumAddress(remotePeerId)
	if !ok {
		logger.Error("CreateRemotePeer", "step", "ValidateEthereumAddress", "err", "remote peer id格式不合法~")
		return "remote peer id格式不合法~"
	}
	// 验证remote peer PubKey是否合法
	ok = tool.ValidateEthereumCompressedPublicKey(remotePeerPubKey)
	if !ok {
		logger.Error("CreateRemotePeer", "step", "ValidateEthereumCompressedPublicKey", "err", "remote peer pubKey格式不合法~")
		return "remote peer pubKey格式不合法~"
	}
	// 验证ip规则是否合法
	ok = tool.ValidateIPAddress(ip)
	if !ok {
		logger.Error("CreateRemotePeer", "step", "ValidateIPAddress", "err", "ip地址格式不合法~")
		return "ip地址格式不合法~"
	}
	// 验证port规则是否合法
	ok = tool.ValidatePort(port)
	if !ok {
		logger.Error("CreateRemotePeer", "step", "ValidatePort", "err", "port格式不合法~")
		return "port格式不合法~"
	}
	// 验证cp是否合法
	ok = tool.ValidateCP(cp)
	if !ok {
		logger.Error("CreateRemotePeer", "step", "ValidateCP", "err", "通信协议格式不合法~")
		return "通信协议格式不合法~"
	}
	// 验证tp是否合法
	ok = tool.ValidateTP(tp)
	if !ok {
		logger.Error("CreateRemotePeer", "step", "ValidateTP", "err", "传输协议格式不合法~")
		return "传输协议格式不合法~"
	}
	// 保存
	err := models.CreateAndUpdateRemotePeer(peerId, remotePeerName, remotePeerId,
		remotePeerPubKey, ip+":"+port, cp, tp)
	if err != nil {
		logger.Error("CreateRemotePeerHandler", "step", "CreateAndUpdateRemotePeer", "err", err)
		return "系统错误~"
	} else {
		return ""
	}
}
func ListRemotePeer(peerId string) []models.RemotePeer {
	var arr []models.RemotePeer
	rps, err := models.ListRemotePeer(peerId)
	if err != nil {
		logger.Error("ListRemotePeerHandler", "step", "ListRemotePeer", "err", err)
		return arr
	}
	// map转数组
	for _, item := range rps {
		arr = append(arr, item)
	}

	return arr
}
func PeerListenStart(peerId string) string {
	logger.Info("PeerListenStart", "peerId", peerId)
	// 从leveldb取出peer信息
	p, err := models.ViewPeer(peerId)
	if err != nil {
		logger.Error("PeerListenStartHandler", "step", "ViewPeer", "err", err)
		return "系统错误~"
	}
	err = host.InstanceHost().PeerListenStart(p)
	if err != nil {
		logger.Error("PeerListenStartHandler", "step", "PeerListenStart", "err", err)
		return "系统错误~"
	} else {
		return ""
	}
}
func PeerListenStop(peerId string) string {
	logger.Info("PeerListenStop", "peerId", peerId)
	err := host.InstanceHost().PeerListenStop(peerId)
	if err != nil {
		logger.Error("PeerListenStopHandler", "step", "PeerListenStop", "err", err)
		return "系统错误~"
	} else {
		return ""
	}
}
func PeerDialStart(peerId, remotePeerId string) string {
	logger.Info("PeerDialStart", "peerId", peerId, "remotePeerId", remotePeerId)
	// 从leveldb取出peer信息
	p, err := models.ViewPeer(peerId)
	if err != nil {
		logger.Error("PeerDialStartHandler", "step", "ViewPeer", "err", err)
		return "系统错误~"
	}
	// 从leveldb取出remote peer信息
	rp, err := models.ViewRemotePeer(peerId, remotePeerId)
	if err != nil {
		logger.Error("PeerDialStartHandler", "step", "ViewRemotePeer", "err", err)
		return "系统错误~"
	}
	// tmp start
	logger.Info("peer", p.PeerId, p.PeerPubKey, p.PeerName)
	logger.Info("remotePeer", rp.PeerId, rp.RemotePeerName)
	// tmp stop
	err = host.InstanceHost().PeerDialStart(p.PeerId, rp)
	if err != nil {
		logger.Error("PeerDialStartHandler", "step", "PeerDialStart", "err", err)
		return "系统错误~"
	} else {
		return ""
	}
}
func PeerDialStop(peerId, remotePeerId string) string {
	logger.Info("PeerDialStop", "peerId", peerId, "remotePeerId", remotePeerId)
	err := host.InstanceHost().PeerDialStop(peerId, remotePeerId)
	if err != nil {
		logger.Error("PeerDialStopHandler", "step", "PeerDialStop", "err", err)
		return "系统错误~"
	} else {
		return ""
	}
}
func SendPeerMessage(peerId, remotePeerIds, message string) string {
	remotePeerIdsArr := strings.Split(remotePeerIds, ",")
	host.InstanceHost().Peers[peerId].Publish(remotePeerIdsArr, []byte(message))

	return ""
}
func ListPeerMessage(peerId string, pageNum, pageSize int) map[string]interface{} {
	count, list, err := host.InstanceHost().Peers[peerId].GetMessage(pageNum, pageSize)
	if err != nil {
		logger.Error("ListPeerMessageHandler", "step", "GetMessage", "err", err)
		return nil
	} else {
		res := make(map[string]interface{})
		res["records"] = list
		res["total"] = count
		return res
	}
}

func LevelDBInstance() cache.Cache {
	cfg := typecache.ConfigCache{
		DBPath: "./data",
	}
	cacheInstance, err := cache.NewCache("level", cfg)
	if err != nil {
		logger.Painc("LevelDBInstance:", "step", "NewCache", "err", err)
	}
	logger.Info("Instance", "Cache", "connection successful!")
	return cacheInstance
}
