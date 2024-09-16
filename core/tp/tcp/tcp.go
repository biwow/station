package tcp

import (
	"gitee.com/trustChain/blockchain/tools/key/ethkey"
	"gitee.com/trustChain/pkg/logger"
	"github.com/biwow/station/core/message"
	"github.com/biwow/station/core/peer"
	"github.com/biwow/station/global"
	"github.com/biwow/station/tool"
	"net"
	"time"
)

const MaxConnLimit = 16 // 未握手最大连接数

type TPTcp struct {
	Peer       peer.Peer
	listener   net.Listener
	trustConns map[string]*PeerConn // 握手成功的连接
}

func NewTCP(p peer.Peer) *TPTcp {
	return &TPTcp{
		Peer:       p,
		listener:   nil,
		trustConns: make(map[string]*PeerConn),
	}
}

func (t *TPTcp) ListenPeer(peer peer.Peer) {
	listener, err := net.Listen("tcp", peer.GetAddr())
	if err != nil {
		logger.Error("TCP ListenPeer", "step", "Listen", "err", err)
	}
	defer listener.Close()
	logger.Info("TCP ListenPeer", "step", "Listen", "Listening Peer on", peer.GetAddr())
	t.listener = listener
	t.Peer = peer

	for {
		conn, err := listener.Accept()
		if err != nil {
			logger.Error("TCP ListenPeer", "step", "Accept", "err", err)
			// 出现错误退出该goroutine
			return
		}
		// 先去握手
		peerConn := NewPeerConn(conn, t.Peer.GetCP())
		go t.handlerConn(peerConn)
	}
}

func (t *TPTcp) DialPeer(remotePeerAddr string) {
	conn, err := net.Dial("tcp", remotePeerAddr)
	if err != nil {
		logger.Error("TCP DialPeer", "step", "Dial", "err", err)
	}
	// 先去握手
	peerConn := NewPeerConn(conn, t.Peer.GetCP())
	go t.handlerConn(peerConn)
}

func (t *TPTcp) Stop() error {
	err := t.Listener().Close()
	if err != nil {
		return err
	}
	// 关闭所有已有的连接
	for key, pc := range t.trustConns {
		err = pc.Conn.Close()
		if err != nil {
			logger.Error("TCP StopPeer", "step", "Close", "err", err)
		}
		// 取消消息总线订阅
		t.Peer.GetEventBus().Unsubscribe(key)
	}
	logger.Info("TCP StopPeer all connections have been closed")

	return nil
}

func (t *TPTcp) Listener() net.Listener {
	return t.listener
}

func (t *TPTcp) TrustConns() map[string]*PeerConn {
	return t.trustConns
}

func (t *TPTcp) TrustConn(remotePeerId string) *PeerConn {
	return t.trustConns[remotePeerId]
}

func (t *TPTcp) addTrustConns(remotePeerId string, pc *PeerConn) {
	pc.RemotePeerId = remotePeerId
	t.trustConns[remotePeerId] = pc
	// 增加消息总线订阅，增加监听呀
	t.Peer.GetEventBus().Subscribe(remotePeerId)
	go func() {
		for {
			// 从事件总线接收信息，通过conn发给remote peer
			msg := <-t.Peer.GetEventBus().CH[remotePeerId]
			err := t.SendMessage(remotePeerId, msg)
			if err != nil {
				logger.Error("addTrustConns", "step", "SendMessage", "err", err)
			}
		}
	}()
}

func (t *TPTcp) handlerConn(pc *PeerConn) {
	// 连接后先发握手信息，再监听对方消息
	t.SendHandShake(pc)
	t.ReceivePeerConnMessage(pc)
}

func (t *TPTcp) ReceivePeerConnMessage(pc *PeerConn) {
	// 	从通道读取消息并保存
	for {
		msg := <-pc.ReadChan
		if msg.OP == message.HandShake {
			// 验证签名获取公钥，计算交换密钥并保存，加入可信池，回复pong消息
			businessMessage, err := message.RecoverMessage(msg.Data)
			if err != nil {
				logger.Error("handShakePing", "step", "RecoverBusinessMessage", "err", err)
				pc.Conn.Close()
				return
			}
			handShake := businessMessage.(message.ContentHandShake)
			remotePeerPubKey, ok, err := ethkey.RecoverCompact(handShake.Sign, tool.Uint64ToBytes(handShake.Ts))
			if err != nil || !ok {
				logger.Error("handShakePing", "step", "RecoverCompact", "err", err)
				pc.Conn.Close()
				return
			}
			// 将远程节点连接加入可信池
			remotePeerId := remotePeerPubKey.ToAddress()
			// 密钥交换key存入pc
			secretKey := ethkey.GenerateSharedSecret(t.Peer.GetPeerPriKey(), remotePeerPubKey)
			pc.SecretKey = secretKey
			t.addTrustConns(remotePeerId, pc)
			logger.Info("ReceivePeerConnMessage handShake success", "local", pc.Conn.LocalAddr(), "remote", pc.Conn.RemoteAddr(), "remotePeerId", remotePeerId)
		} else if msg.OP == message.EventBusPublish {
			err := global.Cache.Set("read:"+t.Peer.GetPeerId()+":"+tool.GetCurrentMillisecondsAsString(), pc.RemotePeerId+":"+string(msg.Data), 0)
			if err != nil {
				logger.Error("ReceivePeerConnMessage", "step", "Cache.Set", "err", err)
			}
			logger.Info("ReceivePeerConnMessage", "step", "Cache.Set", "data", string(msg.Data))
		} else {
			return
		}
	}
}

func (t *TPTcp) SendHandShake(pc *PeerConn) {
	ts := time.Now().Unix()
	priKey := t.Peer.GetPeerPriKey()
	sign, err := priKey.SignCompact(tool.Int64ToBytes(ts), true)
	if err != nil {
		logger.Error("SendHandShake", "step", "SignCompact", "err", err)
	}
	handShakeMsg, err := message.CreateHandShakeMessage(uint64(ts), sign)

	err = pc.SendMessage(message.HandShake, handShakeMsg)
	if err != nil {
		logger.Error("SendHandShake", "step", "SendMessage", "err", err)
	}
}

func (t *TPTcp) SendMessage(remotePeerId string, msg []byte) error {
	commonMessage, err := message.CreateCommonMessage(msg)
	err = t.TrustConn(remotePeerId).SendMessage(message.EventBusPublish, commonMessage)
	if err != nil {
		return err
	}
	return nil
}
