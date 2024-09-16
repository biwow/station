package localpeer

import (
	"gitee.com/trustChain/blockchain/tools/key/ethkey"
	"gitee.com/trustChain/pkg/logger"
	"github.com/biwow/station/core/pubsub"
	"github.com/biwow/station/core/tp"
	"github.com/biwow/station/global"
	"github.com/biwow/station/models"
)

type LocalPeer struct {
	PeerName              string
	PeerId                string
	PeerPubKey            string
	PeerPriKey            string
	PeerAddr              string
	PeerEventBus          *pubsub.SubList
	CommunicationProtocol string
	TransportProtocol     string
	TP                    tp.TP
}

func NewLocalPeer(p models.Peer) *LocalPeer {
	peer := &LocalPeer{
		PeerName:              p.PeerName,
		PeerId:                p.PeerId,
		PeerPubKey:            p.PeerPubKey,
		PeerPriKey:            p.PeerPriKey,
		PeerAddr:              p.PeerAddr,
		PeerEventBus:          pubsub.NewSubList(),
		TransportProtocol:     p.TransportProtocol,
		CommunicationProtocol: p.CommunicationProtocol,
	}
	return peer
}

func (p *LocalPeer) Start() {
	t := tp.NewTP(p.TransportProtocol, p)
	p.TP = t
	// 	启动监听
	go func() {
		t.ListenPeer(p)
	}()
}
func (p *LocalPeer) Stop() error {
	err := p.TP.Stop()
	if err != nil {
		return err
	}

	return nil
}
func (p *LocalPeer) DialRemotePeer(remotePeerAddr string) {
	t := tp.NewTP(p.TransportProtocol, p)
	p.TP = t
	// 	启动拨号
	t.DialPeer(remotePeerAddr)
}
func (p *LocalPeer) StopRemotePeer(remotePeerId string) error {
	err := p.TP.TrustConn(remotePeerId).Conn.Close()
	if err != nil {
		return err
	}

	return nil
}
func (p *LocalPeer) GetAddr() string {
	return p.PeerAddr
}
func (p *LocalPeer) GetCP() string {
	return p.CommunicationProtocol
}
func (p *LocalPeer) GetPeerId() string {
	return p.PeerId
}
func (p *LocalPeer) GetPublicKey() string {
	return p.PeerPubKey
}
func (p *LocalPeer) GetPeerPriKey() *ethkey.PrivateKey {
	pri, err := ethkey.NewPrivateKey(p.PeerPriKey)
	if err != nil {
		logger.Error("LocalPeer GetPublicKey", "step", "NewPrivateKey", "err", err)
	}

	return pri
}
func (p *LocalPeer) GetEventBus() *pubsub.SubList {
	return p.PeerEventBus
}
func (p *LocalPeer) Publish(remotePeerIds []string, msg []byte) {
	p.PeerEventBus.PublishMessage(remotePeerIds, msg)
}
func (p *LocalPeer) GetMessage(pageNum, pageSize int) (int, []string, error) {
	return global.Cache.List("read:"+p.PeerId, pageNum, pageSize)
}
