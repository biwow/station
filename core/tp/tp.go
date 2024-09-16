package tp

import (
	"github.com/biwow/station/core/peer"
	"github.com/biwow/station/core/tp/tcp"
	"net"
)

// TP 传输协议
type TP interface {
	ListenPeer(peer peer.Peer)
	DialPeer(remotePeerAddr string)
	Stop() error
	TrustConns() map[string]*tcp.PeerConn
	TrustConn(remotePeerId string) *tcp.PeerConn
	Listener() net.Listener
}

func NewTP(tp string, p peer.Peer) TP {
	switch tp {
	case "tcp":
		return tcp.NewTCP(p)
	default:

		return nil
	}
}
