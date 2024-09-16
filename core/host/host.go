package host

import (
	"github.com/biwow/station/core/peer/localpeer"
	"github.com/biwow/station/models"
)

type Host struct {
	HostID        string
	HostMasterKey string
	HostAddr      string
	Peers         map[string]*localpeer.LocalPeer
}

var instance *Host

func InstanceHost() *Host {
	if instance == nil {
		ps := make(map[string]*localpeer.LocalPeer)
		// 从存储中取host信息
		h, err := models.ViewHost()
		if err != nil {

		}
		instance = &Host{
			HostID:        h.HostID,
			HostMasterKey: h.HostMasterKey,
			HostAddr:      h.HostIP,
			Peers:         ps,
		}
	}
	return instance
}

func (h *Host) PeerListenStart(p models.Peer) error {
	pi := localpeer.NewLocalPeer(p)
	h.Peers[p.PeerId] = pi
	pi.Start()

	return nil
}

func (h *Host) PeerListenStop(peedId string) error {
	err := h.Peers[peedId].Stop()
	if err != nil {
		return err
	}
	delete(h.Peers, peedId)
	return nil
}

func (h *Host) PeerDialStart(peedId string, rp models.RemotePeer) error {
	h.Peers[peedId].DialRemotePeer(rp.RemotePeerAddr)

	return nil
}

func (h *Host) PeerDialStop(peedId string, remotePeerId string) error {
	err := h.Peers[peedId].TP.TrustConn(remotePeerId).Stop()
	if err != nil {
		return err
	}
	return nil
}
