package models

import (
	"gitee.com/trustChain/pkg/codec"
	"github.com/biwow/station/global"
)

type Peer struct {
	PeerName              string `json:"peerName"`
	PeerId                string `json:"peerId"`
	PeerPubKey            string `json:"peerPubKey"`
	PeerPriKey            string `json:"peerPriKey"`
	PeerAddr              string `json:"peerAddr"`
	CommunicationProtocol string `json:"cp"`
	TransportProtocol     string `json:"tp"`
}

type Peers map[string]Peer

func CreateAndUpdatePeer(peerName, peerId, peerPubKey, peerPriKey, peerAddr, cp, tp string) error {
	// 先保存节点信息
	p := Peer{
		PeerName:              peerName,
		PeerId:                peerId,
		PeerPubKey:            peerPubKey,
		PeerPriKey:            peerPriKey,
		PeerAddr:              peerAddr,
		CommunicationProtocol: cp,
		TransportProtocol:     tp,
	}
	hex, err := codec.NewCodec("json").EncodeHex(p)
	if err != nil {
		return err
	}
	err = global.Cache.Set("peer:"+peerId, hex, 0)
	if err != nil {
		return err
	}
	// 取出来再保存节点列表信息
	var peers map[string]Peer
	peersHex, err := global.Cache.Get("peers")
	if err != nil && err.Error() != "leveldb: not found" {
		return err
	}
	if len(peersHex) == 0 {
		peers = make(map[string]Peer)
	} else {
		err = codec.NewCodec("json").DecodeHex(peersHex, &peers)
		if err != nil {
			return err
		}
	}
	peers[peerId] = p
	hex, err = codec.NewCodec("json").EncodeHex(peers)
	if err != nil {
		return err
	}
	err = global.Cache.Set("peers", hex, 0)
	if err != nil {
		return err
	}

	return nil
}

func DeletePeer(peerId string) error {
	// 先删peer
	err := global.Cache.Del("peer:" + peerId)
	if err != nil {
		return err
	}
	// 再删peers
	var peers map[string]Peer
	peersHex, err := global.Cache.Get("peers")
	if err != nil {
		return err
	}
	if len(peersHex) == 0 {
		peers = make(map[string]Peer)
	} else {
		err := codec.NewCodec("json").DecodeHex(peersHex, &peers)
		if err != nil {
			return err
		}
	}
	// 删除键值对
	delete(peers, peerId)
	hex, err := codec.NewCodec("json").EncodeHex(peers)
	if err != nil {
		return err
	}
	err = global.Cache.Set("peers", hex, 0)
	if err != nil {
		return err
	}

	return nil
}

func ListPeer() (map[string]Peer, error) {
	var peers map[string]Peer
	peersHex, err := global.Cache.Get("peers")
	if err != nil {
		return nil, err
	}
	if len(peersHex) == 0 {
		peers = make(map[string]Peer)
	} else {
		err := codec.NewCodec("json").DecodeHex(peersHex, &peers)
		if err != nil {
			return nil, err
		}
	}

	return peers, nil
}

func ViewPeer(peerId string) (Peer, error) {
	var res Peer
	hex, err := global.Cache.Get("peer:" + peerId)
	if err != nil {
		return Peer{}, err
	}
	err = codec.NewCodec("json").DecodeHex(hex, &res)
	if err != nil {
		return Peer{}, err
	}

	return res, nil
}
