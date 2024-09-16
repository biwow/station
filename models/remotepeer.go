package models

import (
	"gitee.com/trustChain/pkg/codec"
	"github.com/biwow/station/global"
)

type RemotePeer struct {
	PeerId                string `json:"peerId"`
	RemotePeerName        string `json:"remotePeerName"`
	RemotePeerId          string `json:"remotePeerId"`
	RemotePeerPubKey      string `json:"remotePeerPubKey"`
	RemotePeerAddr        string `json:"remotePeerAddr"`
	RemotePeerSpeed       int    `json:"remotePeerSpeed"`
	CommunicationProtocol string `json:"cp"`
	TransportProtocol     string `json:"tp"`
}

type RemotePeers map[string]RemotePeer

func CreateAndUpdateRemotePeer(peerId, remotePeerName, remotePeerId, remotePeerPubKey, remotePeerAddr, cp, tp string) error {
	// 先保存节点信息
	p := RemotePeer{
		PeerId:                peerId,
		RemotePeerName:        remotePeerName,
		RemotePeerId:          remotePeerId,
		RemotePeerPubKey:      remotePeerPubKey,
		RemotePeerAddr:        remotePeerAddr,
		RemotePeerSpeed:       0,
		CommunicationProtocol: cp,
		TransportProtocol:     tp,
	}
	hex, err := codec.NewCodec("json").EncodeHex(p)
	if err != nil {
		return err
	}
	err = global.Cache.Set("remotePeer:"+peerId+":"+remotePeerId, hex, 0)
	if err != nil {
		return err
	}
	// 取出来再保存节点列表信息
	var remotePeers map[string]RemotePeer
	remotePeersHex, err := global.Cache.Get("remotePeers:" + peerId)
	if err != nil && err.Error() != "leveldb: not found" {
		return err
	}
	if len(remotePeersHex) == 0 {
		remotePeers = make(map[string]RemotePeer)
	} else {
		err = codec.NewCodec("json").DecodeHex(remotePeersHex, &remotePeers)
		if err != nil {
			return err
		}
	}
	remotePeers[remotePeerId] = p
	hex, err = codec.NewCodec("json").EncodeHex(remotePeers)
	if err != nil {
		return err
	}
	err = global.Cache.Set("remotePeers:"+peerId, hex, 0)
	if err != nil {
		return err
	}

	return nil
}

func DeleteRemotePeer(peerId, remotePeerId string) error {
	// 先删peer
	err := global.Cache.Del("remotePeer:" + peerId + ":" + remotePeerId)
	if err != nil {
		return err
	}
	// 再删peers
	var remotePeers map[string]RemotePeer
	remotePeersHex, err := global.Cache.Get("remotePeers:" + peerId)
	if err != nil {
		return err
	}
	if len(remotePeersHex) == 0 {
		remotePeers = make(map[string]RemotePeer)
	} else {
		err := codec.NewCodec("json").DecodeHex(remotePeersHex, &remotePeers)
		if err != nil {
			return err
		}
	}
	// 删除键值对
	delete(remotePeers, remotePeerId)
	hex, err := codec.NewCodec("json").EncodeHex(remotePeers)
	if err != nil {
		return err
	}
	err = global.Cache.Set("remotePeers:"+peerId, hex, 0)
	if err != nil {
		return err
	}

	return nil
}

func ListRemotePeer(peerId string) (map[string]RemotePeer, error) {
	var remotePeers map[string]RemotePeer
	remotePeersHex, err := global.Cache.Get("remotePeers:" + peerId)
	if err != nil {
		return nil, err
	}
	if len(remotePeersHex) == 0 {
		remotePeers = make(map[string]RemotePeer)
	} else {
		err := codec.NewCodec("json").DecodeHex(remotePeersHex, &remotePeers)
		if err != nil {
			return nil, err
		}
	}

	return remotePeers, nil
}

func ViewRemotePeer(peerId, remotePeerId string) (RemotePeer, error) {
	var res RemotePeer
	hex, err := global.Cache.Get("remotePeer:" + peerId + ":" + remotePeerId)
	if err != nil {
		return RemotePeer{}, err
	}
	err = codec.NewCodec("json").DecodeHex(hex, &res)
	if err != nil {
		return RemotePeer{}, err
	}

	return res, nil
}
