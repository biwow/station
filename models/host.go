package models

import (
	"gitee.com/trustChain/pkg/codec"
	"github.com/biwow/station/global"
)

type Host struct {
	HostName      string
	HostID        string
	HostMasterKey string
	HostIP        string
}

func CreateAndUpdateHost(hostname, id, masterKey, ip string) error {
	h := Host{
		HostName:      hostname,
		HostID:        id,
		HostMasterKey: masterKey,
		HostIP:        ip,
	}
	hex, err := codec.NewCodec("json").EncodeHex(h)
	if err != nil {
		return err
	}
	err = global.Cache.Set("host", hex, 0)
	if err != nil {
		return err
	}

	return nil
}

func ViewHost() (Host, error) {
	var res Host
	hex, err := global.Cache.Get("host")
	if err != nil {
		return Host{}, err
	}
	err = codec.NewCodec("json").DecodeHex(hex, &res)
	if err != nil {
		return Host{}, err
	}

	return res, nil
}
