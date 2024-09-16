package cp

import (
	"github.com/biwow/station/core/cp/tlv"
	"github.com/biwow/station/core/message"
)

// CP 通信协议的封包和拆包
type CP interface {
	PacketEncoding(m message.Message, key []byte) ([]byte, error)
	PacketDecoding(data []byte, ip string, key []byte) (message.Message, error)
}

func NewCP(provider string) CP {
	switch provider {
	case "tlv":
		return tlv.NewTLV()
	default:

		return nil
	}
}
