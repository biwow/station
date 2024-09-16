package codec

import (
	"gitee.com/trustChain/pkg/codec/json"
	"gitee.com/trustChain/pkg/codec/msgpack"
	"gitee.com/trustChain/pkg/codec/protobuffer"
	"gitee.com/trustChain/pkg/codec/rlp"
	"gitee.com/trustChain/pkg/codec/serializenone"
	"gitee.com/trustChain/pkg/codec/thrift"
)

type Codec interface {
	Encode(i interface{}) ([]byte, error)
	Decode(data []byte, i interface{}) error
	EncodeHex(i interface{}) (string, error)
	DecodeHex(data string, i interface{}) error
}

func NewCodec(provider string) Codec {
	switch provider {
	case "json":
		return new(jsoncodec.JSONCodec)
	case "msgPack":
		return new(msgpackcodec.MsgpackCodec)
	case "pb":
		return new(pbcodec.PBCodec)
	case "rlp":
		return new(rlp.RLPCodec)
	case "byteCode":
		return new(bytecodec.ByteCodec)
	case "thrift":
		return new(thriftcodec.ThriftCodec)
	default:

		return nil
	}
}
