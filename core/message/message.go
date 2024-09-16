package message

import (
	"errors"
	"gitee.com/trustChain/pkg/codec"
	"time"
)

const (
	// HandShake 小于等于1000不需要加解密，大于10需要加解密
	HandShake       = uint16(666)  // 连接握手
	EventBusPublish = uint16(8888) // 发布消息
	TSPeriod        = 30000        //消息有效期30秒(30000毫秒)，包含系统之间时间误差容错
)

type Message struct {
	OP   uint16 // 操作符
	TS   uint64 // 毫秒级时间戳
	Data []byte // Message Data
}

// PackMessage 打包Message结构体
func PackMessage(code uint16, data []byte) (Message, error) {
	msg := Message{
		OP:   code,
		TS:   uint64(time.Now().UnixNano() / 1e6),
		Data: data,
	}
	return msg, nil
}

type Business struct {
	Type string
	Data []byte
}

type ContentHandShake struct {
	Ts   uint64
	Sign []byte
}

func CreateHandShakeMessage(ts uint64, sign []byte) ([]byte, error) {
	contentHandShake := ContentHandShake{Ts: ts, Sign: sign}
	encode, err := codec.NewCodec("rlp").Encode(contentHandShake)
	if err != nil {
		return nil, err
	}
	business := Business{
		Type: "handShake",
		Data: encode,
	}
	encode, err = codec.NewCodec("rlp").Encode(business)
	if err != nil {
		return nil, err
	}

	return encode, nil
}

func CreateCommonMessage(data []byte) ([]byte, error) {
	business := Business{
		Type: "common",
		Data: data,
	}
	encode, err := codec.NewCodec("rlp").Encode(business)
	if err != nil {
		return nil, err
	}

	return encode, nil
}

func RecoverMessage(data []byte) (interface{}, error) {
	var b Business
	var pp ContentHandShake
	err := codec.NewCodec("rlp").Decode(data, &b)
	if err != nil {
		return nil, err
	}
	switch b.Type {
	case "handShake":
		err := codec.NewCodec("rlp").Decode(b.Data, &pp)
		if err != nil {
			return nil, err
		}
		return pp, nil
	case "common":
		return b.Data, nil
	default:
		return nil, errors.New("type is wrong")
	}
}

func IsInOP(value uint16) bool {
	switch value {
	case HandShake, EventBusPublish:
		return true
	default:
		return false
	}
}

func ValidityPeriod(ts uint64) bool {
	return uint64(time.Now().UnixNano()/1e6)-ts < TSPeriod
}
