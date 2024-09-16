package tlv

import (
	"encoding/binary"
	"errors"
	"github.com/biwow/station/core/message"
	"github.com/biwow/station/tool"
	"sync"
)

// TLV 定义 TLV 结构体
type TLV struct {
	lc          sync.Mutex
	WriteBuffer []byte // write buffer
}

const (
	OPLen      = 2                       // Message operation symbol length
	TSLen      = 8                       // Message millisecond level timestamp length
	DataLen    = 4                       // Message data length
	HeadLen    = OPLen + TSLen + DataLen // Message head byte array length (OPLen + TSLen + DataLen)
	DataMaxLen = 1024 * 1024 * 10        // Message body max length(10M) 1024 * 1024 * 10
	BufLen     = HeadLen + DataMaxLen    // Buffer byte array length
)

var Buffer = make([]byte, BufLen)

func NewTLV() *TLV {
	return &TLV{
		lc:          sync.Mutex{},
		WriteBuffer: make([]byte, BufLen),
	}
}

func (t *TLV) PacketEncoding(m message.Message, key []byte) ([]byte, error) {
	t.lc.Lock()
	defer t.lc.Unlock()
	// 判断OP是否大于10，如果大于10需要加密
	var encryptByte []byte
	var err error
	// 判断OP是否大于1000，如果大于10000需要加密
	if m.OP > 1000 {
		encryptByte, err = tool.EncryptByte(m.Data, key)
		if err != nil {
			return nil, err
		}
		m.Data = encryptByte
	}

	dataLen := len(m.Data)

	if dataLen > DataMaxLen {
		return nil, errors.New("message data greater than 10M")
	}

	// 开始拼凑报文
	binary.BigEndian.PutUint16(Buffer[:OPLen], m.OP)
	binary.BigEndian.PutUint64(Buffer[OPLen:OPLen+TSLen], m.TS)
	binary.BigEndian.PutUint32(Buffer[OPLen+TSLen:OPLen+TSLen+DataLen], uint32(len(m.Data)))
	copy(Buffer[HeadLen:], m.Data[:dataLen])

	return Buffer[:HeadLen+dataLen], nil
}

// PacketDecoding 增加ip是为了验证消息去重
func (t *TLV) PacketDecoding(msg []byte, ip string, key []byte) (message.Message, error) {
	// 计算data长度是否合法
	dataLenBuf := msg[OPLen+TSLen : OPLen+TSLen+DataLen]
	dataLen := binary.BigEndian.Uint32(dataLenBuf)
	if len(msg) != (HeadLen + int(dataLen)) {
		return message.Message{}, errors.New("data length is wrong")
	}
	opLenBuf := msg[:OPLen]
	tsLenBuf := msg[OPLen : OPLen+TSLen]
	data := msg[HeadLen:]
	// 检测是否是重复消息
	msgHash := tool.Sha3256Hash(opLenBuf, tsLenBuf, data, []byte(ip))
	if NewQM().CheckIn(msgHash) == true {
		return message.Message{}, errors.New("information duplication～")
	}
	NewQM().Push(msgHash)
	ts := binary.BigEndian.Uint64(tsLenBuf)
	op := binary.BigEndian.Uint16(opLenBuf)
	// 判断OP是否大于1000，如果大于10000需要解密
	if op > 1000 {
		decryptByte, err := tool.DecryptByte(data, key)
		if err != nil {
			return message.Message{}, err
		}
		data = decryptByte
	}
	res := message.Message{
		OP:   op,
		TS:   ts,
		Data: data,
	}

	return res, nil
}
