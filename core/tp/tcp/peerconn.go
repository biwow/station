package tcp

import (
	"encoding/binary"
	"gitee.com/trustChain/pkg/logger"
	"github.com/biwow/station/core/cp"
	"github.com/biwow/station/core/cp/tlv"
	"github.com/biwow/station/core/message"
	"github.com/biwow/station/tool"
	"net"
)

type PeerConn struct {
	Conn         net.Conn
	RemotePeerId string
	SecretKey    []byte
	Reader       tool.ReadBuffer      // 读用缓冲机制，写使用conn直接发
	ReadChan     chan message.Message // 循环读取信息通道
	CP           cp.CP
}

func NewPeerConn(conn net.Conn, communicationProtocol string) *PeerConn {
	peerConn := &PeerConn{
		Conn:      conn,
		SecretKey: nil,
		Reader:    tool.NewBuffer(conn, tlv.BufLen),
		ReadChan:  make(chan message.Message),
		CP:        cp.NewCP(communicationProtocol),
	}
	go peerConn.readMessage()

	return peerConn
}

func (p *PeerConn) Pack(msg message.Message) ([]byte, error) {
	return p.CP.PacketEncoding(msg, p.SecretKey)
}

// BufferToMessage 为conn读取的数据解包
func (p *PeerConn) bufferToMessage() ([]byte, bool) {
	opBuf, err := p.Reader.Seek(0, tlv.OPLen) // read message type length
	if err != nil {
		return nil, false
	}
	op := binary.BigEndian.Uint16(opBuf)
	// 验证op是否合法
	if !message.IsInOP(op) {
		return nil, false
	}
	tsBuf, err := p.Reader.Seek(tlv.OPLen, tlv.OPLen+tlv.TSLen) // read message type length
	if err != nil {
		return nil, false
	}
	ts := binary.BigEndian.Uint64(tsBuf)
	// 验证ts是否合法
	if !message.ValidityPeriod(ts) {
		return nil, false
	}
	dataLenBuf, err := p.Reader.Seek(tlv.OPLen+tlv.TSLen, tlv.OPLen+tlv.TSLen+tlv.DataLen) // read message type length
	if err != nil {
		return nil, false
	}
	dataLen := int(binary.BigEndian.Uint32(dataLenBuf))
	msg, err := p.Reader.Read(0, tlv.HeadLen+dataLen)
	if err != nil {
		return nil, false
	}
	return msg, true
}

func (p *PeerConn) SendMessage(op uint16, msg []byte) error {
	packMessage, err := message.PackMessage(op, msg)
	if err != nil {
		return err
	}
	packetEncoding, err := p.CP.PacketEncoding(packMessage, p.SecretKey)
	if err != nil {
		return err
	}
	_, err = p.Conn.Write(packetEncoding)
	if err != nil {
		return err
	}
	logger.Info("SendMessage", "step", "Write", "local", p.Conn.LocalAddr(), "remote", p.Conn.RemoteAddr(), "message", string(msg))

	return nil
}

// ReadMessage 监听该连接接收的数据并放入通道
func (p *PeerConn) readMessage() {
	// 	监听数据并解包放入通道
	go func() {
		for {
			_, err := p.Reader.ReadFromReader()
			if err != nil {
				logger.Error("ReadMessage", "step", "ReadFromReader", "err", err)
				p.Conn.Close()
				return
			}
			for {
				msgBytes, ok := p.bufferToMessage()
				if ok {
					packetDecoding, err := p.CP.PacketDecoding(msgBytes, p.Conn.RemoteAddr().String(), p.SecretKey)
					if err != nil {
						logger.Error("readMessage", "step", "PacketDecoding", "err", err)
					} else {
						p.ReadChan <- packetDecoding
					}
				}
				break
			}
		}
	}()
}

func (p *PeerConn) Stop() error {
	err := p.Conn.Close()
	if err != nil {
		return err
	}
	close(p.ReadChan)

	return nil
}
