package thriftcodec

import (
	"context"
	"encoding/hex"
	"errors"
	"github.com/apache/thrift/lib/go/thrift"
)

type ThriftCodec struct{}

func (c ThriftCodec) Encode(i interface{}) ([]byte, error) {
	b := thrift.NewTMemoryBufferLen(1024)
	p := thrift.NewTBinaryProtocolFactoryConf(&thrift.TConfiguration{}).
		GetProtocol(b)
	t := &thrift.TSerializer{
		Transport: b,
		Protocol:  p,
	}
	t.Transport.Close()
	if msg, ok := i.(thrift.TStruct); ok {
		return t.Write(context.Background(), msg)
	}
	return nil, errors.New("type assertion failed")
}

func (c ThriftCodec) Decode(data []byte, i interface{}) error {
	t := thrift.NewTMemoryBufferLen(1024)
	p := thrift.NewTBinaryProtocolFactoryConf(&thrift.TConfiguration{}).
		GetProtocol(t)
	d := &thrift.TDeserializer{
		Transport: t,
		Protocol:  p,
	}
	d.Transport.Close()
	return d.Read(context.Background(), i.(thrift.TStruct), data)
}

func (c ThriftCodec) EncodeHex(i interface{}) (string, error) {
	b, err := c.Encode(i)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func (c ThriftCodec) DecodeHex(data string, i interface{}) error {
	b, err := hex.DecodeString(data)
	if err != nil {
		return err
	}
	return c.Decode(b, i)
}
