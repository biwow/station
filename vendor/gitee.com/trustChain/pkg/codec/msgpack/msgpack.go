package msgpackcodec

import (
	"bytes"
	"encoding/hex"
	"github.com/tinylib/msgp/msgp"
	"github.com/vmihailenco/msgpack/v5"
)

type MsgpackCodec struct{}

// Encode encodes an object into slice of bytes.
func (c MsgpackCodec) Encode(i interface{}) ([]byte, error) {
	if m, ok := i.(msgp.Marshaler); ok {
		return m.MarshalMsg(nil)
	}
	var buf bytes.Buffer
	enc := msgpack.NewEncoder(&buf)
	// enc.UseJSONTag(true)
	err := enc.Encode(i)
	return buf.Bytes(), err
}

// Decode decodes an object from slice of bytes.
func (c MsgpackCodec) Decode(data []byte, i interface{}) error {
	if m, ok := i.(msgp.Unmarshaler); ok {
		_, err := m.UnmarshalMsg(data)
		return err
	}
	dec := msgpack.NewDecoder(bytes.NewReader(data))
	// dec.UseJSONTag(true)
	err := dec.Decode(i)
	return err
}

func (c MsgpackCodec) EncodeHex(i interface{}) (string, error) {
	b, err := c.Encode(i)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func (c MsgpackCodec) DecodeHex(data string, i interface{}) error {
	b, err := hex.DecodeString(data)
	if err != nil {
		return err
	}
	return c.Decode(b, i)
}
