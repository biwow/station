package pbcodec

import (
	"encoding/hex"
	"fmt"
	"github.com/gogo/protobuf/proto"
	pb "google.golang.org/protobuf/proto"
)

type PBCodec struct{}

// Encode encodes an object into slice of bytes.
func (c PBCodec) Encode(i interface{}) ([]byte, error) {
	if m, ok := i.(proto.Marshaler); ok {
		return m.Marshal()
	}

	if m, ok := i.(pb.Message); ok {
		return pb.Marshal(m)
	}

	return nil, fmt.Errorf("%T is not a proto.Marshaler or pb.Message", i)
}

// Decode decodes an object from slice of bytes.
func (c PBCodec) Decode(data []byte, i interface{}) error {
	if m, ok := i.(proto.Unmarshaler); ok {
		return m.Unmarshal(data)
	}

	if m, ok := i.(pb.Message); ok {
		return pb.Unmarshal(data, m)
	}

	return fmt.Errorf("%T is not a proto.Unmarshaler  or pb.Message", i)
}

func (c PBCodec) EncodeHex(i interface{}) (string, error) {
	b, err := c.Encode(i)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func (c PBCodec) DecodeHex(data string, i interface{}) error {
	b, err := hex.DecodeString(data)
	if err != nil {
		return err
	}
	return c.Decode(b, i)
}
