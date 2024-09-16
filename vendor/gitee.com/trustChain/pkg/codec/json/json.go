package jsoncodec

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
)

type JSONCodec struct{}

// Encode encodes an object into slice of bytes.
func (c JSONCodec) Encode(i interface{}) ([]byte, error) {
	return json.Marshal(i)
}

func (c JSONCodec) EncodeHex(i interface{}) (string, error) {
	b, err := c.Encode(i)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// Decode decodes an object from slice of bytes.
func (c JSONCodec) Decode(data []byte, i interface{}) error {
	d := json.NewDecoder(bytes.NewBuffer(data))
	d.UseNumber()
	return d.Decode(i)
}

func (c JSONCodec) DecodeHex(data string, i interface{}) error {
	b, err := hex.DecodeString(data)
	if err != nil {
		return err
	}
	return c.Decode(b, i)
}
