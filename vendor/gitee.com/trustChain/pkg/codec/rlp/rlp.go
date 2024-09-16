package rlp

import "encoding/hex"

type RLPCodec struct{}

func (c RLPCodec) Encode(i interface{}) ([]byte, error) {
	return EncodeToBytes(i)
}

func (c RLPCodec) Decode(data []byte, i interface{}) error {
	return DecodeBytes(data, i)
}

func (c RLPCodec) EncodeHex(i interface{}) (string, error) {
	b, err := c.Encode(i)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func (c RLPCodec) DecodeHex(data string, i interface{}) error {
	b, err := hex.DecodeString(data)
	if err != nil {
		return err
	}
	return c.Decode(b, i)
}
