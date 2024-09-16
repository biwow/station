package tool

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"io"
)

func padBytesTo32(key []byte) []byte {
	if len(key) >= 32 {
		return key[:32]
	}
	padded := make([]byte, 32)
	copy(padded[32-len(key):], key)
	return padded
}

func EncryptByte(plain []byte, key []byte) ([]byte, error) {
	paddedKey := padBytesTo32(key)
	block, err := aes.NewCipher(paddedKey)
	if err != nil {
		return nil, err
	}
	// 对于CBC模式，需要使用PKCS#7填充plaintext到blocksize的整数倍
	plain = pad(plain, aes.BlockSize)
	ciphertext := make([]byte, aes.BlockSize+len(plain))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], plain)

	return ciphertext, nil
}

func DecryptByte(ciphertext []byte, key []byte) ([]byte, error) {
	paddedKey := padBytesTo32(key)
	block, err := aes.NewCipher(paddedKey)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < aes.BlockSize {
		return nil, err
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(ciphertext, ciphertext)
	// 删除PKCS#7填充
	plaintext := unpad(ciphertext)
	return plaintext, nil
}

func padKey(key string) []byte {
	for len(key) < 32 {
		key = "0" + key
	}
	if len(key) > 32 {
		key = key[:32]
	}
	return []byte(key)
}

func Encrypt(key string, plaintext string) (string, error) {
	paddedKey := padKey(key)
	block, err := aes.NewCipher(paddedKey)
	if err != nil {
		return "", err
	}
	plainBytes := []byte(plaintext)
	// 对于CBC模式，需要使用PKCS#7填充plaintext到blocksize的整数倍
	plainBytes = pad(plainBytes, aes.BlockSize)
	ciphertext := make([]byte, aes.BlockSize+len(plainBytes))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], plainBytes)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func Decrypt(key string, ct string) (string, error) {
	paddedKey := padKey(key)
	ciphertext, err := base64.StdEncoding.DecodeString(ct)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(paddedKey)
	if err != nil {
		return "", err
	}
	if len(ciphertext) < aes.BlockSize {
		return "", err
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(ciphertext, ciphertext)
	// 删除PKCS#7填充
	plaintext := unpad(ciphertext)
	return string(plaintext), nil
}

// pad 使用PKCS#7标准填充数据
func pad(buf []byte, blockSize int) []byte {
	padding := blockSize - (len(buf) % blockSize)
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(buf, padtext...)
}

// unpad 删除PKCS#7填充的字节
func unpad(buf []byte) []byte {
	length := len(buf)
	if length == 0 {
		return buf
	}
	unpadding := int(buf[length-1])
	return buf[:length-unpadding]
}
