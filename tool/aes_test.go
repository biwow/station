package tool

import (
	"log"
	"testing"
)

func TestName(t *testing.T) {
	key := "123456" // 16字节长度
	plaintext := "Hello, AES!"

	// 加密
	ciphertext, err := Encrypt(key, plaintext)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Encrypted:", ciphertext)

	// 解密
	decrypted, err := Decrypt(key, ciphertext)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Decrypted:", decrypted)
}
