package main

import (
	"crypto/sha256"
	"fmt"
	"golang.org/x/crypto/ripemd160"
	"math/big"
)

// base58Encode 对字节数组进行 Base58 编码
func base58Encode(input []byte) string {
	alphabet := "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	var result string
	value := big.NewInt(0).SetBytes(input)
	base := big.NewInt(58)
	zero := big.NewInt(0)

	for value.Cmp(zero) > 0 {
		mod := big.NewInt(0)
		value.DivMod(value, base, mod)
		result = string(alphabet[mod.Int64()]) + result
	}

	for _, b := range input {
		if b == 0x00 {
			result = "1" + result
		} else {
			break
		}
	}

	return result
}

// generateBitcoinAddress 生成比特币地址
func generateBitcoinAddress() string {
	// 生成随机的私钥（这里只是简单模拟）
	privateKey := []byte("random_private_key")
	// 计算公钥
	hash1 := sha256.Sum256(privateKey)
	// 进行 RIPEMD-160 哈希
	hasher := ripemd160.New()
	hasher.Write(hash1[:])
	hash2 := hasher.Sum(nil)

	// 添加版本号
	versionedHash := append([]byte{0x00}, hash2...)

	// 计算校验和
	checksum := sha256.Sum256(versionedHash)
	checksum = sha256.Sum256(checksum[:])
	checksumPart := checksum[:4]

	// 组合生成地址
	addressBytes := append(versionedHash, checksumPart...)

	return base58Encode(addressBytes)
}

func main() {
	address := generateBitcoinAddress()
	fmt.Println("Bitcoin Address:", address)
}
