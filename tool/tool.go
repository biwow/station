package tool

import (
	"encoding/hex"
	"net"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

type CPV string
type TPV string

const (
	TLV       CPV = "TLV"
	TCP       TPV = "TCP"
	UDP       TPV = "UDP"
	WEBSOCKET TPV = "WEBSOCKET"
)

func ValidateCP(cp string) bool {
	cp = strings.ToUpper(cp)
	switch CPV(cp) {
	case TLV:
		return true
	default:
		return false
	}
}

func ValidateTP(tp string) bool {
	tp = strings.ToUpper(tp)
	switch TPV(tp) {
	case TCP, UDP, WEBSOCKET:
		return true
	default:
		return false
	}
}

// IsAllAlphabet 用于验证字符串是否全部由字母组成
func IsAllAlphabet(s string) bool {
	for _, r := range s {
		if !unicode.IsLetter(r) {
			return false
		}
	}
	return true
}

// ValidateIPAddress 验证字符串是否为有效的 IPv4 地址
func ValidateIPAddress(ip string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}
	return parsedIP.To4() != nil
}

// ValidatePort 验证端口号是否合法
func ValidatePort(port string) bool {
	portNum, err := strconv.Atoi(port)
	if err != nil {
		return false
	}
	if portNum < 80 || portNum > 60000 {
		return false
	}
	return true
}

// ValidateEthereumAddress 验证字符串是否是以太坊的地址
func ValidateEthereumAddress(address string) bool {
	// 以太坊地址的正则表达式模式
	pattern := `^0x[a-fA-F0-9]{40}$`
	match, _ := regexp.MatchString(pattern, address)
	return match
}

// ValidateEthereumCompressedPublicKey 验证字符串是否为以太坊的压缩公钥
func ValidateEthereumCompressedPublicKey(key string) bool {
	// 检查长度是否为 33 字节（包括开头的 02 或 03）
	if len(key) != 66 {
		return false
	}

	// 检查是否以 02 或 03 开头
	if key[0] != '0' || (key[1] != '2' && key[1] != '3') {
		return false
	}

	// 检查剩余部分是否为有效的十六进制字符串
	_, err := hex.DecodeString(key[2:])
	if err != nil {
		return false
	}

	return true
}
