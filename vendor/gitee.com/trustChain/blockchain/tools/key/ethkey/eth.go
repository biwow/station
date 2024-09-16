package ethkey

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"gitee.com/trustChain/blockchain/btc/base58"
	"gitee.com/trustChain/blockchain/tools/eccs256"
	"golang.org/x/crypto/sha3"
	"hash"
	"io"
	"math/big"
	"strings"
)

type PublicKey struct {
	elliptic.Curve
	X, Y *big.Int
}

type PrivateKey struct {
	PublicKey
	D *big.Int
}

type Signature struct {
	R, S *big.Int
}

// GenerateKey 随机生成公私钥对
func GenerateKey() *PrivateKey {
	key, _ := ecdsa.GenerateKey(curve, rand.Reader)
	private := &PrivateKey{
		PublicKey: PublicKey{
			Curve: key.Curve,
			X:     key.X,
			Y:     key.Y,
		},
		D: key.D,
	}

	return private
}

const (
	PubKeyBytesLenCompressed        = 33
	PubKeyBytesLenUncompressed      = 65
	PubKeyBytesLenHybrid            = 65
	pubkeyCompressed           byte = 0x2 // y_bit + x coord
	pubkeyUncompressed         byte = 0x4 // x coord + y coord
	pubkeyHybrid               byte = 0x6 // y_bit + x coord + y coord
	compressMagic              byte = 0x01
	// 一个big.Word的位数
	wordBits = 32 << (uint64(^big.Word(0)) >> 63)
	// 一个big.Word的字节数
	wordBytes = wordBits / 8
)

var (
	curve = eccs256.S256()
	// Curve order and halforder, used to tame ECDSA malleability (see BIP-0062)
	order     = new(big.Int).Set(curve.N)
	halforder = new(big.Int).Rsh(order, 1)

	// Used in RFC6979 implementation when testing the nonce for correctness
	one = big.NewInt(1)

	// oneInitializer is used to fill a byte slice with byte 0x01.  It is provided
	// here to avoid the need to create it multiple times.
	oneInitializer = []byte{0x01}

	// 解密过程中，当消息验证检查(MAC)失败时，发生ErrInvalidMAC。这是因为无效的私钥或损坏的密文。
	errInvalidMAC = errors.New("invalid mac hash")
	// 发生在解密函数的输入密文长度小于134字节的情况下。
	errInputTooShort = errors.New("ciphertext too short")
	// 发生在加密文本的前两个字节不是0x02CA (= 712 = secp256k1，来自OpenSSL)的时候。
	errUnsupportedCurve = errors.New("unsupported curve")
	errInvalidXLength   = errors.New("invalid X length, must be 32")
	errInvalidYLength   = errors.New("invalid Y length, must be 32")
	errInvalidPadding   = errors.New("invalid PKCS#7 padding")

	secp256k1N, _ = new(big.Int).SetString("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)

	ciphCurveBytes  = [2]byte{0x02, 0xCA}
	ciphCoordLength = [2]byte{0x00, 0x20}
)

// GenerateSharedSecret 基于私钥和公钥生成共享密钥。
func GenerateSharedSecret(privateKey *PrivateKey, pubkey *PublicKey) []byte {
	x, _ := pubkey.Curve.ScalarMult(pubkey.X, pubkey.Y, privateKey.D.Bytes())
	return x.Bytes()
}

func NewPrivateKey(priHex string) (*PrivateKey, error) {
	b, err := hex.DecodeString(priHex)
	if err != nil {
		return nil, err
	}
	c := curve
	privateKey := new(PrivateKey)
	privateKey.PublicKey.Curve = c
	privateKey.D = new(big.Int).SetBytes(b)
	privateKey.PublicKey.X, privateKey.PublicKey.Y = c.ScalarBaseMult(b)
	return privateKey, nil
}

// Public 私钥转公钥
func (private *PrivateKey) Public() crypto.PublicKey {
	return &private.PublicKey
}

// ToHex 私钥转哈希
func (p *PrivateKey) ToHex() string {
	return hex.EncodeToString(p.D.Bytes())
}

// ToByte 私钥转byte
func (p *PrivateKey) ToByte() []byte {
	bigint := p.D
	n := p.Params().BitSize / 8

	if bigint.BitLen()/8 >= n {
		return bigint.Bytes()
	}
	ret := make([]byte, n)
	ReadBits(bigint, ret)
	return ret
}

// ToECDSA 私钥转哈希
func (p *PrivateKey) ToECDSA() (*ecdsa.PrivateKey, error) {
	priv := new(ecdsa.PrivateKey)
	priv.D = p.D

	// The priv.D must < N
	if priv.D.Cmp(secp256k1N) >= 0 {
		return nil, errors.New("invalid private key, >=N")
	}
	// The priv.D must not be zero or negative.
	if priv.D.Sign() <= 0 {
		return nil, errors.New("invalid private key, zero or negative")
	}

	priv.PublicKey.X, priv.PublicKey.Y = p.Curve.ScalarBaseMult(p.ToByte())
	if priv.PublicKey.X == nil {
		return nil, errors.New("invalid private key")
	}
	return priv, nil
}

// Sign 签名
func (private *PrivateKey) Sign(hash []byte) (*Signature, error) {
	return signRFC6979(private, hash)
}

// SignCompact 使用指定的koblitz曲线上的指定私钥从而在散列中生成数据的压缩签名
func (private *PrivateKey) SignCompact(hash []byte, isCompressedKey bool) ([]byte, error) {
	sig, err := private.Sign(hash)
	if err != nil {
		return nil, err
	}

	// bitcoind检查R和S的位长。ecdsa签名算法返回R和S mod N，因此它们是曲线的位大小，因此大小正确。
	for i := 0; i < (curve.H+1)*2; i++ {
		pk, err := recoverKeyFromSignature(sig, hash, i, true)
		if err == nil && pk.X.Cmp(private.X) == 0 && pk.Y.Cmp(private.Y) == 0 {
			result := make([]byte, 1, 2*curve.BitSize+1)
			result[0] = 27 + byte(i)
			if isCompressedKey {
				result[0] += 4
			}

			curvelen := (curve.BitSize + 7) / 8

			bytelen := (sig.R.BitLen() + 7) / 8
			if bytelen < curvelen {
				result = append(result,
					make([]byte, curvelen-bytelen)...)
			}
			result = append(result, sig.R.Bytes()...)

			bytelen = (sig.S.BitLen() + 7) / 8
			if bytelen < curvelen {
				result = append(result,
					make([]byte, curvelen-bytelen)...)
			}
			result = append(result, sig.S.Bytes()...)

			return result, nil
		}
	}
	return nil, errors.New("no valid solution for pubkey found")
}

// RecoverCompact 验证“曲线”中Koblitz曲线的“签名”并推出公钥
func RecoverCompact(signature, hash []byte) (*PublicKey, bool, error) {
	bitlen := (curve.BitSize + 7) / 8
	if len(signature) != 1+bitlen*2 {
		return nil, false, errors.New("invalid compact signature size")
	}

	iteration := int((signature[0] - 27) & ^byte(4))

	// format is <header byte><bitlen R><bitlen S>
	sig := &Signature{
		R: new(big.Int).SetBytes(signature[1 : bitlen+1]),
		S: new(big.Int).SetBytes(signature[bitlen+1:]),
	}
	// The iteration used here was encoded
	key, err := recoverKeyFromSignature(sig, hash, iteration, false)
	if err != nil {
		return nil, false, err
	}

	return key, ((signature[0] - 27) & 4) == 4, nil
}

// Decrypt 私钥解密
func (p *PrivateKey) Decrypt(in []byte) ([]byte, error) {
	// IV + Curve params/X/Y + 1 block + HMAC-256
	if len(in) < aes.BlockSize+70+aes.BlockSize+sha256.Size {
		return nil, errInputTooShort
	}

	// read iv
	iv := in[:aes.BlockSize]
	offset := aes.BlockSize

	// start reading pubkey
	if !bytes.Equal(in[offset:offset+2], ciphCurveBytes[:]) {
		return nil, errUnsupportedCurve
	}
	offset += 2

	if !bytes.Equal(in[offset:offset+2], ciphCoordLength[:]) {
		return nil, errInvalidXLength
	}
	offset += 2

	xBytes := in[offset : offset+32]
	offset += 32

	if !bytes.Equal(in[offset:offset+2], ciphCoordLength[:]) {
		return nil, errInvalidYLength
	}
	offset += 2

	yBytes := in[offset : offset+32]
	offset += 32

	pb := make([]byte, PubKeyBytesLenUncompressed)
	pb[0] = byte(0x04) // uncompressed
	copy(pb[1:33], xBytes)
	copy(pb[33:], yBytes)
	// 检查(X, Y)是否位于曲线上，如果位于曲线上，则创建一个Pubkey
	pubkey, err := UnmarshalPubkey(pb)
	if err != nil {
		return nil, err
	}

	// 检查密码文本的长度
	if (len(in)-aes.BlockSize-offset-sha256.Size)%aes.BlockSize != 0 {
		return nil, errInvalidPadding // not padded to 16 bytes
	}

	// 生成共享密钥
	ecdhKey := GenerateSharedSecret(p, pubkey)
	derivedKey := sha512.Sum512(ecdhKey)
	keyE := derivedKey[:32]
	keyM := derivedKey[32:]

	// verify mac
	hm := hmac.New(sha256.New, keyM)
	hm.Write(in[:len(in)-sha256.Size]) // everything is hashed
	expectedMAC := hm.Sum(nil)
	messageMAC := in[len(in)-sha256.Size:]
	if !hmac.Equal(messageMAC, expectedMAC) {
		return nil, errInvalidMAC
	}

	// 开始解密
	block, err := aes.NewCipher(keyE)
	if err != nil {
		return nil, err
	}

	plaintext := make([]byte, len(in)-offset-sha256.Size)
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, in[offset:len(in)-sha256.Size])

	length := len(plaintext)
	padLength := int(plaintext[length-1])
	if padLength > aes.BlockSize || length < aes.BlockSize {
		return nil, errInvalidPadding
	}
	return plaintext[:length-padLength], nil
}

// WIFToPrvKey 哈希字符串转私钥
// 1 WIF：KxbF2HbMFTTfpiic6X8g5GSaKSLLqFYn5bfMquNrYwokySpqeBn8
// 2 base58解码：8028ea039252a3c0b5f3ec2d92f664011561ccf69f434512f20d0daa5fb2a349310118afa009
// 3 丢弃后四字节：8028ea039252a3c0b5f3ec2d92f664011561ccf69f434512f20d0daa5fb2a3493101
// 4 丢弃前后各一字节：28ea039252a3c0b5f3ec2d92f664011561ccf69f434512f20d0daa5fb2a34931
func WIFToPrvKey(wif string) (*PrivateKey, error) {
	decoded, err := base58.Decode(wif, base58.BitcoinAlphabet)
	if err != nil {
		return nil, err
	}
	decodedLen := len(decoded)
	var compress bool
	// Length of base58 decoded WIF must be 32 bytes + an optional 1 byte
	// (0x01) if compressed, plus 1 byte for netID + 4 bytes of checksum.
	switch decodedLen {
	case 1 + 32 + 1 + 4:
		if decoded[33] != 0x01 {
			return nil, errors.New("malformed private key")
		}
		compress = true
	case 1 + 32 + 4:
		compress = false
	default:
		return nil, errors.New("malformed private key")
	}
	// Checksum is first four bytes of double SHA256 of the identifier byte
	// and privKey.  Verify this matches the final 4 bytes of the decoded
	// private key.
	var tosum []byte
	if compress {
		tosum = decoded[:1+32+1]
	} else {
		tosum = decoded[:1+32]
	}
	cksum := DoubleHashB(tosum)[:4]
	if !bytes.Equal(cksum, decoded[decodedLen-4:]) {
		return nil, errors.New("checksum mismatch")
	}

	privKeyBytes := decoded[1 : 1+32]

	privKey, _ := NewPrivateKey(hex.EncodeToString(privKeyBytes))
	return privKey, nil
}

// PrvKeyToWIF creates the Wallet Import Format string encoding of a WIF structure.
// See DecodeWIF for a detailed breakdown of the format and requirements of
// a valid WIF string.
// 1 私钥：28ea039252a3c0b5f3ec2d92f664011561ccf69f434512f20d0daa5fb2a34931
// 2 前缀增加0x80，后缀增加01：8028ea039252a3c0b5f3ec2d92f664011561ccf69f434512f20d0daa5fb2a3493101
// 3 进行hash：f0722e985124f3d12e63abc8016f7c775471ff76c59143c52334b99bf0d13547
// 4 在进行hash：18afa0093fe60a479ee51ffe026900aaa4ae545a3c6d3bea0192b82e3a59bc06
// 5 取双hash结果前四个字节，加在第二步结果后面：8028ea039252a3c0b5f3ec2d92f664011561ccf69f434512f20d0daa5fb2a349310118afa009
// 6 进行base58编码：KxbF2HbMFTTfpiic6X8g5GSaKSLLqFYn5bfMquNrYwokySpqeBn8
func PrvKeyToWIF(privKey *PrivateKey, compress bool) string {
	// Precalculate size.  Maximum number of bytes before base58 encoding
	// is one byte for the network, 32 bytes of private key, possibly one
	// extra byte if the pubkey is to be compressed, and finally four
	// bytes of checksum.
	encodeLen := 1 + 32 + 4
	if compress {
		encodeLen++
	}

	a := make([]byte, 0, encodeLen)
	a = append(a, 0x80)
	// Pad and append bytes manually, instead of using Serialize, to
	// avoid another call to make.
	a = paddedAppend(32, a, privKey.D.Bytes())
	if compress {
		a = append(a, compressMagic)
	}
	cksum := DoubleHashB(a)[:4]
	a = append(a, cksum...)
	return base58.Encode(a, base58.BitcoinAlphabet)
}

/********************** 公钥 *********************/

func NewPublicKey(pubHex string) (*PublicKey, error) {
	pubKeyStr, err := hex.DecodeString(pubHex)
	if err != nil {
		return nil, err
	}
	pubKey := PublicKey{}
	pubKey.Curve = curve

	if len(pubKeyStr) == 0 {
		return nil, errors.New("pubkey string is empty")
	}

	format := pubKeyStr[0]
	ybit := (format & 0x1) == 0x1
	format &= ^byte(0x1)

	switch len(pubKeyStr) {
	case PubKeyBytesLenUncompressed:
		if format != pubkeyUncompressed && format != pubkeyHybrid {
			return nil, fmt.Errorf("invalid magic in pubkey str: "+
				"%d", pubKeyStr[0])
		}

		pubKey.X = new(big.Int).SetBytes(pubKeyStr[1:33])
		pubKey.Y = new(big.Int).SetBytes(pubKeyStr[33:])
		// hybrid keys have extra information, make use of it.
		if format == pubkeyHybrid && ybit != isOdd(pubKey.Y) {
			return nil, fmt.Errorf("ybit doesn't match oddness")
		}
	case PubKeyBytesLenCompressed:
		// format is 0x2 | solution, <X coordinate>
		// solution determines which solution of the curve we use.
		/// y^2 = x^3 + Curve.B
		if format != pubkeyCompressed {
			return nil, fmt.Errorf("invalid magic in compressed "+
				"pubkey string: %d", pubKeyStr[0])
		}
		pubKey.X = new(big.Int).SetBytes(pubKeyStr[1:33])
		pubKey.Y, err = decompressPoint(curve, pubKey.X, ybit)
		if err != nil {
			return nil, err
		}
	default: // wrong!
		return nil, fmt.Errorf("invalid pub key length %d",
			len(pubKeyStr))
	}

	if pubKey.X.Cmp(pubKey.Curve.Params().P) >= 0 {
		return nil, fmt.Errorf("pubkey X parameter is >= to P")
	}
	if pubKey.Y.Cmp(pubKey.Curve.Params().P) >= 0 {
		return nil, fmt.Errorf("pubkey Y parameter is >= to P")
	}
	if !pubKey.Curve.IsOnCurve(pubKey.X, pubKey.Y) {
		return nil, fmt.Errorf("pubkey [%v,%v] isn't on secp256k1 curve",
			pubKey.X, pubKey.Y)
	}
	return &pubKey, nil
}

// ToHex 公钥转哈希
func (p *PublicKey) ToHex() string {
	return hex.EncodeToString(p.SerializeCompressed())
}

func (pub *PublicKey) Verify(msg []byte, sign []byte) bool {

	return false
}

// Encrypt 公钥加密
func (p *PublicKey) Encrypt(data []byte) ([]byte, error) {

	// 利用新私钥与公钥生成共享秘钥
	private := GenerateKey()
	derivedKey := sha512.Sum512(GenerateSharedSecret(private, p))
	keyE := derivedKey[:32]
	keyM := derivedKey[32:]

	padding := aes.BlockSize - len(data)%aes.BlockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	paddedIn := append(data, padtext...)

	out := make([]byte, aes.BlockSize+70+len(paddedIn)+sha256.Size)
	iv := out[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	pb := private.PublicKey.SerializeUncompressed()
	offset := aes.BlockSize
	copy(out[offset:offset+4], append(ciphCurveBytes[:], ciphCoordLength[:]...))
	offset += 4
	// X
	copy(out[offset:offset+32], pb[1:33])
	offset += 32
	// Y length
	copy(out[offset:offset+2], ciphCoordLength[:])
	offset += 2
	// Y
	copy(out[offset:offset+32], pb[33:])
	offset += 32

	// 开始加密
	block, err := aes.NewCipher(keyE)
	if err != nil {
		return nil, err
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(out[offset:len(out)-sha256.Size], paddedIn)

	// start HMAC-SHA-256
	hm := hmac.New(sha256.New, keyM)
	hm.Write(out[:len(out)-sha256.Size])          // everything is hashed
	copy(out[len(out)-sha256.Size:], hm.Sum(nil)) // write checksum
	return out, nil
}

// SerializeCompressed serializes a public key in a 33-byte compressed format.
func (p *PublicKey) SerializeCompressed() []byte {
	b := make([]byte, 0, PubKeyBytesLenCompressed)
	format := pubkeyCompressed
	if isOdd(p.Y) {
		format |= 0x1
	}
	b = append(b, format)
	return paddedAppend(32, b, p.X.Bytes())
}

// SerializeUncompressed 将公钥序列化为65位的[]byte
func (p *PublicKey) SerializeUncompressed() []byte {
	b := make([]byte, 0, PubKeyBytesLenUncompressed)
	b = append(b, pubkeyUncompressed)
	b = paddedAppend(32, b, p.X.Bytes())
	return paddedAppend(32, b, p.Y.Bytes())
}

// ToAddress 公钥转地址方法
func (p *PublicKey) ToAddress() string {
	pubBytes := elliptic.Marshal(curve, p.X, p.Y)
	i := Keccak256(pubBytes[1:])[12:]
	tmpStr := hex.EncodeToString(i)
	hash := Keccak256([]byte(tmpStr))

	result := []byte(tmpStr)
	for i := 0; i < len(result); i++ {
		hashByte := hash[i/2]
		if i%2 == 0 {
			hashByte = hashByte >> 4
		} else {
			hashByte &= 0xf
		}
		if result[i] > '9' && hashByte > 7 {
			result[i] -= 32
		}
	}
	return "0x" + strings.ToLower(string(result))
}

/********************** 通用方法 *********************/

func Keccak256(data ...[]byte) []byte {
	hasher := sha3.NewLegacyKeccak256()
	for _, b := range data {
		hasher.Write(b)
	}
	return hasher.Sum(nil)
}

func isOdd(a *big.Int) bool {
	return a.Bit(0) == 1
}

func decompressPoint(curve *eccs256.KoblitzCurve, x *big.Int, ybit bool) (*big.Int, error) {
	// TODO(oga) This will probably only work for secp256k1 due to
	// optimizations.

	// Y = +-sqrt(x^3 + B)
	x3 := new(big.Int).Mul(x, x)
	x3.Mul(x3, x)
	x3.Add(x3, curve.Params().B)

	// now calculate sqrt mod p of x2 + B
	// This code used to do a full sqrt based on tonelli/shanks,
	// but this was replaced by the algorithms referenced in
	// https://bitcointalk.org/index.php?topic=162805.msg1712294#msg1712294
	y := new(big.Int).Exp(x3, curve.Q, curve.Params().P)

	if ybit != isOdd(y) {
		y.Sub(curve.Params().P, y)
	}
	if ybit != isOdd(y) {
		return nil, fmt.Errorf("ybit doesn't match oddness")
	}
	return y, nil
}

func paddedAppend(size uint, dst, src []byte) []byte {
	for i := 0; i < int(size)-len(src); i++ {
		dst = append(dst, 0)
	}
	return append(dst, src...)
}

// signRFC6979 generates a deterministic ECDSA signature according to RFC 6979
// and BIP 62.
func signRFC6979(privateKey *PrivateKey, hash []byte) (*Signature, error) {

	privkey := privateKey
	N := order
	k := NonceRFC6979(privkey.D, hash, nil, nil)
	inv := new(big.Int).ModInverse(k, N)
	r, _ := privkey.Curve.ScalarBaseMult(k.Bytes())
	if r.Cmp(N) == 1 {
		r.Sub(r, N)
	}

	if r.Sign() == 0 {
		return nil, errors.New("calculated R is zero")
	}

	e := hashToInt(hash, privkey.Curve)
	s := new(big.Int).Mul(privkey.D, r)
	s.Add(s, e)
	s.Mul(s, inv)
	s.Mod(s, N)

	if s.Cmp(halforder) == 1 {
		s.Sub(N, s)
	}
	if s.Sign() == 0 {
		return nil, errors.New("calculated S is zero")
	}
	return &Signature{R: r, S: s}, nil
}

// NonceRFC6979 generates an ECDSA nonce (`k`) deterministically according to
// RFC 6979. It takes a 32-byte hash as an input and returns 32-byte nonce to
// be used in ECDSA algorithm.
func NonceRFC6979(privkey *big.Int, hash []byte, extra []byte,
	version []byte) *big.Int {
	curve := curve
	q := curve.Params().N
	x := privkey
	alg := sha256.New

	qlen := q.BitLen()
	holen := alg().Size()
	rolen := (qlen + 7) >> 3
	bx := append(int2octets(x, rolen), bits2octets(hash, curve, rolen)...)
	if len(extra) == 32 {
		bx = append(bx, extra...)
	}
	if len(version) == 16 && len(extra) == 32 {
		bx = append(bx, extra...)
	}
	if len(version) == 16 && len(extra) != 32 {
		bx = append(bx, bytes.Repeat([]byte{0x00}, 32)...)
		bx = append(bx, version...)
	}

	// Step B
	v := bytes.Repeat(oneInitializer, holen)

	// Step C (Go zeroes the all allocated memory)
	k := make([]byte, holen)

	// Step D
	k = mac(alg, k, append(append(v, 0x00), bx...))

	// Step E
	v = mac(alg, k, v)

	// Step F
	k = mac(alg, k, append(append(v, 0x01), bx...))

	// Step G
	v = mac(alg, k, v)

	// Step H
	for {
		// Step H1
		var t []byte

		// Step H2
		for len(t)*8 < qlen {
			v = mac(alg, k, v)
			t = append(t, v...)
		}

		// Step H3
		secret := hashToInt(t, curve)
		if secret.Cmp(one) >= 0 && secret.Cmp(q) < 0 {
			return secret
		}
		k = mac(alg, k, append(v, 0x00))
		v = mac(alg, k, v)
	}
}

// hashToInt将哈希值转换为整数
func hashToInt(hash []byte, c elliptic.Curve) *big.Int {
	orderBits := c.Params().N.BitLen()
	orderBytes := (orderBits + 7) / 8
	if len(hash) > orderBytes {
		hash = hash[:orderBytes]
	}

	ret := new(big.Int).SetBytes(hash)
	excess := len(hash)*8 - orderBits
	if excess > 0 {
		ret.Rsh(ret, uint(excess))
	}
	return ret
}

func int2octets(v *big.Int, rolen int) []byte {
	out := v.Bytes()

	// left pad with zeros if it's too short
	if len(out) < rolen {
		out2 := make([]byte, rolen)
		copy(out2[rolen-len(out):], out)
		return out2
	}

	// drop most significant bytes if it's too long
	if len(out) > rolen {
		out2 := make([]byte, rolen)
		copy(out2, out[len(out)-rolen:])
		return out2
	}

	return out
}

func bits2octets(in []byte, curve elliptic.Curve, rolen int) []byte {
	z1 := hashToInt(in, curve)
	z2 := new(big.Int).Sub(z1, curve.Params().N)
	if z2.Sign() < 0 {
		return int2octets(z1, rolen)
	}
	return int2octets(z2, rolen)
}

// mac返回给定键和消息的HMAC
func mac(alg func() hash.Hash, k, m []byte) []byte {
	h := hmac.New(alg, k)
	h.Write(m)
	return h.Sum(nil)
}

// UnmarshalPubkey 将[]byte转换为secp256k1公钥
func UnmarshalPubkey(pub []byte) (*PublicKey, error) {
	x, y := elliptic.Unmarshal(curve, pub)
	if x == nil {
		return nil, errors.New("invalid secp256k1 public key")
	}
	return &PublicKey{Curve: curve, X: x, Y: y}, nil
}

// DoubleHashB calculates hash(hash(b)) and returns the resulting bytes.
func DoubleHashB(b []byte) []byte {
	first := sha256.Sum256(b)
	second := sha256.Sum256(first[:])
	return second[:]
}

// 从给定消息散列“msg”上的签名“sig”中提取公钥
func recoverKeyFromSignature(sig *Signature, msg []byte, iter int, doChecks bool) (*PublicKey, error) {

	Rx := new(big.Int).Mul(curve.Params().N,
		new(big.Int).SetInt64(int64(iter/2)))
	Rx.Add(Rx, sig.R)
	if Rx.Cmp(curve.Params().P) != -1 {
		return nil, errors.New("calculated Rx is larger than curve P")
	}

	Ry, err := decompressPoint(curve, Rx, iter%2 == 1)
	if err != nil {
		return nil, err
	}

	if doChecks {
		nRx, nRy := curve.ScalarMult(Rx, Ry, curve.Params().N.Bytes())
		if nRx.Sign() != 0 || nRy.Sign() != 0 {
			return nil, errors.New("n*R does not equal the point at infinity")
		}
	}

	e := hashToInt(msg, curve)

	invr := new(big.Int).ModInverse(sig.R, curve.Params().N)

	invrS := new(big.Int).Mul(invr, sig.S)
	invrS.Mod(invrS, curve.Params().N)
	sRx, sRy := curve.ScalarMult(Rx, Ry, invrS.Bytes())

	e.Neg(e)
	e.Mod(e, curve.Params().N)
	e.Mul(e, invr)
	e.Mod(e, curve.Params().N)
	minuseGx, minuseGy := curve.ScalarBaseMult(e.Bytes())

	Qx, Qy := curve.Add(sRx, sRy, minuseGx, minuseGy)

	return &PublicKey{
		Curve: curve,
		X:     Qx,
		Y:     Qy,
	}, nil
}

// ReadBits 将bigint的绝对值编码为大端字节。调用者必须确保buf有足够的空间。如果buf太短，结果将是不完整的。
func ReadBits(bigint *big.Int, buf []byte) {
	i := len(buf)
	for _, d := range bigint.Bits() {
		for j := 0; j < wordBytes && i > 0; j++ {
			i--
			buf[i] = byte(d)
			d >>= 8
		}
	}
}
