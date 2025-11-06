// Package crypto provides cryptographic functionality for Stella network
package crypto

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"math/big"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/poly1305"
)

// 加密套件常量，与ZeroTierOne兼容
const (
	// CipherC25519_POLY1305_NONE 使用Curve25519进行密钥交换，但不加密数据
	CipherC25519_POLY1305_NONE = 0
	
	// CipherC25519_POLY1305_SALSA2012 使用Curve25519进行密钥交换，Poly1305进行身份验证，Salsa20/12进行加密
	CipherC25519_POLY1305_SALSA2012 = 1
	
	// CipherAES_GMAC_SIV 使用AES-GMAC-SIV进行加密
	CipherAES_GMAC_SIV = 2
)

// KeyPair 表示加密密钥对
type KeyPair struct {
	Public  []byte
	Private []byte
}

// 实现RotateLeft函数，因为salsa包中没有直接提供
func rotateLeft(v uint32, n int) uint32 {
	return (v << n) | (v >> (32 - n))
}

// GenerateKeyPair generates a Curve25519 key pair
func GenerateKeyPair() (*KeyPair, error) {
	privateKey := make([]byte, curve25519.ScalarSize)
	if _, err := rand.Read(privateKey); err != nil {
		return nil, err
	}

	// 转换为固定大小的数组
	var privateKeyArr [curve25519.ScalarSize]byte
	copy(privateKeyArr[:], privateKey)

	// 生成公钥
	var publicKeyArr [curve25519.PointSize]byte
	curve25519.ScalarBaseMult(&publicKeyArr, &privateKeyArr)

	return &KeyPair{
		Private: privateKey,
		Public:  publicKeyArr[:],
	}, nil
}

// GenerateP256KeyPair generates a P256 key pair
func GenerateP256KeyPair() (*KeyPair, error) {
	curve := elliptic.P256()

	// 生成P256密钥对
	priv, x, y, err := elliptic.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, err
	}

	// 生成压缩格式的公钥
	publicKey := elliptic.MarshalCompressed(curve, x, y)

	return &KeyPair{
		Public:  publicKey,
		Private: priv,
	}, nil
}

// Hash 计算SHA-512哈希值
func Hash(data []byte) []byte {
	h := sha512.Sum512(data)
	return h[:]
}

// DeriveSharedSecret derives a shared secret using Curve25519 ECDH
func DeriveSharedSecret(privateKey []byte, peerPublicKey []byte) ([]byte, error) {
	// 验证输入长度
	if len(privateKey) != curve25519.ScalarSize {
		return nil, errors.New("invalid private key length")
	}
	if len(peerPublicKey) != curve25519.PointSize {
		return nil, errors.New("invalid peer public key length")
	}

	// 转换为固定大小的数组
	var privateKeyArr [curve25519.ScalarSize]byte
	copy(privateKeyArr[:], privateKey)

	var peerPublicKeyArr [curve25519.PointSize]byte
	copy(peerPublicKeyArr[:], peerPublicKey)

	// 派生共享密钥
	var sharedSecretArr [curve25519.PointSize]byte
	curve25519.ScalarMult(&sharedSecretArr, &privateKeyArr, &peerPublicKeyArr)

	// 对共享密钥进行哈希以获得固定长度的输出
	hashedSecret := Hash(sharedSecretArr[:])

	return hashedSecret, nil
}

// DeriveSharedSecretP256 使用P256椭圆曲线派生共享密钥
func DeriveSharedSecretP256(privateKey []byte, peerPublicKey []byte) ([]byte, error) {
	curve := elliptic.P256()

	// 解析私钥
	priv := new(big.Int).SetBytes(privateKey)

	// 解析公钥
	x, y := elliptic.UnmarshalCompressed(curve, peerPublicKey)
	if x == nil || y == nil {
		return nil, errors.New("invalid public key")
	}

	// 计算共享密钥
	x, _ = curve.ScalarMult(x, y, priv.Bytes())
	if x == nil {
		return nil, errors.New("failed to derive shared secret")
	}

	// 对共享密钥进行哈希
	hashedSecret := Hash(x.Bytes())

	return hashedSecret, nil
}

// Poly1305Authenticate 计算Poly1305 MAC
func Poly1305Authenticate(message []byte, key []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("Poly1305 key must be 32 bytes")
	}

	var keyArr [32]byte
	copy(keyArr[:], key)

	var mac [16]byte
	poly1305.Sum(&mac, message, &keyArr)

	return mac[:], nil
}

// Poly1305Verify verifies a Poly1305 MAC
func Poly1305Verify(message []byte, key []byte, mac []byte) bool {
	computedMAC, err := Poly1305Authenticate(message, key)
	if err != nil {
		return false
	}

	// 恒定时间比较防止时间侧信道攻击
	return subtleConstantTimeCompare(mac, computedMAC)
}

// Salsa2012Stream generates a Salsa20/12 keystream
func Salsa2012Stream(key, nonce []byte, out []byte) error {
	if len(key) != 32 {
		return errors.New("Salsa20 key must be 32 bytes")
	}
	if len(nonce) != 8 {
		return errors.New("Salsa20 nonce must be 8 bytes")
	}

	// 创建key和nonce的固定大小数组
	var keyArr [32]byte
	var nonceArr [8]byte
	copy(keyArr[:], key)
	copy(nonceArr[:], nonce)

	// 手动处理每个数据块
	for i := 0; i < len(out); i += 64 {
		// 准备Salsa20状态
		var state [16]uint32

		// 设置Salsa20常量
		state[0] = 0x61707865 // "expa"
		state[1] = 0x3320646e // "nd 3"
		state[2] = 0x79622d32 // "2-by"
		state[3] = 0x6b206574 // "te k"
		state[12] = 0x6b206574 // "te k"
		state[13] = 0x79622d32 // "2-by"
		state[14] = 0x3320646e // "nd 3"
		state[15] = 0x61707865 // "expa"

		// 设置密钥
		for j := 0; j < 8; j++ {
			state[j+4] = uint32(keyArr[4*j])<<24 | uint32(keyArr[4*j+1])<<16 | uint32(keyArr[4*j+2])<<8 | uint32(keyArr[4*j+3])
		}

		// 设置nonce和计数器
		counter := uint64(i / 64)
		state[8] = uint32(counter >> 32)
		state[9] = uint32(counter)
		state[10] = uint32(nonceArr[0])<<24 | uint32(nonceArr[1])<<16 | uint32(nonceArr[2])<<8 | uint32(nonceArr[3])
		state[11] = uint32(nonceArr[4])<<24 | uint32(nonceArr[5])<<16 | uint32(nonceArr[6])<<8 | uint32(nonceArr[7])

		// 复制状态用于最终的加法
		var initialState [16]uint32
		copy(initialState[:], state[:])

		// 执行12轮Salsa20/12操作（标准Salsa20是20轮）
		for round := 0; round < 6; round++ {
			// 列混合
			state[4] ^= rotateLeft(state[0]+state[12], 7)
			state[8] ^= rotateLeft(state[4]+state[0], 9)
			state[12] ^= rotateLeft(state[8]+state[4], 13)
			state[0] ^= rotateLeft(state[12]+state[8], 18)

			state[9] ^= rotateLeft(state[5]+state[1], 7)
			state[13] ^= rotateLeft(state[9]+state[5], 9)
			state[1] ^= rotateLeft(state[13]+state[9], 13)
			state[5] ^= rotateLeft(state[1]+state[13], 18)

			state[14] ^= rotateLeft(state[10]+state[6], 7)
			state[2] ^= rotateLeft(state[14]+state[10], 9)
			state[6] ^= rotateLeft(state[2]+state[14], 13)
			state[10] ^= rotateLeft(state[6]+state[2], 18)

			state[3] ^= rotateLeft(state[15]+state[11], 7)
			state[7] ^= rotateLeft(state[3]+state[15], 9)
			state[11] ^= rotateLeft(state[7]+state[3], 13)
			state[15] ^= rotateLeft(state[11]+state[7], 18)

			// 行混合
			state[1] ^= rotateLeft(state[0]+state[3], 7)
			state[2] ^= rotateLeft(state[1]+state[0], 9)
			state[3] ^= rotateLeft(state[2]+state[1], 13)
			state[0] ^= rotateLeft(state[3]+state[2], 18)

			state[6] ^= rotateLeft(state[5]+state[4], 7)
			state[7] ^= rotateLeft(state[6]+state[5], 9)
			state[4] ^= rotateLeft(state[7]+state[6], 13)
			state[5] ^= rotateLeft(state[4]+state[7], 18)

			state[11] ^= rotateLeft(state[10]+state[9], 7)
			state[8] ^= rotateLeft(state[11]+state[10], 9)
			state[9] ^= rotateLeft(state[8]+state[11], 13)
			state[10] ^= rotateLeft(state[9]+state[8], 18)

			state[12] ^= rotateLeft(state[15]+state[14], 7)
			state[13] ^= rotateLeft(state[12]+state[15], 9)
			state[14] ^= rotateLeft(state[13]+state[12], 13)
			state[15] ^= rotateLeft(state[14]+state[13], 18)
		}

		// 将状态转换为字节并与输入数据进行XOR
		for j := 0; j < 16; j++ {
			// 最终加法
			state[j] += initialState[j]

			// 将结果转换为字节
			val := state[j]
			byteOffset := i + 4*j

			if byteOffset < len(out) {
				out[byteOffset] ^= byte(val >> 24)
			}
			if byteOffset+1 < len(out) {
				out[byteOffset+1] ^= byte(val >> 16)
			}
			if byteOffset+2 < len(out) {
				out[byteOffset+2] ^= byte(val >> 8)
			}
			if byteOffset+3 < len(out) {
				out[byteOffset+3] ^= byte(val)
			}
		}
	}

	return nil
}

// EncryptSalsa2012 encrypts data using Salsa20/12
func EncryptSalsa2012(plaintext []byte, key []byte, nonce []byte) ([]byte, error) {
	// 创建明文的副本用于加密
	ciphertext := make([]byte, len(plaintext))
	copy(ciphertext, plaintext)

	// 使用Salsa20/12加密
	err := Salsa2012Stream(key, nonce, ciphertext)
	if err != nil {
		return nil, err
	}

	return ciphertext, nil
}

// DecryptSalsa2012 decrypts data using Salsa20/12
func DecryptSalsa2012(ciphertext []byte, key []byte, nonce []byte) ([]byte, error) {
	// Salsa20/12的解密与加密使用相同的操作
	return EncryptSalsa2012(ciphertext, key, nonce)
}

// EncryptSalsa2012WithPoly1305 encrypts data using Salsa20/12 with Poly1305 authentication
func EncryptSalsa2012WithPoly1305(data []byte, key []byte, nonce []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("encryption key must be 32 bytes")
	}

	if len(nonce) != 8 {
		return nil, errors.New("nonce must be 8 bytes")
	}

	// 生成用于Poly1305的密钥（使用key和nonce的哈希）
	polyKey := Hash(append(key, nonce...))[:32]
	
	// 加密数据
	ciphertext, err := EncryptSalsa2012(data, key, nonce)
	if err != nil {
		return nil, err
	}

	// 计算Poly1305 MAC
	mac, err := Poly1305Authenticate(ciphertext, polyKey)
	if err != nil {
		return nil, err
	}

	// 组合密文和MAC
	result := append(ciphertext, mac...)
	return result, nil
}

// DecryptSalsa2012WithPoly1305 decrypts data using Salsa20/12 with Poly1305 authentication
func DecryptSalsa2012WithPoly1305(data []byte, key []byte, nonce []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("decryption key must be 32 bytes")
	}

	if len(nonce) != 8 {
		return nil, errors.New("nonce must be 8 bytes")
	}

	if len(data) < 16 {
		return nil, errors.New("data too short, missing MAC")
	}

	// 分割密文和MAC
	ciphertext := data[:len(data)-16]
	mac := data[len(data)-16:]

	// 生成用于Poly1305验证的密钥
	polyKey := Hash(append(key, nonce...))[:32]

	// 验证MAC
	valid := Poly1305Verify(ciphertext, polyKey, mac)
	if !valid {
		return nil, errors.New("MAC verification failed")
	}

	// 解密数据
	return DecryptSalsa2012(ciphertext, key, nonce)
}

// subtleConstantTimeCompare performs a constant-time comparison of two byte slices
func subtleConstantTimeCompare(x, y []byte) bool {
	if len(x) != len(y) {
		return false
	}

	var v byte
	for i := 0; i < len(x); i++ {
		v |= x[i] ^ y[i]
	}

	return v == 0
}