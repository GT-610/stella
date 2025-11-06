package crypto

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestKeyPairGeneration 测试密钥对生成
func TestKeyPairGeneration(t *testing.T) {
	keyPair, err := GenerateKeyPair()
	assert.NoError(t, err)
	assert.NotNil(t, keyPair)
	assert.Len(t, keyPair.Public, 32)    // Curve25519 公钥大小
	assert.Len(t, keyPair.Private, 32)   // Curve25519 私钥大小

	// 测试 P256 密钥对生成
	p256KeyPair, err := GenerateP256KeyPair()
	assert.NoError(t, err)
	assert.NotNil(t, p256KeyPair)
}

// TestSharedSecretDerivation 测试共享密钥派生
func TestSharedSecretDerivation(t *testing.T) {
	// 生成两对密钥
	keyPair1, err := GenerateKeyPair()
	assert.NoError(t, err)

	keyPair2, err := GenerateKeyPair()
	assert.NoError(t, err)

	// 派生共享密钥（从两个方向）
	secret1, err := DeriveSharedSecret(keyPair1.Private, keyPair2.Public)
	assert.NoError(t, err)

	secret2, err := DeriveSharedSecret(keyPair2.Private, keyPair1.Public)
	assert.NoError(t, err)

	// 验证两个方向派生的密钥应该相同
	assert.Equal(t, secret1, secret2)
	assert.Len(t, secret1, 64) // SHA-512 哈希输出长度
}

// TestSalsa2012EncryptionDecryption 测试 Salsa20/12 加密和解密
func TestSalsa2012EncryptionDecryption(t *testing.T) {
	// 准备测试数据
	plaintext := []byte("Hello, this is a test message for encryption!")
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	nonce := make([]byte, 8)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}

	// 加密
	ciphertext, err := EncryptSalsa2012(plaintext, key, nonce)
	assert.NoError(t, err)
	assert.NotEqual(t, plaintext, ciphertext) // 密文应该与明文不同

	// 解密
	decrypted, err := DecryptSalsa2012(ciphertext, key, nonce)
	assert.NoError(t, err)
	assert.Equal(t, plaintext, decrypted) // 解密后的文本应该与原始明文相同
}

// TestPoly1305Authentication 测试 Poly1305 认证
func TestPoly1305Authentication(t *testing.T) {
	// 准备测试数据
	message := []byte("Test message for Poly1305 authentication")
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	// 生成认证标签
	mac, err := Poly1305Authenticate(message, key)
	assert.NoError(t, err)
	assert.Len(t, mac, 16) // Poly1305 输出长度为 16 字节

	// 验证标签（正确密钥）
	valid := Poly1305Verify(message, key, mac)
	assert.True(t, valid)

	// 验证标签（错误密钥）
	badKey := make([]byte, 32)
	if _, err := rand.Read(badKey); err != nil {
		t.Fatal(err)
	}
	// 确保坏密钥与好密钥不同
	for i := range key {
		if key[i] != badKey[i] {
			break
		}
		badKey[i] ^= 1 // 至少修改一位
	}

	invalid := Poly1305Verify(message, badKey, mac)
	assert.False(t, invalid)
}

// TestHash 测试哈希函数
func TestHash(t *testing.T) {
	// 测试简单字符串
	hash1 := Hash([]byte("test"))
	assert.Len(t, hash1, 64) // SHA-512 输出长度

	// 测试空字符串
	hash2 := Hash([]byte{})
	assert.Len(t, hash2, 64)

	// 测试两个相同输入应该产生相同哈希
	hash3 := Hash([]byte("test"))
	assert.Equal(t, hash1, hash3)

	// 测试两个不同输入应该产生不同哈希
	hash4 := Hash([]byte("test2"))
	assert.NotEqual(t, hash1, hash4)
}

// TestTransportEncryptionDecryption 测试端到端加密流程
func TestTransportEncryptionDecryption(t *testing.T) {
	// 模拟两个节点的密钥对
	node1KeyPair, err := GenerateKeyPair()
	assert.NoError(t, err)

	node2KeyPair, err := GenerateKeyPair()
	assert.NoError(t, err)

	// 原始消息
	originalMessage := []byte("This is a secure message between nodes")

	// 节点1 加密消息给节点2
	// 1. 生成 nonce
	nonce := make([]byte, 8)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}

	// 2. 派生共享密钥
	sharedSecret1, err := DeriveSharedSecret(node1KeyPair.Private, node2KeyPair.Public)
	assert.NoError(t, err)

	// 3. 加密消息
	ciphertext, err := EncryptSalsa2012(originalMessage, sharedSecret1[:32], nonce)
	assert.NoError(t, err)

	// 节点2 解密消息
	// 1. 派生共享密钥
	sharedSecret2, err := DeriveSharedSecret(node2KeyPair.Private, node1KeyPair.Public)
	assert.NoError(t, err)

	// 2. 解密消息
	decryptedMessage, err := DecryptSalsa2012(ciphertext, sharedSecret2[:32], nonce)
	assert.NoError(t, err)

	// 验证解密后的消息与原始消息相同
	assert.Equal(t, originalMessage, decryptedMessage)
}