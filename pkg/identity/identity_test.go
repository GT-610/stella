package identity

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewIdentity(t *testing.T) {
	// Generate new identity
	id, err := NewIdentity()
	assert.NoError(t, err, "Creating new identity should succeed")
	assert.NotNil(t, id, "Identity should not be nil")
	assert.NotNil(t, id.Address, "Address should not be nil")
	assert.NotEmpty(t, id.PublicKey, "Public key should not be empty")
	assert.NotEmpty(t, id.PrivateKey, "Private key should not be empty")

	// Validate identity
	assert.True(t, id.Validate(), "Identity should be valid")

	// Check if private key is included
	assert.True(t, id.HasPrivateKey(), "Newly generated identity should contain private key")
}

func TestNewIdentityFromPublic(t *testing.T) {
	// First generate a complete identity
	fullId, err := NewIdentity()
	assert.NoError(t, err, "Creating complete identity should succeed")

	// Create identity from public key
	publicId, err := NewIdentityFromPublic(fullId.PublicKey)
	assert.NoError(t, err, "Creating identity from public key should succeed")

	// Verify address matches
	assert.True(t, fullId.Address.Equals(publicId.Address), "Addresses should match")

	// Verify public key matches
	assert.Equal(t, fullId.PublicKey, publicId.PublicKey, "Public keys should match")

	// Verify no private key
	assert.False(t, publicId.HasPrivateKey(), "Identity created from public key should not contain private key")

	// 验证身份
	assert.True(t, publicId.Validate(), "Identity should be valid")
}

func TestIdentitySerialization(t *testing.T) {
	// 生成新身份
	id, err := NewIdentity()
	assert.NoError(t, err, "Creating new identity should succeed")

	// Serialize identity
	serialized := id.Serialize()

	// Recreate identity from serialized string
	restored, err := NewIdentityFromString(serialized)
	assert.NoError(t, err, "Creating identity from serialized string should succeed")

	// 验证地址匹配
	assert.True(t, id.Address.Equals(restored.Address), "Addresses should match")

	// 验证公钥匹配
	assert.Equal(t, id.PublicKey, restored.PublicKey, "Public keys should match")

	// Verify private key matches
	assert.Equal(t, id.PrivateKey, restored.PrivateKey, "Private keys should match")

	// 验证身份
	assert.True(t, restored.Validate(), "Restored identity should be valid")
}

func TestIdentityWithoutPrivateKeySerialization(t *testing.T) {
	// 先生成一个完整的身份
	fullId, err := NewIdentity()
	assert.NoError(t, err, "Creating complete identity should succeed")

	// Create an identity without private key from public key
	publicId, err := NewIdentityFromPublic(fullId.PublicKey)
	assert.NoError(t, err, "Creating identity from public key should succeed")

	// Serialize identity
	serialized := publicId.Serialize()

	// Ensure serialized string doesn't contain private key part
	expected := publicId.Address.String() + ":" + base64.StdEncoding.EncodeToString(publicId.PublicKey)
	assert.Equal(t, expected, serialized, "Serialized string should not contain private key part")

	// Recreate identity from serialized string
	restored, err := NewIdentityFromString(serialized)
	assert.NoError(t, err, "Creating identity from serialized string should succeed")

	// 验证地址匹配
	assert.True(t, publicId.Address.Equals(restored.Address), "Addresses should match")

	// 验证公钥匹配
	assert.Equal(t, publicId.PublicKey, restored.PublicKey, "Public keys should match")

	// Verify no private key
	assert.False(t, restored.HasPrivateKey(), "Restored identity should not contain private key")
}

func TestGetSharedSecret(t *testing.T) {
	// Generate two identities
	id1, err := NewIdentity()
	assert.NoError(t, err, "Creating first identity should succeed")

	id2, err := NewIdentity()
	assert.NoError(t, err, "Creating second identity should succeed")

	// Calculate shared secret
	secret1, err := id1.GetSharedSecret(id2)
	assert.NoError(t, err, "Calculating shared secret should succeed")

	secret2, err := id2.GetSharedSecret(id1)
	assert.NoError(t, err, "Calculating shared secret should succeed")

	// Verify shared secrets calculated in both directions are the same
	assert.Equal(t, secret1, secret2, "Shared secrets calculated in both directions should be the same")

	// Verify identity without private key cannot calculate shared secret
	publicId, _ := NewIdentityFromPublic(id1.PublicKey)
	_, err = publicId.GetSharedSecret(id2)
	assert.Error(t, err, "Identity without private key should not be able to calculate shared secret")
}

func TestIdentityValidation(t *testing.T) {
	// Generate new identity
	id, err := NewIdentity()
	assert.NoError(t, err, "Creating new identity should succeed")

	// Verify identity should be valid
	assert.True(t, id.Validate(), "Identity should be valid")

	// Manually create an invalid identity (address doesn't match public key)
	id2, _ := NewIdentity()
	invalidId := &Identity{
		Address:   id.Address,   // Use id1's address
		PublicKey: id2.PublicKey, // But use id2's public key
	}

	// Verify invalid identity should fail validation
	assert.False(t, invalidId.Validate(), "Invalid identity should fail validation")
}