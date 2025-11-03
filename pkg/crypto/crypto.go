// Package crypto provides cryptographic functionality for Stella network
package crypto

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"math/big"
)

// KeyPair represents a cryptographic key pair
type KeyPair struct {
	Public  []byte
	Private []byte
}

// GenerateKeyPair generates a new key pair
func GenerateKeyPair() (*KeyPair, error) {
	curve := elliptic.P256() // Using P256 as the initial implementation
	privateKey, x, y, err := elliptic.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, err
	}

	// Combine the x and y coordinates of the public key into a byte array
	publicKey := append(x.Bytes(), y.Bytes()...)

	return &KeyPair{
		Public:  publicKey,
		Private: privateKey,
	}, nil
}

// Hash performs SHA-512 hash calculation on input data
func Hash(data []byte) []byte {
	hash := sha512.Sum512(data)
	return hash[:]
}

// DeriveSharedSecret derives a shared secret using ECDH
func DeriveSharedSecret(privateKey []byte, peerPublicKey []byte) ([]byte, error) {
	curve := elliptic.P256()

	// Recover private key from bytes
	d := new(big.Int).SetBytes(privateKey)

	// Recover public key from bytes
	if len(peerPublicKey) < 64 {
		return nil, errors.New("invalid public key length")
	}
	
	x := new(big.Int).SetBytes(peerPublicKey[:32])
	y := new(big.Int).SetBytes(peerPublicKey[32:])

	// Calculate shared secret
	sx, _ := curve.ScalarMult(x, y, d.Bytes())
	sharedSecret := sx.Bytes()

	// Hash the shared secret to get a fixed-length output
	return Hash(sharedSecret), nil
}