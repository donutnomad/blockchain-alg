package xecdsa

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/assert"
)

// TestPublicKeyFrom tests the From method with different input types
func TestPublicKeyFrom(t *testing.T) {
	// Test with ecdsa.PublicKey
	privKey, err := ecdsa.GenerateKey(P256.Curve(), rand.Reader)
	assert.NoError(t, err)

	pubKey, err := new(PublicKey).From(&privKey.PublicKey, P256)
	assert.NoError(t, err)
	assert.NotNil(t, pubKey)
	assert.Equal(t, privKey.PublicKey.X, pubKey.X)
	assert.Equal(t, privKey.PublicKey.Y, pubKey.Y)

	// Test with string (hex) - using uncompressed format
	uncompressed := elliptic.Marshal(P256.Curve(), privKey.PublicKey.X, privKey.PublicKey.Y)
	hexKey := "0x" + hex.EncodeToString(uncompressed)
	pubKey, err = new(PublicKey).From(hexKey, P256)
	assert.NoError(t, err)
	assert.NotNil(t, pubKey)
	assert.Equal(t, privKey.PublicKey.X, pubKey.X)
	assert.Equal(t, privKey.PublicKey.Y, pubKey.Y)

	// Test with secp256k1.PublicKey
	secpPrivKey, err := secp256k1.GeneratePrivateKey()
	assert.NoError(t, err)
	secpPubKey := secpPrivKey.PubKey()
	pubKey, err = new(PublicKey).From(secpPubKey, Secp256k1)
	assert.NoError(t, err)
	assert.NotNil(t, pubKey)
}

// TestPublicKeyFromBytes tests the FromBytes method
func TestPublicKeyFromBytes(t *testing.T) {
	// Test with P256
	privKey, err := ecdsa.GenerateKey(P256.Curve(), rand.Reader)
	assert.NoError(t, err)

	// Test uncompressed format
	uncompressed := elliptic.Marshal(P256.Curve(), privKey.PublicKey.X, privKey.PublicKey.Y)
	pubKey, err := new(PublicKey).FromBytes(uncompressed, P256)
	assert.NoError(t, err)
	assert.NotNil(t, pubKey)
	assert.Equal(t, privKey.PublicKey.X, pubKey.X)
	assert.Equal(t, privKey.PublicKey.Y, pubKey.Y)

	// Test compressed format
	compressed := elliptic.MarshalCompressed(P256.Curve(), privKey.PublicKey.X, privKey.PublicKey.Y)
	pubKey, err = new(PublicKey).FromBytes(compressed, P256)
	assert.NoError(t, err)
	assert.NotNil(t, pubKey)
	assert.Equal(t, privKey.PublicKey.X, pubKey.X)
	assert.Equal(t, privKey.PublicKey.Y, pubKey.Y)

	// Test with Secp256k1
	secpPrivKey, err := secp256k1.GeneratePrivateKey()
	assert.NoError(t, err)
	secpPubKey := secpPrivKey.PubKey()
	secpBytes := secpPubKey.SerializeCompressed()
	pubKey, err = new(PublicKey).FromBytes(secpBytes, Secp256k1)
	assert.NoError(t, err)
	assert.NotNil(t, pubKey)
}

// TestPublicKeyToECDSA tests the ToECDSA method
func TestPublicKeyToECDSA(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(P256.Curve(), rand.Reader)
	assert.NoError(t, err)

	pubKey := new(PublicKey).FromECDSA(&privKey.PublicKey)
	ecdsaKey := pubKey.ToECDSA()
	assert.NotNil(t, ecdsaKey)
	assert.Equal(t, privKey.PublicKey.X, ecdsaKey.X)
	assert.Equal(t, privKey.PublicKey.Y, ecdsaKey.Y)
}

// TestPublicKeyToBytes tests the ToBytes method
func TestPublicKeyToBytes(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(P256.Curve(), rand.Reader)
	assert.NoError(t, err)

	pubKey := new(PublicKey).FromECDSA(&privKey.PublicKey)
	bytes := pubKey.ToBytes()
	assert.NotEmpty(t, bytes)
	assert.Equal(t, byte(4), bytes[0]) // Should be uncompressed format
}

// TestPublicKeyToDER tests the ToDER method
func TestPublicKeyToDER(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(P256.Curve(), rand.Reader)
	assert.NoError(t, err)

	pubKey := new(PublicKey).FromECDSA(&privKey.PublicKey)
	der, err := pubKey.ToDER()
	assert.NoError(t, err)
	assert.NotEmpty(t, der)
}

// TestPublicKeySerialize tests the Serialize method
func TestPublicKeySerialize(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(P256.Curve(), rand.Reader)
	assert.NoError(t, err)

	pubKey := new(PublicKey).FromECDSA(&privKey.PublicKey)

	// Test uncompressed format
	uncompressed := pubKey.Serialize(false)
	assert.NotEmpty(t, uncompressed)
	assert.Equal(t, byte(4), uncompressed[0])

	// Test compressed format
	compressed := pubKey.Serialize(true)
	assert.NotEmpty(t, compressed)
	assert.True(t, compressed[0] == 2 || compressed[0] == 3)
}
