package xecdsa

import (
	"crypto/ecdsa"
	"crypto/rand"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/assert"
)

// TestGenerateKey tests the GenerateKey function for different algorithms
func TestGenerateKey(t *testing.T) {
	tests := []struct {
		name    string
		alg     Algorithm
		wantErr bool
	}{
		{
			name:    "Generate Secp256k1 key",
			alg:     Secp256k1,
			wantErr: false,
		},
		{
			name:    "Generate P256 key",
			alg:     P256,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GenerateKey(tt.alg)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				assert.NotNil(t, got)
				assert.NotNil(t, got.D)
				assert.NotNil(t, got.X)
				assert.NotNil(t, got.Y)
			}
		})
	}
}

// TestNewPrivateKeyS256 tests the NewPrivateKeyS256 function
func TestNewPrivateKeyS256(t *testing.T) {
	// Generate a random 32-byte key
	key := [32]byte{}
	_, err := rand.Read(key[:])
	assert.NoError(t, err)

	privKey, err := NewPrivateKeyS256(key)
	assert.NoError(t, err)
	assert.NotNil(t, privKey)
	assert.Equal(t, Secp256k1, privKey.Algorithm())
}

// TestNewPrivateKeyP256 tests the NewPrivateKeyP256 function
func TestNewPrivateKeyP256(t *testing.T) {
	// Generate a random 32-byte key
	key := [32]byte{}
	_, err := rand.Read(key[:])
	assert.NoError(t, err)

	privKey, err := NewPrivateKeyP256(key)
	assert.NoError(t, err)
	assert.NotNil(t, privKey)
	assert.Equal(t, P256, privKey.Algorithm())
}

// TestFrom tests the From method with different input types
func TestFrom(t *testing.T) {
	// Test with ecdsa.PrivateKey
	ecdsaKey, err := ecdsa.GenerateKey(P256.Curve(), rand.Reader)
	assert.NoError(t, err)

	privKey, err := new(PrivateKey).From(ecdsaKey, P256)
	assert.NoError(t, err)
	assert.NotNil(t, privKey)
	assert.Equal(t, ecdsaKey.D, privKey.D)

	// Test with string (hex)
	hexKey := "0x1234567890abcdef"
	privKey, err = new(PrivateKey).From(hexKey, P256)
	assert.NoError(t, err)
	assert.NotNil(t, privKey)

	// Test with secp256k1.PrivateKey
	secpKey, err := secp256k1.GeneratePrivateKey()
	assert.NoError(t, err)
	privKey, err = new(PrivateKey).From(secpKey, Secp256k1)
	assert.NoError(t, err)
	assert.NotNil(t, privKey)
}

// TestToECDSA tests the ToECDSA method
func TestToECDSA(t *testing.T) {
	privKey, err := GenerateKey(P256)
	assert.NoError(t, err)

	ecdsaKey := privKey.ToECDSA()
	assert.NotNil(t, ecdsaKey)
	assert.Equal(t, privKey.D, ecdsaKey.D)
	assert.Equal(t, privKey.X, ecdsaKey.X)
	assert.Equal(t, privKey.Y, ecdsaKey.Y)
}

// TestToDER tests the ToDER method
func TestToDER(t *testing.T) {
	privKey, err := GenerateKey(P256)
	assert.NoError(t, err)

	der, err := privKey.ToDER()
	assert.NoError(t, err)
	assert.NotEmpty(t, der)
}

// TestAlgorithm tests the Algorithm method
func TestAlgorithm(t *testing.T) {
	tests := []struct {
		name string
		alg  Algorithm
	}{
		{
			name: "Secp256k1 algorithm",
			alg:  Secp256k1,
		},
		{
			name: "P256 algorithm",
			alg:  P256,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			privKey, err := GenerateKey(tt.alg)
			assert.NoError(t, err)
			assert.Equal(t, tt.alg, privKey.Algorithm())
		})
	}
}
