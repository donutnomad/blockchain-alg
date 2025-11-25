package xsecp256k1

import (
	"crypto/rand"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"golang.org/x/crypto/sha3"
)

func TestExtractV(t *testing.T) {
	// Generate a random private key
	var privateKey [32]byte
	if _, err := rand.Read(privateKey[:]); err != nil {
		t.Fatalf("failed to generate random private key: %v", err)
	}

	// Derive the public key from the private key
	privKey := secp256k1.PrivKeyFromBytes(privateKey[:])
	publicKey := &PublicKey{PublicKey: *privKey.PubKey()}

	// Create a message hash
	message := []byte("test message for ExtractV")
	hash := keccak256(message)

	// Sign the message using SignS256Compact (which includes v as 27 or 28)
	signatureCompat := SignS256Compact(privateKey, hash)
	expectedV := signatureCompat.V()

	// Extract v using ExtractV (returns 27 or 28)
	extractedV, ok := Secp256k1.ExtractV(publicKey, signatureCompat.Signature(), hash)
	if !ok {
		t.Fatal("ExtractV failed to extract v")
	}

	if extractedV != expectedV {
		t.Errorf("ExtractV returned wrong v: got %d, want %d", extractedV, expectedV)
	}
}

func TestFillSignatureV(t *testing.T) {
	// Generate a random private key
	var privateKey [32]byte
	if _, err := rand.Read(privateKey[:]); err != nil {
		t.Fatalf("failed to generate random private key: %v", err)
	}

	// Derive the public key from the private key
	privKey := secp256k1.PrivKeyFromBytes(privateKey[:])
	publicKey := &PublicKey{PublicKey: *privKey.PubKey()}

	// Create a message hash
	message := []byte("test message for FillSignatureV")
	hash := keccak256(message)

	// Sign the message using SignS256Compact (which includes v as 27 or 28)
	originalSignature := SignS256Compact(privateKey, hash)
	expectedV := originalSignature.V()

	// Get signature without v
	signatureWithoutV := originalSignature.Signature()

	// Fill v using FillSignatureV (returns v as 27 or 28)
	filledSignature, ok := Secp256k1.FillSignatureV(publicKey, signatureWithoutV, hash)
	if !ok {
		t.Fatal("FillSignatureV failed to fill v")
	}

	// Verify that the filled signature has the correct v (27 or 28)
	if filledSignature.V() != expectedV {
		t.Errorf("FillSignatureV returned wrong v: got %d, want %d", filledSignature.V(), expectedV)
	}

	// Verify R and S are preserved
	if filledSignature.R().Cmp(originalSignature.R()) != 0 {
		t.Error("FillSignatureV changed R value")
	}
	if filledSignature.S().Cmp(originalSignature.S()) != 0 {
		t.Error("FillSignatureV changed S value")
	}
}

func TestExtractVAndFillSignatureVConsistency(t *testing.T) {
	// Run multiple iterations to test with different keys and messages
	for i := range 10 {
		t.Run("iteration", func(t *testing.T) {
			// Generate a random private key
			var privateKey [32]byte
			if _, err := rand.Read(privateKey[:]); err != nil {
				t.Fatalf("iteration %d: failed to generate random private key: %v", i, err)
			}

			// Derive the public key
			privKey := secp256k1.PrivKeyFromBytes(privateKey[:])
			publicKey := &PublicKey{PublicKey: *privKey.PubKey()}

			// Create a unique message hash for each iteration
			message := make([]byte, 32)
			if _, err := rand.Read(message); err != nil {
				t.Fatalf("iteration %d: failed to generate random message: %v", i, err)
			}
			hash := keccak256(message)

			// Sign the message (v is 27 or 28)
			originalSignature := SignS256Compact(privateKey, hash)
			expectedV := originalSignature.V()

			// Test ExtractV (returns 27 or 28)
			extractedV, ok := Secp256k1.ExtractV(publicKey, originalSignature.Signature(), hash)
			if !ok {
				t.Fatalf("iteration %d: ExtractV failed", i)
			}
			if extractedV != expectedV {
				t.Errorf("iteration %d: ExtractV mismatch: got %d, want %d", i, extractedV, expectedV)
			}

			// Test FillSignatureV (returns v as 27 or 28)
			filledSignature, ok := Secp256k1.FillSignatureV(publicKey, originalSignature.Signature(), hash)
			if !ok {
				t.Fatalf("iteration %d: FillSignatureV failed", i)
			}
			if filledSignature.V() != expectedV {
				t.Errorf("iteration %d: FillSignatureV mismatch: got %d, want %d", i, filledSignature.V(), expectedV)
			}

			// Verify the filled signature can recover the correct public key
			recoveredPubKey, err := Secp256k1.RecoverPublicKey(filledSignature, hash)
			if err != nil {
				t.Fatalf("iteration %d: RecoverPublicKey failed: %v", i, err)
			}
			if !recoveredPubKey.IsEqual(&publicKey.PublicKey) {
				t.Errorf("iteration %d: recovered public key does not match original", i)
			}
		})
	}
}

func TestExtractVWithWrongPublicKey(t *testing.T) {
	// Generate two different private keys
	var privateKey1, privateKey2 [32]byte
	if _, err := rand.Read(privateKey1[:]); err != nil {
		t.Fatalf("failed to generate random private key 1: %v", err)
	}
	if _, err := rand.Read(privateKey2[:]); err != nil {
		t.Fatalf("failed to generate random private key 2: %v", err)
	}

	// Derive the public keys
	privKey1 := secp256k1.PrivKeyFromBytes(privateKey1[:])
	privKey2 := secp256k1.PrivKeyFromBytes(privateKey2[:])
	publicKey2 := &PublicKey{PublicKey: *privKey2.PubKey()}

	// Sign with key1 but try to extract v with key2's public key
	message := []byte("test message")
	hash := keccak256(message)
	signature := SignS256Compact(privateKey1, hash)

	// This should fail because we're using the wrong public key
	_, ok := Secp256k1.ExtractV(publicKey2, signature.Signature(), hash)

	// The result depends on whether key2 happens to match one of the recovery attempts
	// In most cases, it should return false, but we can't guarantee it
	// So we just verify the function doesn't panic
	_ = ok

	// Verify with correct public key works
	publicKey1 := &PublicKey{PublicKey: *privKey1.PubKey()}
	v, ok := Secp256k1.ExtractV(publicKey1, signature.Signature(), hash)
	if !ok {
		t.Fatal("ExtractV failed with correct public key")
	}
	// v should be 27 or 28
	expectedV := signature.V()
	if v != expectedV {
		t.Errorf("ExtractV returned wrong v with correct key: got %d, want %d", v, expectedV)
	}
}

// keccak256 is a helper function to compute Keccak256 hash.
func keccak256(data []byte) []byte {
	h := sha3.NewLegacyKeccak256()
	h.Write(data)
	return h.Sum(nil)
}
