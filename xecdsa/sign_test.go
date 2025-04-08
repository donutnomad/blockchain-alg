package xecdsa

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
	"testing"
)

func TestSignAndVerify(t *testing.T) {
	// Test secp256k1 curve
	t.Run("secp256k1", func(t *testing.T) {
		privKey, err := GenerateKey(Secp256k1)
		if err != nil {
			t.Fatalf("Failed to generate key: %v", err)
		}

		message := []byte("test message")
		hash := sha256.Sum256(message)

		sig, err := privKey.Sign(hash[:])
		if err != nil {
			t.Fatalf("Failed to sign: %v", err)
		}
		if sig == nil {
			t.Fatal("Signature is nil")
		}

		// Verify signature
		ecdsaPrivKey := privKey.ToECDSA()
		pubKey := &ecdsaPrivKey.PublicKey
		if !Verify(pubKey, hash[:], sig) {
			t.Fatal("Signature verification failed")
		}

		// Test with wrong hash
		wrongHash := sha256.Sum256([]byte("wrong message"))
		if Verify(pubKey, wrongHash[:], sig) {
			t.Fatal("Signature verification should fail with wrong hash")
		}
	})

	// Test P256 curve
	t.Run("P256", func(t *testing.T) {
		privKey, err := GenerateKey(P256)
		if err != nil {
			t.Fatalf("Failed to generate key: %v", err)
		}

		message := []byte("test message")
		hash := sha256.Sum256(message)

		sig, err := privKey.Sign(hash[:])
		if err != nil {
			t.Fatalf("Failed to sign: %v", err)
		}
		if sig == nil {
			t.Fatal("Signature is nil")
		}

		// Verify signature
		ecdsaPrivKey := privKey.ToECDSA()
		pubKey := &ecdsaPrivKey.PublicKey
		if !Verify(pubKey, hash[:], sig) {
			t.Fatal("Signature verification failed")
		}
	})
}

func TestSignatureSerialization(t *testing.T) {
	privKey, err := GenerateKey(Secp256k1)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	message := []byte("test message")
	hash := sha256.Sum256(message)

	sig, err := privKey.Sign(hash[:])
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	// Test Bytes serialization
	bytes := sig.Bytes()
	if len(bytes) != 64 {
		t.Fatalf("Expected 64 bytes, got %d", len(bytes))
	}

	// Test DER serialization
	der := sig.DER()
	if len(der) == 0 {
		t.Fatal("DER encoding is empty")
	}

	// Test RSV format (if supported)
	if sig.HasV() {
		rsvSig := sig.(*RSVSignature)
		rsv := rsvSig.RSV()
		if len(rsv) != 65 {
			t.Fatalf("Expected 65 bytes for RSV, got %d", len(rsv))
		}
		vrs := rsvSig.VRS()
		if len(vrs) != 65 {
			t.Fatalf("Expected 65 bytes for VRS, got %d", len(vrs))
		}
	}
}

func TestSignatureCreation(t *testing.T) {
	r := big.NewInt(12345)
	s := big.NewInt(67890)
	v := byte(1)

	// Test creating signature with V
	sigWithV := NewSignature(r, s, &v)
	if !sigWithV.HasV() {
		t.Fatal("Signature should have V value")
	}
	if sigWithV.R().Cmp(r) != 0 {
		t.Fatal("R value mismatch")
	}
	if sigWithV.S().Cmp(s) != 0 {
		t.Fatal("S value mismatch")
	}

	// Test creating signature without V
	sigWithoutV := NewSignature(r, s, nil)
	if sigWithoutV.HasV() {
		t.Fatal("Signature should not have V value")
	}
	if sigWithoutV.R().Cmp(r) != 0 {
		t.Fatal("R value mismatch")
	}
	if sigWithoutV.S().Cmp(s) != 0 {
		t.Fatal("S value mismatch")
	}
}

func TestEdgeCases(t *testing.T) {
	// Test empty message
	t.Run("empty message", func(t *testing.T) {
		privKey, err := GenerateKey(Secp256k1)
		if err != nil {
			t.Fatalf("Failed to generate key: %v", err)
		}

		emptyHash := sha256.Sum256([]byte{})
		sig, err := privKey.Sign(emptyHash[:])
		if err != nil {
			t.Fatalf("Failed to sign: %v", err)
		}

		ecdsaPrivKey := privKey.ToECDSA()
		pubKey := &ecdsaPrivKey.PublicKey
		if !Verify(pubKey, emptyHash[:], sig) {
			t.Fatal("Signature verification failed for empty message")
		}
	})

	// Test large message
	t.Run("large message", func(t *testing.T) {
		privKey, err := GenerateKey(Secp256k1)
		if err != nil {
			t.Fatalf("Failed to generate key: %v", err)
		}

		largeMessage := make([]byte, 1024*1024) // 1MB
		rand.Read(largeMessage)
		hash := sha256.Sum256(largeMessage)

		sig, err := privKey.Sign(hash[:])
		if err != nil {
			t.Fatalf("Failed to sign: %v", err)
		}

		ecdsaPrivKey := privKey.ToECDSA()
		pubKey := &ecdsaPrivKey.PublicKey
		if !Verify(pubKey, hash[:], sig) {
			t.Fatal("Signature verification failed for large message")
		}
	})
}

func TestErrorCases(t *testing.T) {
	// Test invalid private key
	t.Run("invalid private key", func(t *testing.T) {
		// Create an invalid private key with value exceeding curve order
		invalidPrivKey := &PrivateKey{
			PublicKey: ecdsa.PublicKey{
				Curve: elliptic.P256(),
				X:     big.NewInt(0),
				Y:     big.NewInt(0),
			},
			D: new(big.Int).Add(elliptic.P256().Params().N, big.NewInt(1)), // Value exceeding curve order
		}

		message := []byte("test message")
		hash := sha256.Sum256(message)

		_, err := invalidPrivKey.Sign(hash[:])
		if err == nil {
			t.Fatal("Expected error for invalid private key")
		}
	})

	// Test invalid signature verification
	t.Run("invalid signature verification", func(t *testing.T) {
		privKey, err := GenerateKey(Secp256k1)
		if err != nil {
			t.Fatalf("Failed to generate key: %v", err)
		}

		message := []byte("test message")
		hash := sha256.Sum256(message)

		sig, err := privKey.Sign(hash[:])
		if err != nil {
			t.Fatalf("Failed to sign: %v", err)
		}

		// Create invalid public key
		invalidPubKey := &ecdsa.PublicKey{
			Curve: elliptic.P256(), // Using different curve
			X:     big.NewInt(1),
			Y:     big.NewInt(1),
		}

		if Verify(invalidPubKey, hash[:], sig) {
			t.Fatal("Signature verification should fail with invalid public key")
		}
	})
}
