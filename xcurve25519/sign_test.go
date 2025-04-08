package xcurve25519

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"testing"

	"github.com/donutnomad/blockchain-alg/internal/utils"
	"github.com/donutnomad/blockchain-alg/xed25519"
	"github.com/samber/lo"
)

func TestSign(t *testing.T) {
	randomBs := utils.MustDecodeHex("83002c6662a892b335e34909bd7c4e470b5e5259f0360ed21446de1aea320fc2a28d4c6380bebe33c7e96d29952a3a1429fab01730fffc2baf3eb20b330d8b0d")
	sig := utils.MustDecodeHex("88d90bfdfea87702451a7576bdf32d0ee724d93e3157747b021ffd3a3b25eaf59c7b8eaa896d04f7ad004b5be90e9f159877ba35b5f6e4e72d62546774bc980d")
	pri := utils.MustDecodeHex("5954870b8e419ef12c4ff2265d2c7fb81f559688a63ab59f48b7985708810e20")
	message := []byte("data to be signed")

	sig2 := Sign([32]byte(pri), message, randomBs)
	ok := bytes.Equal(sig, sig2[:])
	if !ok {
		t.Fatalf("invalid signature")
	}
}

func randBs(size int) []byte {
	var out = make([]byte, size)
	lo.Must1(io.ReadFull(rand.Reader, out[:]))
	return out
}

func TestSign2(t *testing.T) {
	message := []byte("data to be sign")
	for i := 0; i < 10000; i++ {
		var priBs = [32]byte(randBs(32))
		var pub = GenPubKey(priBs)
		var random = randBs(64)
		var sig = Sign(priBs, message, random)
		if !Verify(pub, message, sig) {
			panic("invalid signature")
		}
	}
}

func TestVerifyFailure(t *testing.T) {
	message := []byte("data to be signed")
	priKey := [32]byte(randBs(32))
	pubKey := GenPubKey(priKey)
	random := randBs(64)
	sig := Sign(priKey, message, random)

	// Test with wrong message
	if Verify(pubKey, []byte("wrong message"), sig) {
		t.Fatal("verification should fail with wrong message")
	}

	// Test with wrong signature
	wrongSig := sig
	wrongSig[0] ^= 0x01 // Flip one bit
	if Verify(pubKey, message, wrongSig) {
		t.Fatal("verification should fail with wrong signature")
	}
}

func TestDifferentMessageLengths(t *testing.T) {
	priKey := [32]byte(randBs(32))
	pubKey := GenPubKey(priKey)
	random := randBs(64)

	// Test empty message
	emptyMsg := []byte{}
	sig := Sign(priKey, emptyMsg, random)
	if !Verify(pubKey, emptyMsg, sig) {
		t.Fatal("verification failed for empty message")
	}

	// Test very long message
	longMsg := make([]byte, 1024*1024) // 1MB message
	rand.Read(longMsg)
	sig = Sign(priKey, longMsg, random)
	if !Verify(pubKey, longMsg, sig) {
		t.Fatal("verification failed for long message")
	}
}

func TestPubKeyConsistency(t *testing.T) {
	// Test that generating public key multiple times gives same result
	priKey := [32]byte(randBs(32))
	pubKey1 := GenPubKey(priKey)
	pubKey2 := GenPubKey(priKey)

	if !bytes.Equal(pubKey1[:], pubKey2[:]) {
		t.Fatal("public key generation is not consistent")
	}
}

func TestSignByEd25519Key(t *testing.T) {
	message := []byte("data to be sign")
	for i := 0; i < 100; i++ { // Increased iterations for better coverage
		publicKey, privateKey := lo.Must2(ed25519.GenerateKey(rand.Reader))
		sig := SignByEd25519(privateKey, message)
		if !VerifyByEd25519(xed25519.PublicKey(publicKey), message, sig) {
			t.Fatal("invalid signature")
		}
	}
}
