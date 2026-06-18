package crypto

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"math/big"
)

// TraditionalEngine implements CryptoEngine using classical cryptographic
// primitives: ECDSA (P-256) for signing and X25519 for key encapsulation.
type TraditionalEngine struct{}

// NewTraditionalEngine returns a ready-to-use TraditionalEngine.
func NewTraditionalEngine() *TraditionalEngine {
	return &TraditionalEngine{}
}

func (e *TraditionalEngine) Name() string {
	return "Traditional (X25519 + ECDSA)"
}

// GenerateAsymmetricKeys generates a P-256 ECDSA key pair used for signing.
// Returns compressed public key bytes and the raw 32-byte private scalar (D).
func (e *TraditionalEngine) GenerateAsymmetricKeys() ([]byte, []byte, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	pubBytes := elliptic.MarshalCompressed(elliptic.P256(), priv.PublicKey.X, priv.PublicKey.Y)

	// Pad D to exactly 32 bytes so reconstruction is unambiguous.
	privBytes := make([]byte, 32)
	dBytes := priv.D.Bytes()
	copy(privBytes[32-len(dBytes):], dBytes)

	return pubBytes, privBytes, nil
}

// GenerateKEMKeys generates an X25519 key pair used for the KEM/handshake.
// The returned private key bytes are 32 raw bytes suitable for Decapsulate.
func (e *TraditionalEngine) GenerateKEMKeys() (pubKey []byte, privKey []byte, err error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return priv.PublicKey().Bytes(), priv.Bytes(), nil
}

// Sign signs the SHA-256 hash of message using the provided P-256 private key
// bytes. privKey must be the 32-byte scalar produced by GenerateAsymmetricKeys.
func (e *TraditionalEngine) Sign(message []byte, privKey []byte) ([]byte, error) {
	if len(privKey) == 0 {
		return nil, errors.New("traditional: Sign: private key is empty")
	}

	// Reconstruct the full *ecdsa.PrivateKey from the scalar bytes.
	curve := elliptic.P256()
	d := new(big.Int).SetBytes(privKey)

	priv := &ecdsa.PrivateKey{
		D: d,
		PublicKey: ecdsa.PublicKey{
			Curve: curve,
		},
	}
	// Derive the public key point from the scalar so the struct is complete.
	priv.PublicKey.X, priv.PublicKey.Y = curve.ScalarBaseMult(privKey)

	hash := sha256.Sum256(message)
	return ecdsa.SignASN1(rand.Reader, priv, hash[:])
}

// Verify checks the ASN.1-encoded ECDSA signature against the SHA-256 hash of
// message using the provided compressed P-256 public key bytes.
func (e *TraditionalEngine) Verify(message []byte, signature []byte, pubKey []byte) bool {
	x, y := elliptic.UnmarshalCompressed(elliptic.P256(), pubKey)
	if x == nil {
		return false
	}
	pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
	hash := sha256.Sum256(message)
	return ecdsa.VerifyASN1(pub, hash[:], signature)
}

// Encapsulate performs an ephemeral X25519 Diffie-Hellman exchange against the
// peer's static X25519 public key. The ephemeral public key is returned as the
// "ciphertext" (sent to the peer) and the derived shared secret is returned
// for immediate use as a session key seed.
func (e *TraditionalEngine) Encapsulate(peerPubKey []byte) (ciphertext []byte, sharedSecret []byte, err error) {
	ephemeralPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	remotePub, err := ecdh.X25519().NewPublicKey(peerPubKey)
	if err != nil {
		return nil, nil, err
	}

	sharedSecret, err = ephemeralPriv.ECDH(remotePub)
	if err != nil {
		return nil, nil, err
	}

	// The ephemeral public key is the "ciphertext" the other side decapsulates.
	return ephemeralPriv.PublicKey().Bytes(), sharedSecret, nil
}

// Decapsulate recovers the shared secret from the peer's ephemeral public key
// ("ciphertext") using the local static X25519 private key bytes.
func (e *TraditionalEngine) Decapsulate(ciphertext []byte, privKey []byte) ([]byte, error) {
	localPriv, err := ecdh.X25519().NewPrivateKey(privKey)
	if err != nil {
		return nil, err
	}

	ephemeralPub, err := ecdh.X25519().NewPublicKey(ciphertext)
	if err != nil {
		return nil, err
	}

	return localPriv.ECDH(ephemeralPub)
}
