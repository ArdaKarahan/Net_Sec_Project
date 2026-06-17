package crypto

import (
	"github.com/open-quantum-safe/liboqs-go/oqs"
)

type PQCEngine struct {
	kem    oqs.KEM
	sign   oqs.SignatureScheme
}

func NewPQCEngine(kemType, signType string) (*PQCEngine, error) {
	kem, err := oqs.NewKEM(kemType)
	if err != nil {
		return nil, err
	}
	sign, err := oqs.NewSignatureScheme(signType)
	if err != nil {
		return nil, err
	}
	return &PQCEngine{kem: kem, sign: sign}, nil
}

func (p *PQCEngine) Name() string {
	return p.kem.Name()
}

// --- Key Generation ---
func (p *PQCEngine) GenerateAsymmetricKeys() (pubKey []byte, privKey []byte, err error) {
	pubKey, privKey, err = p.kem.KeyPair()
	if err != nil {
		return nil, nil, err
	}
	return pubKey, privKey, nil
}

// --- Digital Signatures ---
func (p *PQCEngine) Sign(message []byte, privKey []byte) (signature []byte, err error) {
	signature, err = p.sign.Sign(privKey, message)
	if err != nil {
		return nil, err
	}
	return signature, nil
}

func (p *PQCEngine) Verify(message []byte, signature []byte, pubKey []byte) bool {
	return p.sign.Verify(pubKey, message, signature)
}

// --- Key Encapsulation Mechanism (KEM) ---
func (p *PQCEngine) Encapsulate(peerPubKey []byte) (ciphertext []byte, sharedSecret []byte, err error) {
	ciphertext, sharedSecret, err = p.kem.Encapsulate(peerPubKey)
	if err != nil {
		return nil, nil, err
	}
	return ciphertext, sharedSecret, nil
}

func (p *PQCEngine) Decapsulate(ciphertext []byte, privKey []byte) (sharedSecret []byte, err error) {
	sharedSecret, err = p.kem.Decapsulate(ciphertext, privKey)
	if err != nil {
		return nil, err
	}
	return sharedSecret, nil
}
