package recovery

import (
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"

	"golang.org/x/crypto/sha3"
)

type SignatureIdentifier string

const (
	Sig_ECDSA_SHA256    SignatureIdentifier = "ECDSA-SHA256"
	Sig_ECDSA_SHA512    SignatureIdentifier = "ECDSA-SHA512"
	Sig_ECDSA_KECCAK256 SignatureIdentifier = "ECDSA-KECCAK256"
)

func (s SignatureIdentifier) Hash() hash.Hash {
	switch s {
	case Sig_ECDSA_SHA256:
		return sha256.New()

	case Sig_ECDSA_SHA512:
		return sha512.New()

	case Sig_ECDSA_KECCAK256:
		return sha3.NewLegacyKeccak256()

	default:
		panic("not defined")
	}
}

func NewSignatureIdentifier(id string) (SignatureIdentifier, error) {
	switch id {
	case string(Sig_ECDSA_SHA256):
		return Sig_ECDSA_SHA256, nil

	case string(Sig_ECDSA_SHA512):
		return Sig_ECDSA_SHA512, nil

	case string(Sig_ECDSA_KECCAK256):
		return Sig_ECDSA_KECCAK256, nil

	default:
		return "", fmt.Errorf("unsupported signature identifier: %s", id)
	}
}

type Signature struct {
	Pub []byte
	Sig []byte
	Msg []byte
}

func (s *Signature) Bytes() []byte {
	out := make([]byte, len(s.Pub)+len(s.Sig)+len(s.Msg))
	copy(out, s.Pub)
	copy(out[len(s.Pub):], s.Sig)
	copy(out[len(s.Pub)+len(s.Sig):], s.Msg)
	return out
}

func SignatureFromBytes(data []byte, curve elliptic.Curve, format string) (*Signature, error) {
	byteLen := byteLen(curve)

	// TODO: leverage format param
	pubBytes := data[:byteLen*2]
	sigBytes := data[byteLen*2 : byteLen*4]
	msg := data[byteLen*4:]

	return &Signature{
		Pub: pubBytes,
		Sig: sigBytes,
		Msg: msg,
	}, nil
}
