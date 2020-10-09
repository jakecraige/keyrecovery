package recovery

import (
	"crypto/elliptic"
	"fmt"

	"github.com/ethereum/go-ethereum/crypto/secp256k1"
)

type CurveIdentifier string

const (
	Curve_S256 CurveIdentifier = "secp256k1"
	Curve_P256 CurveIdentifier = "P256"
	Curve_P384 CurveIdentifier = "P384"
	Curve_P521 CurveIdentifier = "P521"
)

func (c CurveIdentifier) Curve() elliptic.Curve {
	switch c {
	case Curve_S256:
		return secp256k1.S256()
	case Curve_P256:
		return elliptic.P256()
	case Curve_P384:
		return elliptic.P384()
	case Curve_P521:
		return elliptic.P521()
	}

	panic("should be unreachable")
}

func (c CurveIdentifier) IsSupported(sigID SignatureIdentifier) bool {
	switch sigID {
	case Sig_ECDSA_SHA256, Sig_ECDSA_KECCAK256:
		return c == Curve_S256 || c == Curve_P256 || c == Curve_P384
	case Sig_ECDSA_SHA512:
		return c == Curve_P521
	default:
		return false
	}
}

func NewCurveIdentifier(id string) (CurveIdentifier, error) {
	switch id {
	case string(Curve_S256):
		return Curve_S256, nil
	case string(Curve_P256):
		return Curve_P256, nil
	case string(Curve_P384):
		return Curve_P384, nil
	case string(Curve_P521):
		return Curve_P521, nil
	default:
		return "", fmt.Errorf("unsupported curve identifier: %s", id)
	}
}
