package recovery

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"math/big"
)

type NonceReuseStrategy struct {
	curve elliptic.Curve
	sigID SignatureIdentifier
}

func (s *NonceReuseStrategy) Recover(signatures []*Signature) (*ecdsa.PrivateKey, error) {
	if len(signatures) < 2 {
		return nil, fmt.Errorf("must have at least two signatures for nonce reuse")
	}
	curve := s.curve

	switch s.sigID {
	case Sig_ECDSA_SHA256, Sig_ECDSA_SHA512, Sig_ECDSA_KECCAK256:
		byteLen := byteLen(curve)
		n := curve.Params().N

		sig1, sig2 := signatures[0], signatures[1]
		z1 := new(big.Int).SetBytes(hashBytes(s.sigID.Hash(), sig1.Msg))
		r1 := new(big.Int).SetBytes(sig1.Sig[:byteLen])
		s1 := new(big.Int).SetBytes(sig1.Sig[byteLen:])
		z2 := new(big.Int).SetBytes(hashBytes(s.sigID.Hash(), sig2.Msg))
		r2 := new(big.Int).SetBytes(sig2.Sig[:byteLen])
		s2 := new(big.Int).SetBytes(sig2.Sig[byteLen:])

		if r1.Cmp(r2) != 0 {
			return nil, fmt.Errorf("signatures had different r values, nonce not reused")
		}

		// k = z1-z2 / s1-s2
		zDiff := new(big.Int).Sub(z1, z2)
		sDiff := new(big.Int).Sub(s1, s2)
		sDiffInv := new(big.Int).ModInverse(sDiff, n)
		if sDiffInv == nil {
			panic("no mod inverse found")
		}
		k := new(big.Int).Mul(zDiff, sDiffInv)
		k.Mod(k, n)

		// x = sk - z / r
		skSubZ := new(big.Int).Sub(new(big.Int).Mul(s1, k), z1)
		rInv := new(big.Int).ModInverse(r1, n)
		if sDiffInv == nil {
			panic("no r mod inverse found")
		}
		x := new(big.Int).Mul(skSubZ, rInv)
		x.Mod(x, n)

		pubX, pubY := curve.ScalarBaseMult(x.Bytes())
		pub := ecdsa.PublicKey{Curve: curve, X: pubX, Y: pubY}
		priv := &ecdsa.PrivateKey{PublicKey: pub, D: x}

		if !bytes.Equal(sig1.Pub, serializePub(&pub, byteLen)) {
			return nil, fmt.Errorf("failed to recover private key")
		}

		return priv, nil

	default:
		return nil, fmt.Errorf("nonce reuse recovery for %s not implemented", s.sigID)
	}
}

func (s *NonceReuseStrategy) Generate() ([]*Signature, error) {
	switch s.sigID {
	case Sig_ECDSA_SHA256, Sig_ECDSA_SHA512, Sig_ECDSA_KECCAK256:
		byteLen := byteLen(s.curve)

		key, err := ecdsa.GenerateKey(s.curve, rand.Reader)
		if err != nil {
			return nil, err
		}
		pub := serializePub(&key.PublicKey, byteLen)

		nonce := big.NewInt(1337)
		m1 := []byte("example nonce-reuse sig #1")
		r1, s1, err := ecdsaSign(key, nonce, s.curve, hashBytes(s.sigID.Hash(), m1))
		if err != nil {
			return nil, err
		}

		sig1 := make([]byte, byteLen*2)
		copy(sig1, leftPad(r1.Bytes(), byteLen))
		copy(sig1[byteLen:], leftPad(s1.Bytes(), byteLen))

		m2 := []byte("example nonce-reuse sig #2")
		r2, s2, err := ecdsaSign(key, nonce, s.curve, hashBytes(s.sigID.Hash(), m2))
		if err != nil {
			return nil, err
		}

		sig2 := make([]byte, byteLen*2)
		copy(sig2, leftPad(r2.Bytes(), byteLen))
		copy(sig2[byteLen:], leftPad(s2.Bytes(), byteLen))

		sigs := make([]*Signature, 2)
		sigs[0] = &Signature{Pub: pub, Msg: m1, Sig: sig1}
		sigs[1] = &Signature{Pub: pub, Msg: m2, Sig: sig2}

		return sigs, nil

	default:
		return nil, fmt.Errorf("gen nonce reuse not supported for sig type")
	}
}
