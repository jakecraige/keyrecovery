package recovery

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"math/big"
)

type NonceBiasPrefixStrategy struct {
	curve            elliptic.Curve
	sigID            SignatureIdentifier
	bitBias, numSigs int
}

func (s *NonceBiasPrefixStrategy) Recover(sigs []*Signature) (*ecdsa.PrivateKey, error) {
	params := s.curve.Params()
	intBytes := byteLen(s.curve)

	// 2**N-bitBias
	nonceBound := new(big.Int).Lsh(big.NewInt(1), uint(params.N.Int64()-int64(s.bitBias)))

	// Initialize matrix with default 0 values.
	rowColLen := len(sigs) + 1
	matrix := make([][]*big.Int, rowColLen)
	for i := range matrix {
		matrix[i] = make([]*big.Int, rowColLen)
	}

	// Initialize matrix to a state like so, computed based on the number of signatures provided.
	//   [N .  .  .]
	//   [. N  .  .]
	//   [. . B/N .]
	//   [. .  .  B]
	for i, row := range matrix[:len(matrix)-2] {
		row[i] = new(big.Int).SetBytes(params.N.Bytes()) // clone N for unique reference
	}
	noncesRow := matrix[len(matrix)-2]
	msgsRow := matrix[len(matrix)-1]
	noncesRow[rowColLen-2] = new(big.Int).Div(nonceBound, params.N)
	msgsRow[rowColLen-1] = nonceBound

	// Fill in the nonces row
	sig_n := sigs[len(sigs)-1]
	r_n := new(big.Int).SetBytes(sig_n.Sig[:intBytes])
	s_n := new(big.Int).SetBytes(sig_n.Sig[intBytes:])
	rsInv_n := mulModInv(r_n, s_n, params.N)
	for i := 0; i < len(sigs)-1; i++ {
		sig_i := sigs[i]
		r_i := new(big.Int).SetBytes(sig_i.Sig[:intBytes])
		s_i := new(big.Int).SetBytes(sig_i.Sig[intBytes:])
		rsInv_i := mulModInv(r_i, s_i, params.N)
		noncesRow[i] = rsInv_i.Sub(rsInv_i, rsInv_n)
	}

	// Fill in the messages row
	m_n := new(big.Int).SetBytes(hashBytes(s.sigID.Hash(), sig_n.Msg))
	msInv_n := mulModInv(m_n, s_n, params.N)
	for i := 0; i < len(sigs)-1; i++ {
		sig_i := sigs[i]
		m_i := new(big.Int).SetBytes(hashBytes(s.sigID.Hash(), sig_n.Msg))
		s_i := new(big.Int).SetBytes(sig_i.Sig[intBytes:])
		msInv_i := mulModInv(m_i, s_i, params.N)
		msgsRow[i] = msInv_i.Sub(msInv_i, msInv_n)
	}

	// TODO: finish implementation, need and LLL implementation which doesn't seem to exist in go,
	// so I might have to implement it to finish this up.
	panic("not implemented")
}

// Performs x*y^-1, mutating x and y and returning the result in x.
func mulModInv(x, y, n *big.Int) *big.Int {
	return x.Mul(x, y.ModInverse(y, n))
}

func (s *NonceBiasPrefixStrategy) Generate() ([]*Signature, error) {
	switch s.sigID {
	case Sig_ECDSA_SHA256:
		byteLen := byteLen(s.curve)

		key, err := ecdsa.GenerateKey(s.curve, rand.Reader)
		if err != nil {
			return nil, err
		}
		pub := serializePub(&key.PublicKey, byteLen)

		sigs := make([]*Signature, s.numSigs)
		for i := range sigs {
			k, err := rand.Int(rand.Reader, s.curve.Params().N)
			if err != nil {
				return nil, err
			}
			k.Rsh(k, uint(s.bitBias)) // introduce the bias via shifting to zero the highest bits

			m := []byte("example sig with nonce-prefix-bias")
			r, s, err := ecdsaSign(key, k, s.curve, hashBytes(s.sigID.Hash(), m))
			if err != nil {
				return nil, err
			}

			sig := make([]byte, byteLen*2)
			copy(sig, leftPad(r.Bytes(), byteLen))
			copy(sig[byteLen:], leftPad(s.Bytes(), byteLen))
			sigs[i] = &Signature{Pub: pub, Msg: m, Sig: sig}
		}

		return sigs, nil

	default:
		return nil, fmt.Errorf("prefix bias not supported for sig type")
	}
}
