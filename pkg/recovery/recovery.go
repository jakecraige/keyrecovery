package recovery

import (
	"bufio"
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

type RecoveryMode string

const (
	Recovery_NonceReuse      RecoveryMode = "nonce-reuse"
	Recovery_NonceBiasPrefix RecoveryMode = "nonce-bias-prefix"
)

func NewRecoveryMode(mode string) (RecoveryMode, error) {
	switch mode {
	case string(Recovery_NonceReuse):
		return Recovery_NonceReuse, nil
	case string(Recovery_NonceBiasPrefix):
		return Recovery_NonceBiasPrefix, nil
	default:
		return "", fmt.Errorf("unsupported recovery mode: %s", mode)
	}
}

func (m RecoveryMode) Strategy(curveID CurveIdentifier, sigID SignatureIdentifier) (Strategy, error) {
	switch m {
	case Recovery_NonceReuse:
		return &NonceReuseStrategy{curve: curveID.Curve(), sigID: sigID}, nil

	case Recovery_NonceBiasPrefix:
		return &NonceBiasPrefixStrategy{
			curve: curveID.Curve(),
			sigID: sigID,

			// bitBias is the amount of bits that the nonce is biased by. Using a static value for now but
			// this could be made configurable in the future.
			bitBias: 80,

			// numSigs defines the number of signatures to generate so that recovery from the biased nonce
			// is possible. This is enough for down to ~30 bits of bias. This could by dynamically
			// calculated based on the bias in the future.
			numSigs: 10,
		}, nil

	default:
		return nil, fmt.Errorf("strategy not implemented")
	}
}

type Config struct {
	curveID CurveIdentifier
	sigID   SignatureIdentifier
	mode    RecoveryMode
}

func New(curveID CurveIdentifier, sigID SignatureIdentifier, mode RecoveryMode) (*Config, error) {
	if !curveID.IsSupported(sigID) {
		return nil, fmt.Errorf("sig %s is not supported with curve %s", sigID, curveID)
	}

	return &Config{
		curveID: curveID,
		sigID:   sigID,
		mode:    mode,
	}, nil
}

func (c *Config) RecoverFromFile(path string, format string) (*ecdsa.PrivateKey, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	return c.RecoverFromReader(file, format)
}

func (c *Config) RecoverFromReader(r io.Reader, format string) (*ecdsa.PrivateKey, error) {
	sigs := make([]*Signature, 0)

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		bytes, err := hex.DecodeString(scanner.Text())
		if err != nil {
			return nil, err
		}

		sig, err := SignatureFromBytes(bytes, c.curveID.Curve(), format)
		if err != nil {
			return nil, err
		}

		sigs = append(sigs, sig)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return c.Recover(sigs)
}

func (c *Config) Recover(signatures []*Signature) (*ecdsa.PrivateKey, error) {
	strat, err := c.mode.Strategy(c.curveID, c.sigID)
	if err != nil {
		return nil, err
	}

	return strat.Recover(signatures)
}

func (c *Config) Generate() ([]*Signature, error) {
	strat, err := c.mode.Strategy(c.curveID, c.sigID)
	if err != nil {
		return nil, err
	}

	return strat.Generate()
}

type Strategy interface {
	Generate() ([]*Signature, error)
	Recover(signatures []*Signature) (*ecdsa.PrivateKey, error)
}
