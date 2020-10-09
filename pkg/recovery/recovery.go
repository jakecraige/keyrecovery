package recovery

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

type RecoveryMode string

const (
	Recovery_NonceReuse RecoveryMode = "nonce-reuse"
)

func NewRecoveryMode(mode string) (RecoveryMode, error) {
	switch mode {
	case string(Recovery_NonceReuse):
		return Recovery_NonceReuse, nil
	default:
		return "", fmt.Errorf("unsupported recovery mode: %s", mode)
	}
}

type Config struct {
	curve elliptic.Curve
	sigID SignatureIdentifier
	mode  RecoveryMode
}

func NewConfig(curveID CurveIdentifier, sigID SignatureIdentifier, mode RecoveryMode) (*Config, error) {
	if !curveID.IsSupported(sigID) {
		return nil, fmt.Errorf("sig %s is not supported with curve %s", sigID, curveID)
	}

	return &Config{
		curve: curveID.Curve(),
		sigID: sigID,
		mode:  mode,
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

		sig, err := SignatureFromBytes(bytes, c.curve, format)
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
	switch c.mode {
	case Recovery_NonceReuse:
		return recoverNonceReuse(c.curve, c.sigID, signatures)

	default:
		return nil, fmt.Errorf("recovery for %s not implemented", c.mode)
	}
}
