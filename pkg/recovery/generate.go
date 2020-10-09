package recovery

import (
	"fmt"
)

func (m RecoveryMode) Generate(curveID CurveIdentifier, sigID SignatureIdentifier) ([]*Signature, error) {
	if !curveID.IsSupported(sigID) {
		return nil, fmt.Errorf("sig %s is not supported with curve %s", sigID, curveID)
	}

	switch m {
	case Recovery_NonceReuse:
		return genNonceReuseSignatures(curveID.Curve(), sigID)
	}

	panic("should be unreachable")
}
