package recovery_test

import (
	"fmt"
	"testing"

	"github.com/jakecraige/keyrecovery/pkg/recovery"
)

func TestGenerateAndRecover(t *testing.T) {
	var tests = []struct {
		curveID recovery.CurveIdentifier
		sigID   recovery.SignatureIdentifier
		mode    recovery.RecoveryMode
	}{
		{recovery.Curve_S256, recovery.Sig_ECDSA_SHA256, recovery.Recovery_NonceReuse},
		{recovery.Curve_S256, recovery.Sig_ECDSA_KECCAK256, recovery.Recovery_NonceReuse},

		{recovery.Curve_P256, recovery.Sig_ECDSA_SHA256, recovery.Recovery_NonceReuse},
		{recovery.Curve_P256, recovery.Sig_ECDSA_KECCAK256, recovery.Recovery_NonceReuse},

		{recovery.Curve_P384, recovery.Sig_ECDSA_SHA256, recovery.Recovery_NonceReuse},
		{recovery.Curve_P384, recovery.Sig_ECDSA_KECCAK256, recovery.Recovery_NonceReuse},

		{recovery.Curve_P521, recovery.Sig_ECDSA_SHA512, recovery.Recovery_NonceReuse},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s | %s | %s", tt.curveID, tt.sigID, tt.mode), func(t *testing.T) {
			sigs, err := tt.mode.Generate(tt.curveID, tt.sigID)
			if err != nil {
				t.Errorf("generating sigs: %v", err)
				return
			}

			conf, err := recovery.NewConfig(tt.curveID, tt.sigID, tt.mode)
			if err != nil {
				t.Errorf("initializing config: %v", err)
				return
			}

			_, err = conf.Recover(sigs)
			if err != nil {
				t.Errorf("recovering key: %v", err)
				return
			}
		})
	}
}
