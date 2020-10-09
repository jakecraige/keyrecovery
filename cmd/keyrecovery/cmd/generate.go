package cmd

import (
	"fmt"

	"github.com/jakecraige/keyrecovery/pkg/recovery"
	"github.com/spf13/cobra"
)

func init() { //nolint:gochecknoinits
	rootCmd.AddCommand(generateCmd)

	generateCmd.Flags().StringVarP(&curveName, "curve", "c", "P256", "Name of the elliptic curve used to generate signatures")
	generateCmd.Flags().StringVarP(&sigName, "sig-type", "s", "ECDSA-SHA256", "Identifier for the type of signature provided")
	generateCmd.Flags().StringVarP(&recoveryMode, "mode", "m", "nonce-reuse", "The algorithm to use when recovering the private key")
}

var generateCmd = &cobra.Command{
	Use:   "generate [args]",
	Short: "TODO",
	// Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		curveID, err := recovery.NewCurveIdentifier(curveName)
		if err != nil {
			return err
		}

		sigID, err := recovery.NewSignatureIdentifier(sigName)
		if err != nil {
			return err
		}

		mode, err := recovery.NewRecoveryMode(recoveryMode)
		if err != nil {
			return err
		}

		sigs, err := mode.Generate(curveID, sigID)
		if err != nil {
			return err
		}

		for _, sig := range sigs {
			fmt.Printf("%x\n", sig.Bytes())
		}

		return nil
	},
}
