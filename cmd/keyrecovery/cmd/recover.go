package cmd

import (
	"crypto/ecdsa"
	"fmt"
	"os"

	"github.com/jakecraige/keyrecovery/pkg/recovery"
	"github.com/spf13/cobra"
)

var (
	curveName    string
	sigName      string
	sigFormat    string
	recoveryMode string
	inputPath    string
)

func init() { //nolint:gochecknoinits
	rootCmd.AddCommand(recoverCmd)

	recoverCmd.Flags().StringVarP(&curveName, "curve", "c", "P256", "Name of the elliptic curve used to generate signatures")
	recoverCmd.Flags().StringVarP(&sigName, "sig-type", "s", "ECDSA-SHA256", "Identifier for the type of signature provided")
	recoverCmd.Flags().StringVarP(&recoveryMode, "mode", "m", "nonce-reuse", "The algorithm to use when recovering the private key")
	recoverCmd.Flags().StringVarP(&inputPath, "input", "i", "", "Path to file a with newline separated signatures")
}

var recoverCmd = &cobra.Command{
	Use:   "recover",
	Short: "TODO",
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

		conf, err := recovery.New(curveID, sigID, mode)
		if err != nil {
			return err
		}

		var priv *ecdsa.PrivateKey
		if inputPath != "" {
			priv, err = conf.RecoverFromFile(inputPath, "r||s")
		} else {
			priv, err = conf.RecoverFromReader(os.Stdin, "r||s")
		}
		if err != nil {
			return err
		}

		fmt.Println("Recovered private key:")
		fmt.Printf("   pub: %x%x\n", priv.PublicKey.X, priv.PublicKey.Y)
		fmt.Printf("  priv: %x\n", priv.D)

		return nil
	},
}
