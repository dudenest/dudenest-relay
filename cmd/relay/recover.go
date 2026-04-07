// recover.go — re-derive relay key from BIP39 mnemonic (used after hardware failure or key loss)
package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/dudenest/dudenest-relay/internal/keymgmt"
)

func recoverCmd() *cobra.Command {
	var mnemonic string
	cmd := &cobra.Command{
		Use:   "recover",
		Short: "Re-derive relay.env from BIP39 recovery mnemonic",
		Example: `  relay recover --mnemonic "word1 word2 word3 word4 word5 word6 word7 word8 word9 word10 word11 word12"`,
		RunE: func(cmd *cobra.Command, args []string) error { return runRecover(mnemonic) },
	}
	cmd.Flags().StringVar(&mnemonic, "mnemonic", "", "12-word BIP39 recovery mnemonic (required)")
	cmd.MarkFlagRequired("mnemonic") //nolint:errcheck
	return cmd
}

func runRecover(mnemonic string) error {
	key, err := keymgmt.MnemonicToKey(mnemonic, "")
	if err != nil {
		return fmt.Errorf("invalid mnemonic: %w", err)
	}
	envPath := filepath.Join(authConfigDir, "relay.env")
	if err := os.MkdirAll(authConfigDir, 0o700); err != nil {
		return fmt.Errorf("config dir: %w", err)
	}
	envContent := fmt.Sprintf("# DUDENEST RELAY — ENCRYPTION KEY (recovered from mnemonic)\nRELAY_KEY=%s\n", key)
	if err := os.WriteFile(envPath, []byte(envContent), 0o600); err != nil {
		return fmt.Errorf("write relay.env: %w", err)
	}
	fmt.Printf("✅ relay.env written to %s\n", envPath)
	fmt.Println("   Restart relay service: systemctl restart relay.service")
	return nil
}
