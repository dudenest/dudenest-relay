// setup.go — first-time relay key setup: generates BIP39 mnemonic → derives AES-256 key → writes relay.env
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/dudenest/dudenest-relay/internal/keymgmt"
)

func setupCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "setup",
		Short: "Generate BIP39 mnemonic and write relay.env (run once during installation)",
		RunE:  runSetup,
	}
}

func runSetup(cmd *cobra.Command, args []string) error {
	envPath := filepath.Join(authConfigDir, "relay.env")
	if _, err := os.Stat(envPath); err == nil {
		fmt.Printf("⚠️  relay.env already exists at %s\n", envPath)
		fmt.Print("    Overwrite? This will make existing encrypted files unreadable! [yes/no]: ")
		var answer string
		fmt.Scanln(&answer)
		if answer != "yes" {
			fmt.Println("Aborted.")
			return nil
		}
	}
	mnemonic, err := keymgmt.GenerateMnemonic()
	if err != nil {
		return fmt.Errorf("generate mnemonic: %w", err)
	}
	key, err := keymgmt.MnemonicToKey(mnemonic, "")
	if err != nil {
		return fmt.Errorf("derive key: %w", err)
	}
	if err := os.MkdirAll(authConfigDir, 0o700); err != nil {
		return fmt.Errorf("config dir: %w", err)
	}
	envContent := fmt.Sprintf("# DUDENEST RELAY — ENCRYPTION KEY\n# DO NOT SHARE. DO NOT COMMIT TO GIT.\n# Derived from BIP39 mnemonic via PBKDF2-HMAC-SHA512 (2048 rounds)\nRELAY_KEY=%s\n", key)
	if err := os.WriteFile(envPath, []byte(envContent), 0o600); err != nil {
		return fmt.Errorf("write relay.env: %w", err)
	}
	printMnemonic(mnemonic, envPath)
	return nil
}

func printMnemonic(mnemonic, envPath string) {
	words := strings.Fields(mnemonic)
	border := strings.Repeat("═", 60)
	fmt.Printf("\n╔%s╗\n", border)
	fmt.Printf("║  🔑  RELAY RECOVERY MNEMONIC — WRITE THIS DOWN NOW  ║\n")
	fmt.Printf("╠%s╣\n", border)
	fmt.Printf("║                                                            ║\n")
	for i, w := range words {
		fmt.Printf("║    %2d. %-10s", i+1, w)
		if (i+1)%3 == 0 {
			fmt.Printf("                         ║\n")
		}
	}
	fmt.Printf("║                                                            ║\n")
	fmt.Printf("╠%s╣\n", border)
	fmt.Printf("║  ⚠️  This mnemonic is shown ONCE and never stored on disk  ║\n")
	fmt.Printf("║  ⚠️  Without it, encrypted files CANNOT be recovered       ║\n")
	fmt.Printf("║  ✅  Derived key saved to: %-33s║\n", envPath)
	fmt.Printf("╚%s╝\n\n", border)
	fmt.Println("To recover your relay key from this mnemonic:")
	fmt.Printf("  relay recover --mnemonic \"%s\"\n\n", mnemonic)
}
