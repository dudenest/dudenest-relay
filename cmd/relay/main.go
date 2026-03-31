// Package main — dudenest-relay CLI
// Commands: upload, download, info, bench
package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/dudenest/dudenest-relay/internal/cloudconn/local"
	"github.com/dudenest/dudenest-relay/internal/crypto"
	"github.com/dudenest/dudenest-relay/internal/pipeline"
)

var (
	masterKey  string
	storePath  string
	cloudPath  string
	outputPath string
)

func main() {
	root := &cobra.Command{
		Use:   "relay",
		Short: "dudenest-relay — encrypted block storage with erasure coding",
	}
	root.PersistentFlags().StringVar(&masterKey, "key", "", "master key hex (32 bytes) or password")
	root.PersistentFlags().StringVar(&storePath, "map-store", "/tmp/dudenest-maps", "path for FileMap storage")
	root.PersistentFlags().StringVar(&cloudPath, "cloud-path", "/tmp/dudenest-blocks", "local cloud provider path (PoC)")

	root.AddCommand(uploadCmd(), downloadCmd(), infoCmd(), benchCmd())
	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

func getKey() ([]byte, error) {
	if masterKey == "" {
		return nil, fmt.Errorf("--key required")
	}
	if len(masterKey) == 64 { // hex encoded 32 bytes
		return hex.DecodeString(masterKey)
	}
	// treat as password — derive key
	key := crypto.DeriveKeyFromPassword(masterKey, "dudenest-relay-salt-v1")
	return key, nil
}

func getPipeline() (*pipeline.Pipeline, error) {
	key, err := getKey()
	if err != nil {
		return nil, err
	}
	cloud := local.New(cloudPath)
	return pipeline.New(key, cloud, storePath)
}

func uploadCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "upload <file>",
		Short: "Chunk, encrypt, erasure-code and upload a file",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := getPipeline()
			if err != nil {
				return err
			}
			start := time.Now()
			fm, err := p.Upload(args[0])
			if err != nil {
				return fmt.Errorf("upload failed: %w", err)
			}
			elapsed := time.Since(start)
			fmt.Printf("✅ Uploaded: %s\n", fm.Name)
			fmt.Printf("   File ID:  %s\n", fm.FileID)
			fmt.Printf("   Size:     %d bytes (%.1f MB)\n", fm.Size, float64(fm.Size)/1024/1024)
			fmt.Printf("   Chunks:   %d × %.0fMB\n", len(fm.Chunks), float64(fm.ChunkSize)/1024/1024)
			fmt.Printf("   Shards:   %d per chunk (6 data + 3 parity)\n", 9)
			fmt.Printf("   SHA-256:  %s\n", fm.Hash)
			fmt.Printf("   Time:     %s (%.1f MB/s)\n", elapsed, float64(fm.Size)/elapsed.Seconds()/1024/1024)
			return nil
		},
	}
}

func downloadCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "download <file-id>",
		Short: "Download, decrypt and reassemble a file",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := getPipeline()
			if err != nil {
				return err
			}
			if outputPath == "" {
				return fmt.Errorf("--output required")
			}
			start := time.Now()
			if err := p.Download(args[0], outputPath); err != nil {
				return fmt.Errorf("download failed: %w", err)
			}
			fmt.Printf("✅ Downloaded: %s (%.1fs)\n", outputPath, time.Since(start).Seconds())
			return nil
		},
	}
	cmd.Flags().StringVar(&outputPath, "output", "", "output file path")
	return cmd
}

func infoCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "info",
		Short: "Show relay configuration",
		RunE: func(cmd *cobra.Command, args []string) error {
			key, err := getKey()
			if err != nil {
				return err
			}
			fmt.Printf("dudenest-relay v0.0.1\n")
			fmt.Printf("Master key: %s...\n", hex.EncodeToString(key[:4]))
			fmt.Printf("Cloud path: %s\n", cloudPath)
			fmt.Printf("Map store:  %s\n", storePath)
			fmt.Printf("Chunk size: 8 MB\n")
			fmt.Printf("Erasure:    6+3 Reed-Solomon (tolerates 3 failures)\n")
			fmt.Printf("Crypto:     AES-256-GCM + HKDF per-block key derivation\n")
			return nil
		},
	}
}

func benchCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "bench <file>",
		Short: "Benchmark upload+download pipeline",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := getPipeline()
			if err != nil {
				return err
			}
			fmt.Printf("Benchmarking %s...\n", args[0])
			start := time.Now()
			fm, err := p.Upload(args[0])
			if err != nil {
				return err
			}
			uploadTime := time.Since(start)
			tmpOut := "/tmp/dudenest-bench-output"
			start = time.Now()
			if err := p.Download(fm.FileID, tmpOut); err != nil {
				return err
			}
			downloadTime := time.Since(start)
			os.Remove(tmpOut) //nolint:errcheck
			size := float64(fm.Size) / 1024 / 1024
			fmt.Printf("\n📊 Benchmark Results:\n")
			fmt.Printf("   File size:     %.1f MB\n", size)
			fmt.Printf("   Upload:        %s (%.1f MB/s)\n", uploadTime, size/uploadTime.Seconds())
			fmt.Printf("   Download:      %s (%.1f MB/s)\n", downloadTime, size/downloadTime.Seconds())
			fmt.Printf("   Chunks:        %d\n", len(fm.Chunks))
			fmt.Printf("   Shards total:  %d (9 per chunk)\n", len(fm.Chunks)*9)
			return nil
		},
	}
}
