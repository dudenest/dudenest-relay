package pipeline

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/dudenest/dudenest-relay/internal/browser"
	"github.com/dudenest/dudenest-relay/internal/cloudconn/gdrive"
	"github.com/dudenest/dudenest-relay/pkg/types"
)

// LoadAllProviders scans configDir/providers and initializes all CloudProviders.
func LoadAllProviders(configDir, clientSecretPath, basePath string) ([]types.CloudProvider, error) {
	dir := filepath.Join(configDir, "providers")
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var clouds []types.CloudProvider
	seen := map[string]bool{}

	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		if !strings.HasPrefix(e.Name(), "gdrive_") {
			continue
		}

		tokenPath := filepath.Join(dir, e.Name())
		t, err := browser.LoadToken(tokenPath)
		if err != nil {
			fmt.Printf("factory: skip %s: %v\n", e.Name(), err)
			continue
		}

		if seen[t.Email] {
			continue
		}
		seen[t.Email] = true

		id := "gdrive:" + t.Email
		p, err := gdrive.New(id, tokenPath, clientSecretPath, basePath)
		if err != nil {
			fmt.Printf("factory: failed to init %s: %v\n", id, err)
			continue
		}
		clouds = append(clouds, p)
	}

	return clouds, nil
}
