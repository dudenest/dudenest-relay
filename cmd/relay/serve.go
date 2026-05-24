// serve.go — combined HTTP server: file API + browser auth API.
// relay serve --key <key> --provider gdrive --gdrive-token <path> --listen 0.0.0.0:8086
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/oauth2"

	"github.com/dudenest/dudenest-relay/internal/account"
	"github.com/dudenest/dudenest-relay/internal/auth"
	"github.com/dudenest/dudenest-relay/internal/backup"
	"github.com/dudenest/dudenest-relay/internal/blockmap"
	"github.com/dudenest/dudenest-relay/internal/browser"
	"github.com/dudenest/dudenest-relay/internal/config"
	"github.com/dudenest/dudenest-relay/internal/index"
	"github.com/dudenest/dudenest-relay/internal/pipeline"
	"github.com/dudenest/dudenest-relay/internal/register"
	"github.com/dudenest/dudenest-relay/internal/scan"
	"github.com/dudenest/dudenest-relay/internal/relaytoken"
	"github.com/dudenest/dudenest-relay/internal/thumbnail"
	"github.com/dudenest/dudenest-relay/internal/ws"
	"github.com/dudenest/dudenest-relay/pkg/types"
)

var (
	serveListen      string
	relayConfigPath  string
)

func serveCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start combined HTTP server: file API + browser auth API",
		RunE:  runServe,
	}
	home, _ := os.UserHomeDir()
	cmd.Flags().StringVar(&serveListen, "listen", "", "HTTP listen address (overrides config; default: 0.0.0.0:8086)")
	cmd.Flags().StringVar(&authClientSecret, "client-secret", filepath.Join(home, ".config/dudenest/gdrive_client_secret.json"), "Path to Google OAuth2 client_secret.json")
	cmd.Flags().StringVar(&authConfigDir, "config-dir", filepath.Join(home, ".config/dudenest"), "Path to dudenest config directory")
	cmd.Flags().StringVar(&authDisplay, "display", "", "X display for Chromium (TigerVNC); overrides config")
	return cmd
}

// degradedServerWithAuth runs in standby: /files returns 503, but /auth/* and /ws stay active
// so users can re-authorize cloud providers without restarting the relay.
// /health returns 200 (degraded) so HAProxy keeps the node in rotation.
// tryReg is called on /files requests even in standby so JWT-based registration fires regardless of cloud auth state.
//
// When reload receives a value (set by wsHub.SetOnAuthDone in runServe), the HTTP server is
// gracefully shut down and the function returns nil — the outer loop then retries getPipeline()
// and upgrades to the full server WITHOUT a process restart (no systemd cycle, no Flutter disconnect storm).
// If ListenAndServe fails for any other reason, that error is returned instead.
func degradedServerWithAuth(listen, reason, configDir string, authSrv interface{ RegisterRoutes(*http.ServeMux) }, wsHub http.Handler, tryReg func(string), reload <-chan struct{}) error {
	log.Printf("⚠️  relay: entering standby mode — %s", reason)
	log.Printf("⚠️  relay: /files=503, /auth active — re-authorize via Flutter app")
	tickerCtx, tickerCancel := context.WithCancel(context.Background())
	defer tickerCancel()
	go func() { // periodic reminder, stops when the standby server exits
		t := time.NewTicker(5 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-tickerCtx.Done(): return
			case <-t.C: log.Printf("⚠️  relay: STANDBY (%s) — use /auth/url to re-authorize", reason)
			}
		}
	}()
	standbyFile := func(w http.ResponseWriter, r *http.Request) { // validate JWT + trigger registration even in standby
		if tryReg != nil { tryReg(r.Header.Get("Authorization")) }
		jsonErr(w, "relay in standby: "+reason, http.StatusServiceUnavailable)
	}
	mux := http.NewServeMux()
	authSrv.RegisterRoutes(mux) // /auth/* active even in standby — user can add/re-auth providers
	mux.Handle("/ws", wsHub)
	mux.HandleFunc("/relay/bootstrap", makeBootstrapHandler(configDir)) // ZT: receive creds even in standby
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "degraded", "reason": reason}) //nolint:errcheck
	})
	mux.HandleFunc("/files", standbyFile)
	mux.HandleFunc("/files/", standbyFile)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { jsonErr(w, "relay in standby: "+reason, http.StatusServiceUnavailable) })
	srv := &http.Server{Addr: listen, Handler: corsMiddleware(mux)}
	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe() }()
	log.Printf("⚠️  relay: standby server with auth listening on %s", listen)
	select {
	case err := <-errCh:
		if err == http.ErrServerClosed { return nil }
		return err
	case <-reload:
		log.Printf("✅ relay: standby reload triggered (auth_done event) — shutting down to re-init pipeline")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx) //nolint:errcheck
		return nil // signal to caller: retry getPipeline()
	}
}

func runServe(cmd *cobra.Command, args []string) error {
	cfg, err := config.Load(relayConfigPath) // load config first — CLI flags override below
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	if serveListen != "" { cfg.Server.Listen = serveListen }         // --listen overrides config
	if authDisplay != "" { cfg.Server.Display = authDisplay }        // --display overrides config
	// --client-secret (browser auth flow) and --gdrive-secret (provider token refresh in getClouds()) refer to the SAME OAuth client_secret.json file.
	// Historically declared as two separate flags with different defaults; systemd units only pass --client-secret, so getClouds() was reading the stale --gdrive-secret default (/root/.config/dudenest/...) which doesn't exist on installs that use /etc/dudenest. Sync them here so provider init can find the file.
	if gdriveSecretPath != authClientSecret { gdriveSecretPath = authClientSecret }
	cs, err := browser.LoadClientSecret(authClientSecret) // load auth config before pipeline — needed for standby mode too
	if err != nil {
		return fmt.Errorf("load client_secret: %w", err)
	}
	cfg2 := browser.BuildOAuthConfig(cs, browser.CallbackURL(cfg.OAuth.CallbackPort))
	var webCfg *oauth2.Config // web client for cfg.OAuth.WebRedirectURL callbacks (Flutter web)
	if id, secret := os.Getenv("GDRIVE_WEB_CLIENT_ID"), os.Getenv("GDRIVE_WEB_CLIENT_SECRET"); id != "" && secret != "" {
		webCfg = browser.BuildWebOAuthConfig(id, secret, cfg.OAuth.WebRedirectURL)
		fmt.Println("relay serve: web OAuth client loaded (GDRIVE_WEB_CLIENT_ID)")
	}
	register.LoadJWTSecret(authConfigDir)         // ZT bootstrap: restore jwt_secret from jwt_secret.txt if present
	maybeAnnounce(authConfigDir, cfg.Backup.URL)  // ZT provisioning: announce to hub if no creds and ZT_ANNOUNCE=true
	wsHub := ws.NewHub()
	bm := blockmap.New(storePath) // blockmap for file_count in /auth/providers
	authSrv := browser.NewServer(cfg.Server.Display, cfg.Server.Listen, browser.BuildAuthURL(cfg2), cfg2, webCfg, authConfigDir, wsHub, bm, cfg.OAuth.CallbackPort, cfg.NoVNC.BackendAddr, cfg.SessionTimeout())
	// tryReg: JWT-based registration trigger, created before getPipeline() so it fires even in standby.
	// Validates Bearer token, extracts user_id from claims, registers relay with backup (saves relay_creds.json).
	// Does not need pipeline/fileServer — only configDir + backupURL.
	var standbyRegOnce sync.Once
	tryReg := func(authHeader string) {
		if !strings.HasPrefix(authHeader, "Bearer ") { return }
		token := strings.TrimPrefix(authHeader, "Bearer ")
		claims, err := auth.ValidateJWT(token)
		if err != nil || claims == nil || claims.Sub == "" { return }
		go standbyRegOnce.Do(func() {
			creds2, err2 := register.RegisterOnceWithUserID(authConfigDir, claims.Sub, cfg.Backup.URL, cfg.Backup.PublicURL)
			if err2 != nil {
				log.Printf("⚠️  standby register: %v", err2)
				return
			}
			if creds2 != nil { // set env so backup.New() can read credentials
				os.Setenv("RELAY_ID", creds2.RelayID)         //nolint:errcheck
				os.Setenv("RELAY_SECRET", creds2.RelaySecret) //nolint:errcheck
			}
			log.Printf("✅ standby register: relay registered with backup (user=%s relay_url=%s)", claims.Sub, cfg.Backup.PublicURL)
			key, _ := getKey() // start ping loop even in standby — updates last_seen_at + relay_version
			if bc := backup.New(key, authConfigDir, cfg.Backup.URL, cfg.Debounce(), Version); bc != nil {
				bc.StartPingLoop(30 * time.Second) // s313 Phase 0: 30s default; hub adapts to 3s during release burst window via next_ping_seconds
				log.Printf("✅ standby: ping loop started (version=%s)", Version)
			}
		})
	}
	// Standby loop: if pipeline init fails because no/expired cloud providers, run standby HTTP server
	// (which keeps /auth/* live for the user to add a provider via the Flutter app). When the auth_done
	// WebSocket event fires (wsHub.SetOnAuthDone callback registered BEFORE getPipeline to avoid a tiny
	// race where a token is saved between getPipeline failure and callback registration), the standby
	// server shuts down and we retry getPipeline(). Successful init falls through to the full server
	// below — no process restart, no Flutter disconnect storm. Pre-v0.9.1 behavior required a manual
	// systemctl restart at this point.
	reload := make(chan struct{}, 1)
	wsHub.SetOnAuthDone(func() { select { case reload <- struct{}{}: default: } })
	var p *pipeline.Pipeline
	for {
		p, err = getPipeline()
		if err == nil { break }
		if !isCredentialError(err) { return fmt.Errorf("pipeline init: %w", err) }
		select { case <-reload: default: } // drain stale signal so we wait fresh on the next standby cycle
		if serr := degradedServerWithAuth(cfg.Server.Listen, fmt.Sprintf("pipeline init: %v", err), authConfigDir, authSrv, wsHub, tryReg, reload); serr != nil {
			return serr
		}
		log.Printf("✅ relay: exiting standby — re-initializing pipeline with newly authorized provider")
	}
	wsHub.SetOnAuthDone(nil) // entering full-server mode — full server below re-sets a different callback (scan-engine trigger), so this clears the standby loop callback first

	// Phase α (s313+): attach account.Manager so uploadReplica picks targets via SelectReplicas
	// (policy-driven Priority/FreeBytes/Diversity) instead of the legacy "first 2 in slice".
	// First-time bootstrap: if accounts.json is empty but providers/ has entries, auto-create
	// CloudAccount records (first → PrimaryWrite, rest → ReplicaWrite, Priority = filesystem order).
	// User can then drag-reorder priorities in the UI (Phase β: admin endpoints + Flutter).
	if accMgr, err := account.New(authConfigDir); err != nil {
		log.Printf("⚠️  account.Manager init failed (falling back to legacy upload selection): %v", err)
	} else {
		if len(accMgr.Accounts()) == 0 {
			// Bootstrap from currently-loaded providers. p.clouds is set inside the pipeline;
			// we rebuild the ID list here via getClouds() (same source) to avoid exposing internals.
			if clouds, cErr := getClouds(); cErr == nil {
				ids := make([]string, 0, len(clouds))
				for _, c := range clouds {
					ids = append(ids, c.ID())
				}
				if n, bErr := accMgr.BootstrapFromProviders(ids); bErr != nil {
					log.Printf("⚠️  account bootstrap: %v", bErr)
				} else if n > 0 {
					log.Printf("✅ account bootstrap: created %d CloudAccount records from existing providers (edit priorities in Settings → Cloud Accounts)", n)
				}
			}
		}
		p.SetAccountManager(accMgr)
		log.Printf("✅ account.Manager attached: %d accounts, replication_factor=%d, diversity=%v",
			len(accMgr.ActiveAccounts()), accMgr.Policy().ReplicationFactor, accMgr.Policy().DiversityRequired)

		// F1 sha-256 dedup index — bootstrap from existing FileMaps so dedup works on day 1 after deploy.
		// Index file lives next to accounts.json. Load tries to read existing; on missing/corrupt we
		// rebuild from FileMaps. Inserting fm.LogicalAlias="" (canonical) and !="" (alias) is handled
		// by BootstrapFromList. After this, p.SetIndex makes Upload short-circuit on duplicate hashes.
		shaIdx := index.New(authConfigDir)
		if err := shaIdx.Load(); err != nil { log.Printf("⚠️  sha_index load: %v (rebuilding from FileMaps)", err) }
		if maps, err := p.ListFiles(); err == nil {
			boot := make([]struct{ FileID, Hash string; IsAlias bool }, 0, len(maps))
			for _, fm := range maps {
				boot = append(boot, struct{ FileID, Hash string; IsAlias bool }{fm.FileID, fm.Hash, fm.LogicalAlias != ""})
			}
			if err := shaIdx.BootstrapFromList(boot); err != nil { log.Printf("⚠️  sha_index bootstrap: %v", err) }
		}
		p.SetIndex(shaIdx)
		hashCount, entryCount, aliasCount := shaIdx.Stats()
		log.Printf("✅ sha_index attached: %d unique hashes, %d entries (%d aliases) — F1 dedup active", hashCount, entryCount, aliasCount)

		// Phase β: start quota polling + ReconcileRoles in background. Both honor cancellation
		// via a server-lifetime context (the relay process exit terminates them).
		bgCtx, _ := context.WithCancel(context.Background())
		// provLookup translates CloudAccount → CloudProvider for the polling loop.
		// Defined inline so we don't expose pipeline internals to internal/account.
		provLookup := func(a *types.CloudAccount) types.CloudProvider {
			want := a.Provider + ":" + a.Email
			cs, _ := getClouds() // cheap — getClouds caches inside factory
			for _, c := range cs {
				if c.ID() == want {
					return c
				}
			}
			return nil
		}
		accMgr.StartQuotaPollLoop(bgCtx, provLookup)
		accMgr.StartReconcileLoop(bgCtx)
		// Phase γ drain worker: scans for Role=Drain accounts and migrates their shards to other
		// active accounts. 2-min sweep cadence. Honors cfg.DrainMaxConcurrentMigrations and
		// cfg.DrainBandwidthLimitMBPerSec. Pipeline implements PipelineDrainer interface via
		// ListFiles + GetFileMap + SaveFileMap + CloudByID — all methods that already existed
		// or were added in this commit for exactly this purpose.
		globalDrainState = account.NewDrainState()
		accMgr.StartDrainLoop(bgCtx, p, globalDrainState, 2*time.Minute)
		// Phase γ continue: age-based rotation worker. Daily sweep migrates files older than
		// cfg.AgeRotationDays from PrimaryWrite/ReplicaWrite accounts to ColdArchive accounts.
		// No-op until operator sets cfg.AgeBasedRotation=true + adds at least one Role=ColdArchive.
		// Reuses migrateOneShard from drain — same atomic download+upload+rewrite+persist semantics.
		accMgr.StartAgeRotationLoop(bgCtx, p, 24*time.Hour)
		log.Printf("✅ account.Manager: quota poll + reconcile + drain + age-rotation loops started (interval=%dm, soft_cap=%d%%, hard_cap=%d%%, drain_max_concurrent=%d, age_rotation_enabled=%v age_rotation_days=%d)",
			accMgr.Policy().QuotaCheckIntervalMin, accMgr.Policy().SoftCapDefaultPct, accMgr.Policy().HardCapDefaultPct, accMgr.Policy().DrainMaxConcurrentMigrations,
			accMgr.Policy().AgeBasedRotation, accMgr.Policy().AgeRotationDays)

		// Phase β admin REST endpoints (wired in full-server section below via mux registration).
		// Stashed in package var so the route registration in full-server picks them up.
		// (We can't register here because mux doesn't exist yet — it's built later in serve.go.)
		globalAdminAccounts = &accountAdmin{mgr: accMgr, provLookup: provLookup}
	}

	// P5a proactive backfill: walk blockmap, fill in missing CloudIDs from path → Drive file ID.
	// Background goroutine so it doesn't block server start. Idempotent — safe even if run while
	// users are uploading. Per user decision 2026-05-20: proactive (not lazy) so all legacy
	// FileMaps migrate within a few minutes of v0.17.0 deploy, not over weeks of natural access.
	go func() {
		log.Printf("✅ P5a: starting CloudID backfill pass over blockmap…")
		stats, bfErr := p.BackfillCloudIDs()
		if bfErr != nil { log.Printf("⚠️  P5a backfill: %v", bfErr); return }
		log.Printf("✅ P5a backfill done: scanned=%d backfilled=%d skipped=%d errors=%d", stats.Scanned, stats.Backfilled, stats.Skipped, stats.Errors)
	}()
	tc, err := thumbnail.NewCache(authConfigDir)
	if err != nil {
		return fmt.Errorf("thumbnail cache: %w", err)
	}
	metaDir := filepath.Join(authConfigDir, "meta")
	if err2 := os.MkdirAll(metaDir, 0o750); err2 != nil {
		return fmt.Errorf("meta dir: %w", err2)
	}
	go func() { // non-blocking: install ffmpeg in background at startup
		if err2 := thumbnail.EnsureFFmpeg(); err2 != nil {
			log.Printf("⚠️  ffmpeg: %v", err2)
		}
	}()
	key, _ := getKey() // key already validated in getPipeline(), safe to ignore error here
	var ownerFromCreds string // Layer 2: relay owner known at startup if relay was previously registered
	if creds, err2 := register.EnsureRegistered(authConfigDir, cfg.Backup.URL, cfg.Backup.PublicURL); err2 != nil { // auto-register with backup on first start
		log.Printf("⚠️  register: %v (backup disabled)", err2)
	} else if creds != nil {
		os.Setenv("RELAY_ID", creds.RelayID)         //nolint:errcheck
		os.Setenv("RELAY_SECRET", creds.RelaySecret) //nolint:errcheck
		ownerFromCreds = creds.UserID                // may be empty for old relay_creds.json (will be set on first request)
	}
	bc := backup.New(key, authConfigDir, cfg.Backup.URL, cfg.Debounce(), Version) // nil if URL/RELAY_ID/RELAY_SECRET not set
	if bc != nil {
		bc.StartPingLoop(30 * time.Second) // s313 Phase 0: 30s default; hub adapts to 3s during release burst window via next_ping_seconds // keep last_seen_at current
		// Guard (s313): empty RELAY_PUBLIC_URL means "trust the hub" — auto-provisioned relays (relay-<8hex>.dudenest.com)
		// must not have their CRDB relay_url overwritten on every restart. Only legacy relay-poc1 sets this env explicitly.
		if cfg.Backup.PublicURL != "" {
			if err2 := bc.UpdateURL(cfg.Backup.PublicURL); err2 != nil { // sync relay_url in CRDB at every startup
				log.Printf("⚠️  backup: update-url: %v", err2)
			}
		}
		if ownerFromCreds != "" { // sync user_id in CRDB — fixes old relays that had user_id in file but not CRDB
			if err2 := bc.UpdateUserID(ownerFromCreds); err2 != nil {
				log.Printf("⚠️  backup: update-user-id: %v", err2)
			}
		}
	}
	if maps, err2 := p.ListFiles(); err2 == nil && len(maps) == 0 { // startup recovery: restore if no local files
		if restored, err3 := bc.Restore(); err3 != nil {
			log.Printf("⚠️  startup restore: %v", err3)
		} else if restored {
			log.Printf("✅ startup restore: file maps + provider tokens restored from backup")
		}
	}
	mux := http.NewServeMux()
	authSrv.RegisterRoutes(mux)
	mux.Handle("/ws", wsHub) // WebSocket: Flutter connects for relay→Flutter auth requests
	fs := &fileServer{p: p, thumbCache: tc, backupClient: bc, maxUploadBytes: cfg.MaxUploadBytes(), metaDir: metaDir}
	lr := &lazyRegistrar{configDir: authConfigDir, masterKey: key, fs: fs, backupURL: cfg.Backup.URL, publicURL: cfg.Backup.PublicURL, debounce: cfg.Debounce()}
	if ownerFromCreds != "" { lr.setOwner(ownerFromCreds) } // preload owner from creds (set before ListenAndServe, no races)
	mux.HandleFunc("/relay/bootstrap", makeBootstrapHandler(authConfigDir)) // ZT provisioner delivers creds via ZT network
	mux.HandleFunc("/files", requireAuthWithReg(lr, fs.handleList))
	mux.HandleFunc("/files/", requireAuthWithReg(lr, fs.handleFile))
	mux.HandleFunc("/admin/version", requireAuthWithReg(lr, fs.handleAdminVersion)) // Flutter Update screen — read current + latest release info
	mux.HandleFunc("/admin/update", requireAuthWithReg(lr, fs.handleAdminUpdate))   // Flutter Update screen — trigger immediate self-update + restart
	// Phase β: account/policy admin endpoints (CRUD via Flutter Settings → Cloud Accounts).
	// Same auth wrapper as /files — only the paired user's Flutter can mutate.
	if globalAdminAccounts != nil {
		globalAdminAccounts.register(mux, func(h http.HandlerFunc) http.HandlerFunc { return requireAuthWithReg(lr, h) })
	}
	// P5c scan engine — Flutter Settings → Sync Status surface
	getCloudsLive := func() []types.CloudProvider { cs, _ := getClouds(); return cs }
	scanner, scErr := scan.New(p, getCloudsLive, filepath.Join(authConfigDir, "scan"))
	if scErr != nil { log.Printf("⚠️  scan engine init: %v", scErr) }
	if scanner != nil {
		sh := &scanHandlers{scanner: scanner}
		mux.HandleFunc("/admin/scan/status", requireAuthWithReg(lr, sh.handleStatus))
		mux.HandleFunc("/admin/scan/start",  requireAuthWithReg(lr, sh.handleStart))
		mux.HandleFunc("/admin/scan/pause",  requireAuthWithReg(lr, sh.handlePause))
		mux.HandleFunc("/admin/scan/config", requireAuthWithReg(lr, sh.handleConfig))
		// auth_done → kick scan for every currently-loaded provider (newly authorized one is among them)
		wsHub.SetOnAuthDone(func() {
			for _, cp := range getCloudsLive() {
				go func(pid string) {
					if _, err := scanner.Start(pid); err != nil { log.Printf("scan auto-start %s: %v", pid, err) }
				}(cp.ID())
			}
		})
		// 24h auto-rescan loop (configurable in <configDir>/scan/config.json — default enabled)
		go scanner.AutoRescanLoop(make(chan struct{}))
	}
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) }) //nolint:errcheck
	fmt.Printf("relay serve listening on %s (provider: %s, ws: /ws)\n", cfg.Server.Listen, provider)
	return http.ListenAndServe(cfg.Server.Listen, corsMiddleware(mux))
}

// fileServer handles /files/* endpoints using the pipeline.
type fileServer struct {
	p interface {
		Upload(filePath string, strategy string) (*types.FileMap, error)
		Download(fileID, outputPath string) error
		ListFiles() ([]*types.FileMap, error)
		GetFileMap(fileID string) (*types.FileMap, error)
		DeleteFile(fileID string) error
		MoveFile(fileID, newDir string) error  // P5b: re-bucket a file when its TakenAtOverride changes; no data transfer
		AccountManager() *account.Manager      // Phase α (v0.17.2+): may return nil for CLI/test paths; handleMeta uses it to read PathRoot policy when computing MoveFile destination directory
	}
	thumbCache     *thumbnail.Cache
	backupMu       sync.RWMutex
	backupClient   *backup.Client // nil = backup disabled; may be set lazily after JWT registration
	maxUploadBytes int64          // max multipart upload size (from config)
	metaDir        string         // directory for per-file meta.json (favorites, albums, captions)
}

// fileMeta stores user-editable metadata per file (favorites, albums, location, caption, date override).
type fileMeta struct {
	Favorite bool     `json:"favorite,omitempty"`
	Albums   []string `json:"albums,omitempty"`
	Location string   `json:"location,omitempty"`
	Caption  string   `json:"caption,omitempty"`
	// P5b: user-overridable effective date for date-bucketing. When set, the scan/upload code
	// uses this instead of EXIF/mtime. On PATCH, handleMeta triggers an automatic MoveByID to
	// re-bucket the file into the new YYYY/MM folder. CloudID stays the same after the move.
	// ISO-8601 UTC format; "" means "use derived date" (EXIF → mtime → upload-time fallback).
	TakenAtOverride string `json:"taken_at_override,omitempty"`
}

func (fs *fileServer) backup() *backup.Client {
	fs.backupMu.RLock()
	defer fs.backupMu.RUnlock()
	return fs.backupClient
}
func (fs *fileServer) setBackup(bc *backup.Client) {
	fs.backupMu.Lock()
	fs.backupClient = bc
	fs.backupMu.Unlock()
}

// lazyRegistrar triggers relay registration on first valid JWT request.
// Eliminates the need for RELAY_USER_ID env var — user ID is extracted from JWT claims.
type lazyRegistrar struct {
	once        sync.Once
	mu          sync.RWMutex
	ownerUserID string        // relay owner's JWT sub — set once (startup or first request), never changes
	configDir   string
	masterKey   []byte
	fs          *fileServer
	backupURL   string        // from config — used for registration and backup client init
	publicURL   string        // from config — public HTTPS URL of this relay, sent during registration for Flutter routing
	debounce    time.Duration // from config — used for backup client init
}

func (lr *lazyRegistrar) getOwner() string {
	lr.mu.RLock()
	defer lr.mu.RUnlock()
	return lr.ownerUserID
}
func (lr *lazyRegistrar) setOwner(userID string) {
	lr.mu.Lock()
	lr.ownerUserID = userID
	lr.mu.Unlock()
}

func (lr *lazyRegistrar) tryRegister(userID string) {
	lr.once.Do(func() {
		creds, err := register.RegisterOnceWithUserID(lr.configDir, userID, lr.backupURL, lr.publicURL)
		if err != nil {
			log.Printf("⚠️  lazy register: %v (backup disabled)", err)
			return
		}
		if creds == nil { return }
		os.Setenv("RELAY_ID", creds.RelayID)         //nolint:errcheck
		os.Setenv("RELAY_SECRET", creds.RelaySecret) //nolint:errcheck
		// Layer 2: set owner — from saved creds (new format) or from current JWT (old relay_creds.json without user_id)
		ownerID := creds.UserID
		if ownerID == "" { ownerID = userID }
		lr.setOwner(ownerID)
		// Backfill user_id in relay_creds.json and CRDB for old registrations that predate this field
		if creds.UserID == "" {
			creds.UserID = ownerID
			if data, err2 := json.Marshal(creds); err2 == nil {
				os.WriteFile(filepath.Join(lr.configDir, "relay_creds.json"), data, 0o600) //nolint:errcheck
			}
			// Update CRDB so GET /user/relays returns this relay for its owner
			if existing := lr.fs.backup(); existing != nil {
				if err2 := existing.UpdateUserID(ownerID); err2 != nil {
					log.Printf("⚠️  lazy register: update-user-id: %v", err2)
				}
			}
		}
		bc := backup.New(lr.masterKey, lr.configDir, lr.backupURL, lr.debounce, Version)
		if bc != nil {
			lr.fs.setBackup(bc)
			log.Printf("✅ lazy register: backup enabled (relay_id=%s owner=%s)", creds.RelayID, ownerID)
			if maps, err2 := lr.fs.p.ListFiles(); err2 == nil { bc.Trigger(maps) } // initial snapshot
			bc.StartPingLoop(30 * time.Second) // s313 Phase 0: 30s default; hub adapts to 3s during release burst window via next_ping_seconds
		}
	})
}

// dimsPath returns the path to the .dims sidecar file for a given fileID.
func (fs *fileServer) dimsPath(fileID string) string {
	return filepath.Join(filepath.Dir(fs.thumbCache.Path(fileID)), fileID+".dims")
}

// readDims reads cached image metadata from a .dims sidecar file.
// Format: "width height taken_at_unix" (taken_at_unix=0 means absent).
// Returns zero Dims if file does not exist or is malformed.
func (fs *fileServer) readDims(fileID string) thumbnail.Dims {
	data, err := os.ReadFile(fs.dimsPath(fileID))
	if err != nil { return thumbnail.Dims{} }
	parts := strings.Fields(string(data))
	if len(parts) < 2 { return thumbnail.Dims{} }
	w, _ := strconv.Atoi(parts[0])
	h, _ := strconv.Atoi(parts[1])
	d := thumbnail.Dims{Width: w, Height: h}
	if len(parts) >= 3 {
		if unix, err2 := strconv.ParseInt(parts[2], 10, 64); err2 == nil && unix > 0 {
			t := time.Unix(unix, 0)
			d.TakenAt = &t
		}
	}
	return d
}

// writeDims writes image metadata to a .dims sidecar file.
func (fs *fileServer) writeDims(fileID string, d thumbnail.Dims) {
	unix := int64(0)
	if d.TakenAt != nil { unix = d.TakenAt.Unix() }
	content := strconv.Itoa(d.Width) + " " + strconv.Itoa(d.Height) + " " + strconv.FormatInt(unix, 10)
	os.WriteFile(fs.dimsPath(fileID), []byte(content), 0o644) //nolint:errcheck
}

// folderFromFileMap returns "photos" or "files" for the Flutter Photos/Files tab filter, derived from
// the first Shard's Location.
//
// Three location formats are recognized, depending on the version that wrote the file:
//   - v0.17.2+ (Phase α): "gdrive:<email>:dudenest/photos/2026/05/foo.jpg" — has PathRoot prefix
//   - v0.11.0..v0.17.1 (P2 to s313 cont): "gdrive:<email>:photos/2026/05/foo.jpg" — no PathRoot
//   - pre-v0.11.0 (legacy hash-based): "gdrive:<email>:files/<hash>/0/0" — all stored under files/
//
// Match strategy: scan for "/photos/" (covers both new "dudenest/photos/" and any future PathRoot)
// OR for ":photos/" at the colon boundary right after provider:email (covers legacy without root).
// Default "files" preserves the pre-v0.11.0 behavior where everything was under files/ regardless
// of content type — the Flutter side may further re-classify by extension as a secondary signal.
func folderFromFileMap(fm *types.FileMap) string {
	if len(fm.Chunks) == 0 || len(fm.Chunks[0].Shards) == 0 { return types.FilesFolder }
	loc := fm.Chunks[0].Shards[0].Location // "<provider>:<email>:<relative_path>"
	if strings.Contains(loc, "/"+types.PhotosFolder+"/") { return types.PhotosFolder } // new format with PathRoot
	if strings.Contains(loc, ":"+types.PhotosFolder+"/") { return types.PhotosFolder } // legacy format without PathRoot
	return types.FilesFolder
}

// handleList handles GET /files — returns list of uploaded FileMaps.
func (fs *fileServer) handleList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	maps, err := fs.p.ListFiles()
	if err != nil {
		jsonErr(w, "list files: "+err.Error(), 500)
		return
	}
	type fileSummary struct {
		FileID  string     `json:"file_id"`
		Name    string     `json:"name"`
		Size    int64      `json:"size"`
		Hash    string     `json:"hash"`
		Created time.Time  `json:"created"`
		Folder  string     `json:"folder"`             // P2/P3 redesign: "photos" (media) or "files" (non-media) — sourced from Shard.Location path prefix; Flutter Photos vs Files tabs filter on this
		Width   int        `json:"width,omitempty"`    // original image width (0 = unknown/non-image)
		Height  int        `json:"height,omitempty"`   // original image height
		TakenAt *time.Time `json:"taken_at,omitempty"` // EXIF DateTimeOriginal; null if absent
		LQIP    string     `json:"lqip,omitempty"`     // data:image/jpeg;base64,... tiny blur placeholder
	}
	summaries := make([]fileSummary, 0, len(maps))
	for _, fm := range maps {
		d := fs.readDims(fm.FileID)
		// Fast path: read dims from cached medium preview if .dims sidecar is missing
		if d.Width == 0 && fs.thumbCache.MediumExists(fm.FileID) {
			if md, err2 := thumbnail.ReadDims(fs.thumbCache.MediumPath(fm.FileID)); err2 == nil && md.Width > 0 {
				d.Width = md.Width; d.Height = md.Height
				fs.writeDims(fm.FileID, d) // persist so next list is instant
			}
		}
		lqipData, _ := os.ReadFile(fs.thumbCache.LQIPPath(fm.FileID))
		// Kick off lazy sidecar generation for files missing dims or LQIP (async, non-blocking)
		if d.Width == 0 || len(lqipData) == 0 {
			go fs.lazyGenSidecars(fm.FileID, fm.Name)
		}
		// F1 dedup: alias FileMap has no Chunks — derive folder from canonical (one cached lookup).
		folder := folderFromFileMap(fm)
		if fm.LogicalAlias != "" && (len(fm.Chunks) == 0 || len(fm.Chunks[0].Shards) == 0) {
			if canonical, gerr := fs.p.GetFileMap(fm.LogicalAlias); gerr == nil { folder = folderFromFileMap(canonical) }
		}
		summaries = append(summaries, fileSummary{
			FileID: fm.FileID, Name: fm.Name, Size: fm.Size, Hash: fm.Hash, Created: fm.Created,
			Folder: folder,
			Width: d.Width, Height: d.Height, TakenAt: d.TakenAt, LQIP: string(lqipData),
		})
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"files": summaries}) //nolint:errcheck
}

// handleFile dispatches /files/{id}, /files/{id}/thumbnail, and /files/upload.
func (fs *fileServer) handleFile(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/files/")
	switch {
	case path == "upload" && r.Method == http.MethodPost:
		fs.handleUpload(w, r)
	case strings.HasSuffix(path, "/thumbnail") && r.Method == http.MethodGet:
		fs.handleThumbnail(w, r, strings.TrimSuffix(path, "/thumbnail"))
	case strings.HasSuffix(path, "/preview") && r.Method == http.MethodGet:
		fs.handlePreview(w, r, strings.TrimSuffix(path, "/preview"))
	case strings.HasSuffix(path, "/meta") && (r.Method == http.MethodGet || r.Method == http.MethodPatch):
		fs.handleMeta(w, r, strings.TrimSuffix(path, "/meta"))
	case strings.HasSuffix(path, "/map") && r.Method == http.MethodGet:
		fs.handleGetMap(w, r, strings.TrimSuffix(path, "/map"))
	case path != "" && r.Method == http.MethodGet:
		fs.handleDownload(w, r, path)
	case path != "" && r.Method == http.MethodDelete:
		fs.handleDelete(w, r, path)
	default:
		http.NotFound(w, r)
	}
}

func (fs *fileServer) handleGetMap(w http.ResponseWriter, r *http.Request, fileID string) {
	fm, err := fs.p.GetFileMap(fileID)
	if err != nil {
		jsonErr(w, "get map: "+err.Error(), 404)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(fm) //nolint:errcheck
}
// handleUpload accepts multipart/form-data with field "file", uploads via pipeline.
func (fs *fileServer) handleUpload(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(fs.maxUploadBytes); err != nil {
		jsonErr(w, "parse form: "+err.Error(), 400)
		return
	}
	f, header, err := r.FormFile("file")
	if err != nil {
		jsonErr(w, "form field 'file' required: "+err.Error(), 400)
		return
	}
	defer f.Close()
	tmpDir, err := os.MkdirTemp("", "relay-upload-*") // unique dir → file named as original
	if err != nil {
		jsonErr(w, "tmp dir: "+err.Error(), 500)
		return
	}
	defer os.RemoveAll(tmpDir)
	tmpPath := filepath.Join(tmpDir, header.Filename)
	tmp, err := os.Create(tmpPath)
	if err != nil {
		jsonErr(w, "tmp file: "+err.Error(), 500)
		return
	}
	if _, err := io.Copy(tmp, f); err != nil {
		tmp.Close()
		jsonErr(w, "write tmp: "+err.Error(), 500)
		return
	}
	tmp.Close()
	strategy := r.FormValue("strategy")
	if strategy == "" { strategy = types.StrategyReplica } // default: replica (full file, no encryption)
	// HEIC/HEIF conversion: convert to JPEG before upload so all clients can display the file.
	ext := strings.ToLower(filepath.Ext(header.Filename))
	if ext == ".heic" || ext == ".heif" || ext == ".hif" {
		base := strings.TrimSuffix(header.Filename, filepath.Ext(header.Filename))
		convertedPath := filepath.Join(tmpDir, base+".jpg")
		if err2 := thumbnail.ConvertHEIC(tmpPath, convertedPath); err2 == nil {
			tmpPath = convertedPath
			header.Filename = base + ".jpg"
			ext = ".jpg"
		} else {
			log.Printf("⚠️  HEIC conversion: %v (uploading as-is)", err2)
		}
	}
	fm, err := fs.p.Upload(tmpPath, strategy)
	if err != nil {
		jsonErr(w, "upload: "+err.Error(), 500)
		return
	}
	if fs.thumbCache != nil {
		isVideo := ext == ".mp4" || ext == ".mov" || ext == ".avi" || ext == ".mkv" || ext == ".webm" || ext == ".m4v" || ext == ".3gp" || ext == ".wmv" || ext == ".flv"
		thumbPath := fs.thumbCache.Path(fm.FileID)
		if isVideo {
			if err2 := thumbnail.VideoThumbnail(tmpPath, thumbPath); err2 != nil {
				log.Printf("⚠️  video thumbnail: %v", err2)
			}
		} else {
			if dims, err2 := thumbnail.Generate(tmpPath, thumbPath); err2 == nil && dims.Width > 0 {
				fs.writeDims(fm.FileID, dims)
			}
		}
		// Medium preview (800px) and LQIP generated from temp file while it still exists
		if fs.thumbCache.Exists(fm.FileID) {
			if !isVideo {
				thumbnail.GenerateMedium(tmpPath, fs.thumbCache.MediumPath(fm.FileID)) //nolint:errcheck
			}
			// LQIP from medium preview (aspect-preserving) — fallback to square thumbnail
			lqipSrc := fs.thumbCache.MediumPath(fm.FileID)
			if !fs.thumbCache.MediumExists(fm.FileID) { lqipSrc = thumbPath }
			if lqip := thumbnail.LQIPBase64(lqipSrc); lqip != "" {
				os.WriteFile(fs.thumbCache.LQIPPath(fm.FileID), []byte(lqip), 0o644) //nolint:errcheck
			}
		}
	}
	if maps, err2 := fs.p.ListFiles(); err2 == nil { // trigger backup after successful upload
		fs.backup().Trigger(maps)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
		"file_id":  fm.FileID,
		"name":     header.Filename,
		"size":     fm.Size,
		"hash":     fm.Hash,
		"strategy": fm.Strategy,
		"chunks":   len(fm.Chunks),
	})
}

// handleDownload assembles a file and streams it back with Range support.
func (fs *fileServer) handleDownload(w http.ResponseWriter, r *http.Request, fileID string) {
	tmp, err := os.CreateTemp("", "relay-download-*")
	if err != nil {
		jsonErr(w, "tmp file: "+err.Error(), 500)
		return
	}
	tmp.Close()
	defer os.Remove(tmp.Name())
	if err := fs.p.Download(fileID, tmp.Name()); err != nil {
		jsonErr(w, "download: "+err.Error(), 500)
		return
	}
	f, err := os.Open(tmp.Name())
	if err != nil {
		jsonErr(w, "open: "+err.Error(), 500)
		return
	}
	defer f.Close()
	fm, _ := fs.p.GetFileMap(fileID)
	name := fileID
	var modTime time.Time
	if fm != nil {
		name = fm.Name
		modTime = fm.Modified
	}
	http.ServeContent(w, r, name, modTime, f) // handles Range, Content-Type, ETag
}

// handleThumbnail serves a cached 200×200 JPEG thumbnail; lazy-generates on first request.
// Supports both images (Generate) and videos (VideoThumbnail via ffmpeg).
func (fs *fileServer) handleThumbnail(w http.ResponseWriter, r *http.Request, fileID string) {
	if fileID == "" {
		http.NotFound(w, r)
		return
	}
	thumbPath := fs.thumbCache.Path(fileID)
	if !fs.thumbCache.Exists(fileID) { // lazy-generate: download full file once, then cache
		fm, _ := fs.p.GetFileMap(fileID)
		ext := ""
		if fm != nil { ext = strings.ToLower(filepath.Ext(fm.Name)) }
		tmp, err := os.CreateTemp("", "relay-thumb-*"+ext) // preserve extension so ffmpeg detects format
		if err != nil {
			jsonErr(w, "tmp file: "+err.Error(), 500)
			return
		}
		tmp.Close()
		defer os.Remove(tmp.Name())
		if err := fs.p.Download(fileID, tmp.Name()); err != nil {
			jsonErr(w, "download for thumbnail: "+err.Error(), 500)
			return
		}
		if isVideoExt(ext) {
			if err2 := thumbnail.VideoThumbnail(tmp.Name(), thumbPath); err2 != nil {
				jsonErr(w, "video thumbnail: "+err2.Error(), 500)
				return
			}
		} else {
			dims, err2 := thumbnail.Generate(tmp.Name(), thumbPath)
			if err2 != nil {
				jsonErr(w, "generate thumbnail: "+err2.Error(), 500)
				return
			}
			if dims.Width > 0 { fs.writeDims(fileID, dims) } // cache dims on lazy generation
		}
		// Generate LQIP lazily after thumbnail is ready (best-effort, non-blocking)
		name := fileID
		if fm != nil { name = fm.Name }
		go fs.lazyGenSidecars(fileID, name)
	}
	data, err := os.ReadFile(thumbPath)
	if err != nil {
		jsonErr(w, "read thumbnail: "+err.Error(), 500)
		return
	}
	w.Header().Set("Content-Type", "image/jpeg")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.Write(data) //nolint:errcheck
}

// handleDelete removes a file from cloud storage.
func (fs *fileServer) handleDelete(w http.ResponseWriter, r *http.Request, fileID string) {
	if err := fs.p.DeleteFile(fileID); err != nil {
		jsonErr(w, "delete: "+err.Error(), 500)
		return
	}
	if maps, err := fs.p.ListFiles(); err == nil { // trigger backup after successful delete
		fs.backup().Trigger(maps)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "deleted", "file_id": fileID}) //nolint:errcheck
}

// requireAuthWithReg validates JWT Bearer token and enforces three security layers:
//   Layer 1 — network isolation (separate relay VM per user; enforced at infrastructure level)
//   Layer 2 — JWT sub must match relay owner's user_id (stored in relay_creds.json)
//   Layer 3 — X-Relay-Token must be a valid HMAC signed by backup using relay_secret
// Also triggers lazy relay registration on first valid request (sync.Once).
func requireAuthWithReg(lr *lazyRegistrar, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		// ?token= query param: fallback for web video player (HTMLVideoElement can't send custom headers).
		// Requests using this path skip Layer 3 (no X-Relay-Token available in URL-only auth).
		queryTokenAuth := false
		if authHeader == "" {
			if tok := r.URL.Query().Get("token"); tok != "" {
				authHeader = "Bearer " + tok
				queryTokenAuth = true
			}
		}
		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			jsonErr(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		token := strings.TrimPrefix(authHeader, "Bearer ")
		claims, err := auth.ValidateJWT(token)
		if err != nil {
			jsonErr(w, "invalid token: "+err.Error(), http.StatusUnauthorized)
			return
		}
		// Layer 2: JWT sub must match relay owner — prevents any other account from accessing this relay
		if lr != nil {
			if ownerID := lr.getOwner(); ownerID != "" && claims.Sub != ownerID {
				log.Printf("security L2 rejected: sub=%q owner=%q path=%s", claims.Sub, ownerID, r.URL.Path)
				jsonErr(w, "forbidden: this relay belongs to a different user", http.StatusForbidden)
				return
			}
		}
		// Layer 3: relay_token must be valid HMAC signed by backup using relay_secret
		// Only enforced when owner is known — prevents bootstrap deadlock for old relays without user_id in CRDB.
		// Old relays: ownerUserID="" on startup → L3 skipped → tryRegister fires → sets ownerUserID + updates CRDB
		//             → Flutter gets relay_token from /user/relays → next request includes token → L3 enforced.
		if lr != nil && !queryTokenAuth { // Layer 3 skipped for ?token= requests (web video: no X-Relay-Token in URL)
			if ownerID := lr.getOwner(); ownerID != "" {
				if relaySecret := os.Getenv("RELAY_SECRET"); relaySecret != "" {
					rtoken := r.Header.Get("X-Relay-Token")
					if !relaytoken.Verify(rtoken, relaySecret, claims.Sub) {
						log.Printf("security L3 rejected: sub=%q relay_token_present=%v path=%s", claims.Sub, rtoken != "", r.URL.Path)
						jsonErr(w, "forbidden: invalid or expired relay token", http.StatusForbidden)
						return
					}
				}
			}
		}
		if lr != nil && claims.Sub != "" {
			go lr.tryRegister(claims.Sub) // non-blocking; sync.Once ensures runs exactly once
		}
		next.ServeHTTP(w, r)
	}
}
// corsMiddleware adds CORS headers for Flutter web clients.
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, PATCH, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Relay-Token")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
// makeBootstrapHandler returns a handler for POST /relay/bootstrap.
// Called by relay-provisioner via ZT network after ZT member is authorized.
// Validates X-Announce-Token, writes relay_creds.json, sets RELAY_ID + RELAY_SECRET env vars.
// Auth: one-time token saved at announce time (announce_token.tmp) — deleted after use.
func makeBootstrapHandler(configDir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost { http.Error(w, "POST only", http.StatusMethodNotAllowed); return }
		token := r.Header.Get("X-Announce-Token")
		if token == "" { jsonErr(w, "X-Announce-Token required", http.StatusUnauthorized); return }
		saved, err := register.LoadAnnounceToken(configDir)
		if err != nil { jsonErr(w, "no pending announce (not in ZT provisioning mode)", http.StatusBadRequest); return }
		if token != saved { jsonErr(w, "invalid announce token", http.StatusUnauthorized); return }
		var payload register.BootstrapPayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil { jsonErr(w, "bad json: "+err.Error(), 400); return }
		if payload.RelayID == "" || payload.RelaySecret == "" || payload.JWTSecret == "" {
			jsonErr(w, "relay_id, relay_secret, jwt_secret required", 400); return
		}
		if _, err := register.WriteBootstrapCreds(configDir, &payload); err != nil {
			jsonErr(w, "write creds: "+err.Error(), 500); return
		}
		os.Setenv("RELAY_ID", payload.RelayID)         //nolint:errcheck
		os.Setenv("RELAY_SECRET", payload.RelaySecret) //nolint:errcheck
		os.Setenv("JWT_SECRET", payload.JWTSecret)     //nolint:errcheck — sets for current process; relay.env updated by install script
		if payload.BackupURL != "" { os.Setenv("BACKUP_URL", payload.BackupURL) } //nolint:errcheck
		register.ClearAnnounceToken(configDir) // one-time use — delete after success
		log.Printf("✅ relay bootstrapped: relay_id=%s relay_url=%s", payload.RelayID, payload.RelayURL)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok", "relay_url": payload.RelayURL}) //nolint:errcheck
	}
}

// maybeAnnounce announces to hub if no relay_creds.json and ZT_ANNOUNCE=true env var is set.
// Relay-pull arch: after announce, polls GET /relay/bootstrap?announce_token=<token> in background.
// Non-fatal — relay enters standby and waits for bootstrap credentials.
func maybeAnnounce(configDir, hubURL string) {
	if os.Getenv("ZT_ANNOUNCE") != "true" { return } // ZT provisioning mode must be explicitly enabled
	if _, err := os.ReadFile(filepath.Join(configDir, "relay_creds.json")); err == nil { return } // already registered
	log.Printf("relay: ZT provisioning mode — announcing to %s ...", hubURL)
	token, err := register.Announce(configDir, hubURL)
	if err != nil {
		log.Printf("⚠️  relay: announce failed: %v (will retry on next restart)", err)
		return
	}
	go register.PollBootstrap(configDir, hubURL, token) // relay-pull arch: poll hub until provisioner completes
}

// isCredentialError detects OAuth token errors that should not trigger a crash loop.
// These errors are permanent until credentials are refreshed — retrying is wasteful.
// "no cloud providers available" = fresh install, no users authenticated yet → standby.
func isCredentialError(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "invalid_grant") ||
		strings.Contains(s, "Token has been expired or revoked") ||
		strings.Contains(s, "oauth2: cannot fetch token") ||
		strings.Contains(s, "no cloud providers available")
}

// handlePreview serves an 800px medium JPEG preview; lazy-generates from the original if missing.
// Falls back to the 200px thumbnail for video files or unsupported image formats.
func (fs *fileServer) handlePreview(w http.ResponseWriter, r *http.Request, fileID string) {
	if fileID == "" { http.NotFound(w, r); return }
	mediumPath := fs.thumbCache.MediumPath(fileID)
	if !fs.thumbCache.MediumExists(fileID) {
		tmp, err := os.CreateTemp("", "relay-preview-*")
		if err != nil { jsonErr(w, "tmp: "+err.Error(), 500); return }
		tmp.Close()
		defer os.Remove(tmp.Name())
		if err := fs.p.Download(fileID, tmp.Name()); err != nil { jsonErr(w, "download: "+err.Error(), 500); return }
		if err := thumbnail.GenerateMedium(tmp.Name(), mediumPath); err != nil {
			// Not a supported image (e.g. video) — fall back to thumbnail; generate video thumb if missing
			thumbPath := fs.thumbCache.Path(fileID)
			if !fs.thumbCache.Exists(fileID) {
				if vtErr := thumbnail.VideoThumbnail(tmp.Name(), thumbPath); vtErr != nil {
					jsonErr(w, "no preview available", http.StatusNotFound)
					return
				}
			}
			mediumPath = thumbPath
		} else {
			// Medium generated — also write LQIP from it
			if lqipPath := fs.thumbCache.LQIPPath(fileID); !fileExists(lqipPath) {
				if lqip := thumbnail.LQIPBase64(fs.thumbCache.Path(fileID)); lqip != "" {
					os.WriteFile(lqipPath, []byte(lqip), 0o644) //nolint:errcheck
				}
			}
		}
	}
	data, err := os.ReadFile(mediumPath)
	if err != nil { jsonErr(w, "read preview: "+err.Error(), 500); return }
	w.Header().Set("Content-Type", "image/jpeg")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.Write(data) //nolint:errcheck
}

// handleMeta handles GET/PATCH /files/{id}/meta for favorites, albums, location, caption.
func (fs *fileServer) handleMeta(w http.ResponseWriter, r *http.Request, fileID string) {
	if fileID == "" { http.NotFound(w, r); return }
	switch r.Method {
	case http.MethodGet:
		m := fs.readMeta(fileID)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(m) //nolint:errcheck
	case http.MethodPatch:
		var patch fileMeta
		if err := json.NewDecoder(r.Body).Decode(&patch); err != nil { jsonErr(w, "bad json: "+err.Error(), 400); return }
		prev := fs.readMeta(fileID)
		if err := fs.writeMeta(fileID, patch); err != nil { jsonErr(w, "write meta: "+err.Error(), 500); return }
		// P5b: TakenAtOverride changed → re-bucket file into new YYYY/MM folder via MoveByID.
		// CloudID stays the same; only path changes. Best-effort — failure here doesn't fail the PATCH
		// (meta is persisted regardless; user can retry move via re-PATCH same value or admin endpoint).
		if patch.TakenAtOverride != prev.TakenAtOverride && patch.TakenAtOverride != "" {
			if t, perr := time.Parse(time.RFC3339, patch.TakenAtOverride); perr == nil {
				fm, gerr := fs.p.GetFileMap(fileID)
				if gerr == nil && len(fm.Chunks) > 0 && len(fm.Chunks[0].Shards) > 0 {
					// Derive top folder (photos|files) from existing Location.
					// Three location formats are recognized (matches folderFromFileMap):
					//   v0.17.2+ Phase α:   "gdrive:<email>:dudenest/photos/2026/05/foo.jpg"
					//   v0.11.0..v0.17.1:   "gdrive:<email>:photos/2026/05/foo.jpg"
					//   pre-v0.11.0 legacy: "gdrive:<email>:files/<hash>/0/0"
					// Scan for /<folder>/ (PathRoot present) or :<folder>/ (no PathRoot).
					loc := fm.Chunks[0].Shards[0].Location
					top := types.FilesFolder
					for _, fold := range []string{types.PhotosFolder, types.FilesFolder} {
						if strings.Contains(loc, "/"+fold+"/") || strings.Contains(loc, ":"+fold+"/") {
							top = fold
							break
						}
					}
					// Preserve PathRoot prefix when present in the current location so MoveFile keeps
					// the file under the same root (dudenest/) and doesn't accidentally relocate to drive root.
					newDir := fmt.Sprintf("%s/%04d/%02d", top, t.Year(), int(t.Month()))
					if accts := fs.p.AccountManager(); accts != nil {
						cfg := accts.Policy()
						if cfg.PathRoot != "" && strings.Contains(loc, ":"+cfg.PathRoot+"/") {
							newDir = fmt.Sprintf("%s/%s/%04d/%02d", cfg.PathRoot, top, t.Year(), int(t.Month()))
						}
					}
					if mErr := fs.p.MoveFile(fileID, newDir); mErr != nil {
						log.Printf("⚠️  meta-PATCH MoveFile %s → %s: %v", fileID, newDir, mErr)
					} else {
						log.Printf("✅ meta-PATCH moved file %s to bucket %s (TakenAtOverride=%s)", fileID, newDir, patch.TakenAtOverride)
					}
				}
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(patch) //nolint:errcheck
	}
}

func (fs *fileServer) metaPath(fileID string) string { return filepath.Join(fs.metaDir, fileID+".json") }

func (fs *fileServer) readMeta(fileID string) fileMeta {
	data, err := os.ReadFile(fs.metaPath(fileID))
	if err != nil { return fileMeta{} }
	var m fileMeta
	json.Unmarshal(data, &m) //nolint:errcheck
	return m
}

func (fs *fileServer) writeMeta(fileID string, m fileMeta) error {
	data, err := json.Marshal(m)
	if err != nil { return err }
	return os.WriteFile(fs.metaPath(fileID), data, 0o644)
}

func fileExists(path string) bool { _, err := os.Stat(path); return err == nil }

func isVideoExt(ext string) bool {
	switch ext {
	case ".mp4", ".mov", ".avi", ".mkv", ".webm", ".m4v", ".3gp", ".wmv", ".flv":
		return true
	}
	return false
}

// lazyGenMu deduplicates concurrent lazyGenSidecars calls for the same fileID.
var lazyGenMu sync.Map

// lazyGenSidecars downloads the original file once and generates any missing sidecars:
// thumbnail (images+videos), dims, medium preview (800px), and LQIP.
// Called from handleList and handleThumbnail; safe to call concurrently — deduplicated.
func (fs *fileServer) lazyGenSidecars(fileID, nameOrExt string) {
	if _, loaded := lazyGenMu.LoadOrStore(fileID, true); loaded { return }
	defer lazyGenMu.Delete(fileID)

	ext := strings.ToLower(filepath.Ext(nameOrExt))
	isVideo := isVideoExt(ext)
	thumbPath := fs.thumbCache.Path(fileID)
	mediumPath := fs.thumbCache.MediumPath(fileID)
	lqipPath := fs.thumbCache.LQIPPath(fileID)

	needThumb  := !fs.thumbCache.Exists(fileID)
	needDims   := !fileExists(fs.dimsPath(fileID))
	needMedium := !isVideo && !fs.thumbCache.MediumExists(fileID)
	needLQIP   := !fs.thumbCache.LQIPExists(fileID)
	if !needThumb && !needDims && !needMedium && !needLQIP { return }

	tmp, err := os.CreateTemp("", "relay-lazy-*"+ext)
	if err != nil { log.Printf("⚠️  lazyGenSidecars %s: tmp: %v", fileID, err); return }
	tmp.Close()
	defer os.Remove(tmp.Name())
	if err := fs.p.Download(fileID, tmp.Name()); err != nil {
		log.Printf("⚠️  lazyGenSidecars %s: download: %v", fileID, err)
		return
	}

	if needThumb || needDims {
		if isVideo {
			if needThumb {
				if err2 := thumbnail.VideoThumbnail(tmp.Name(), thumbPath); err2 != nil {
					log.Printf("⚠️  lazyGenSidecars %s: video thumb: %v", fileID, err2)
				}
			}
		} else {
			dims, err2 := thumbnail.Generate(tmp.Name(), thumbPath)
			if err2 != nil {
				log.Printf("⚠️  lazyGenSidecars %s: generate: %v", fileID, err2)
			} else if dims.Width > 0 {
				fs.writeDims(fileID, dims)
			}
		}
	}
	if needMedium && !isVideo {
		if err2 := thumbnail.GenerateMedium(tmp.Name(), mediumPath); err2 != nil {
			log.Printf("⚠️  lazyGenSidecars %s: medium: %v", fileID, err2)
		}
	}
	if needLQIP {
		// Prefer medium preview (aspect-preserving); fall back to thumbnail (square)
		lqipSrc := mediumPath
		if !fs.thumbCache.MediumExists(fileID) { lqipSrc = thumbPath }
		if lqip := thumbnail.LQIPBase64(lqipSrc); lqip != "" {
			os.WriteFile(lqipPath, []byte(lqip), 0o644) //nolint:errcheck
		}
	}
	log.Printf("✅ lazyGenSidecars: %s done", fileID)
}

func jsonErr(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg}) //nolint:errcheck
}
