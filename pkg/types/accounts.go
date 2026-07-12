// Package types — CloudAccount model for multi-account orchestration (Phase α, see
// ~/.AI/dudenest-application/CLOUD-ACCOUNT-POLICY-PLAN.md).
//
// CloudAccount is the relay's view of one user-attached cloud (gdrive/mega/onedrive/local).
// It carries identity, role, priority, quota, and policy overrides. The hub never sees these
// values plaintext — the entire backup snapshot is AES-256-GCM-encrypted with RELAY_KEY before
// upload, so emails / fill percentages / role data remain client-side only.
//
// IDs are int64 monotonic (1, 2, 3, …) — never reused after a Drain+Remove. UI formats as
// "ID001", "ID002", …, auto-expanding to %04d above 999 (see DisplayID).
package types

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Role is the lifecycle state machine bucket for a CloudAccount.
// Transitions are driven by AccountPolicyConfig + ReconcileRoles loop (see internal/account/manager.go).
type Role string

const (
	RolePrimaryWrite Role = "primary_write" // accepts new uploads first (highest priority pool)
	RoleReplicaWrite Role = "replica_write" // accepts replicas of uploads going to PrimaryWrite (and is the default for accounts #5+)
	RoleReadOnly     Role = "read_only"     // do not write; serve reads (scanned files / cold pre-existing content)
	RoleColdArchive  Role = "cold_archive"  // accepts age-rotated files (zstd-compressed per CompressionLevel) — user-opt-in
	RoleDrain        Role = "drain"         // user-initiated remove in progress; migration worker offloads files elsewhere
	RoleQuarantine   Role = "quarantine"    // transient — auth/API issue, exponential backoff, returns to previous role on success
)

// Status is orthogonal to Role: it tracks whether the account is reachable at all.
type Status string

const (
	StatusActive       Status = "active"        // healthy; obeys Role for read+write
	StatusReauthNeeded Status = "reauth_needed" // OAuth token expired/revoked — user must re-auth in UI
	StatusOverQuota    Status = "over_quota"    // exceeded HardCapPct — writes rejected; reads continue
	StatusError        Status = "error"         // generic API failure; see LastError, possibly quarantined
	StatusRemoved      Status = "removed"       // soft-deleted (Drain completed); kept for audit + scan reconciliation
)

// CloudAccount is the per-user, per-cloud configuration object stored in
// ~/.config/dudenest/accounts.json. One record per attached cloud account; soft-deleted
// (Status=Removed) records are retained for audit / scan-file reconciliation.
type CloudAccount struct {
	// --- Identity (immutable for the lifetime of the account) ---
	ID        int64      `json:"id"`                   // 1, 2, 3, ... monotonic per relay; NEVER reused after removal
	Provider  string     `json:"provider"`             // "gdrive" | "mega" | "onedrive" | "local"
	Email     string     `json:"email"`                // unique per (provider, relay); display only
	AddedAt   time.Time  `json:"added_at"`             // when the account was first attached to this relay
	RemovedAt *time.Time `json:"removed_at,omitempty"` // when Drain completed; nil for active accounts

	// --- Role + Priority (dynamic, editable in UI) ---
	Role     Role `json:"role"`
	Priority int  `json:"priority"`         // 0 = highest; dense ranking (gaps closed automatically on add/remove)
	Pinned   bool `json:"pinned,omitempty"` // true = ReconcileRoles will NOT auto-demote/promote this account

	// --- Capacity cache (refreshed every cfg.QuotaCheckIntervalMin via provider API) ---
	QuotaTotalBytes int64     `json:"quota_total_bytes,omitempty"`
	QuotaUsedBytes  int64     `json:"quota_used_bytes,omitempty"`
	QuotaCheckedAt  time.Time `json:"quota_checked_at,omitempty"`

	// --- Per-account policy overrides (nil pointer = inherit from AccountPolicyConfig defaults) ---
	SoftCapPct          *int      `json:"soft_cap_pct,omitempty"`
	HardCapPct          *int      `json:"hard_cap_pct,omitempty"`
	MaxFileSizeBytes    *int64    `json:"max_file_size_bytes,omitempty"`
	AcceptsContentTypes *[]string `json:"accepts_content_types,omitempty"` // e.g. ["photos"] — empty/nil means accept anything

	// --- Future-compat (Phase γ — see design doc §7) ---
	Region           string `json:"region,omitempty"`            // F4 multi-region (e.g. "eu-west")
	CompressionLevel int    `json:"compression_level,omitempty"` // F3 deep archive: 0=off, 1-9 zstd
	LogicalAliasOK   bool   `json:"logical_alias_ok,omitempty"`  // F2 dedup: this account may host LogicalAlias targets

	// --- State (auto-managed) ---
	Status          Status     `json:"status"`
	LastError       string     `json:"last_error,omitempty"`
	LastSeenAt      time.Time  `json:"last_seen_at,omitempty"`      // last successful API call
	QuarantineUntil *time.Time `json:"quarantine_until,omitempty"` // exponential backoff target time
}

// DisplayID renders the account ID in the form shown in UI / logs.
// 1-999 → "ID001".."ID999", 1000+ → "ID1234" (no padding past 4 digits — keeps it readable).
func (a *CloudAccount) DisplayID() string {
	if a.ID < 1000 {
		return fmt.Sprintf("ID%03d", a.ID)
	}
	return fmt.Sprintf("ID%d", a.ID)
}

// FreeBytes returns total - used. Returns 0 if quota not yet cached (defensive — don't claim
// infinite free space, which would let SelectReplicas always pick this account).
func (a *CloudAccount) FreeBytes() int64 {
	if a.QuotaTotalBytes == 0 {
		return 0
	}
	if a.QuotaUsedBytes >= a.QuotaTotalBytes {
		return 0
	}
	return a.QuotaTotalBytes - a.QuotaUsedBytes
}

// UsedPercent returns 0..100 (or 0 if quota not yet known).
func (a *CloudAccount) UsedPercent() int {
	if a.QuotaTotalBytes <= 0 {
		return 0
	}
	p := (a.QuotaUsedBytes * 100) / a.QuotaTotalBytes
	if p < 0 {
		return 0
	}
	if p > 100 {
		return 100
	}
	return int(p)
}

// AccountPolicyConfig is the global policy stored in ~/.config/dudenest/account_policy.json.
// EVERY field is user-configurable from the UI; the values in DefaultPolicy() are the
// only "hardcoded" thing in the codebase and exist solely to seed a sane initial config.
type AccountPolicyConfig struct {
	// --- Replication ---
	ReplicationFactor             int  `json:"replication_factor"`               // default 2; legal [1, len(active_accounts)]
	DiversityRequired             bool `json:"diversity_required"`               // true = each replica on a different Provider type
	DiversityRegionRequired       bool `json:"diversity_region_required"`        // F4 — different Region (only if Region set on accounts)
	AllowSingleReplicaWithWarning bool `json:"allow_single_replica_with_warning"` // true = allow upload with <RF replicas + UI warning; false = block

	// --- Quotas ---
	QuotaCheckIntervalMin int   `json:"quota_check_interval_min"`
	SoftCapDefaultPct     int   `json:"soft_cap_default_pct"`     // % at which PrimaryWrite auto-demotes to ReplicaWrite
	HardCapDefaultPct     int   `json:"hard_cap_default_pct"`     // % at which writes are unconditionally rejected
	MaxFileSizeDefaultMB  int64 `json:"max_file_size_default_mb"` // per-file cap when account has no override

	// --- Promote / Demote ---
	AutoDemoteOnSoftCap bool   `json:"auto_demote_on_soft_cap"`
	AutoPromoteOnSpace  bool   `json:"auto_promote_on_space"`
	PromoteStrategy     string `json:"promote_strategy"` // "by_priority" | "by_free_pct" | "by_age_oldest_first" | "round_robin"

	// --- Age-based rotation (Phase γ) ---
	AgeBasedRotation      bool   `json:"age_based_rotation"`
	AgeRotationDays       int    `json:"age_rotation_days"`
	AgeRotationTargetRole string `json:"age_rotation_target_role"` // "cold_archive" | "read_only"

	// --- Re-add semantics ---
	OnReAddSameEmail string `json:"on_re_add_same_email"` // "prompt_user" | "restore_old_id" | "create_new_id"

	// --- Rebalance ---
	RebalanceOnAdd                 string `json:"rebalance_on_add"` // "manual" | "auto_if_imbalance_pct_above" | "never"
	RebalanceImbalanceThresholdPct int    `json:"rebalance_imbalance_threshold_pct"`

	// --- Path layout ---
	PathScheme string `json:"path_scheme"` // "year_month" (default) | "year_month_day" | "flat"
	PathRoot   string `json:"path_root"`   // default "" — provider owns the base folder; extra prefix only if set (non-"" double-nests)

	// --- Drain / Remove ---
	DrainMaxConcurrentMigrations int   `json:"drain_max_concurrent_migrations"`
	DrainBatchSizeBytes          int64 `json:"drain_batch_size_bytes"`
	DrainBandwidthLimitMBPerSec  int   `json:"drain_bandwidth_limit_mb_per_sec"` // 0 = no limit

	// --- Future-compat (F1-F3) ---
	DuplicateDetectionEnabled   bool   `json:"duplicate_detection_enabled"`
	DuplicateDetectionMethod    string `json:"duplicate_detection_method"` // "sha256" | "perceptual_hash_for_images"
	DedupEnabled                bool   `json:"dedup_enabled"`
	DeepArchiveEnabled          bool   `json:"deep_archive_enabled"`
	DeepArchiveMinAgeDays       int    `json:"deep_archive_min_age_days"`
	DeepArchiveCompressionLevel int    `json:"deep_archive_compression_level"` // 0-9 zstd
}

// DefaultPolicy returns the Standard preset (per user decision 2026-05-22 §11).
// First-time setup uses this; existing relays without account_policy.json load this on boot.
func DefaultPolicy() AccountPolicyConfig {
	return AccountPolicyConfig{
		ReplicationFactor:              2,
		DiversityRequired:              false,
		DiversityRegionRequired:        false,
		AllowSingleReplicaWithWarning:  true,
		QuotaCheckIntervalMin:          30,
		SoftCapDefaultPct:              90,
		HardCapDefaultPct:              98,
		MaxFileSizeDefaultMB:           5000,
		AutoDemoteOnSoftCap:            true,
		AutoPromoteOnSpace:             true,
		PromoteStrategy:                "by_priority",
		AgeBasedRotation:               false,
		AgeRotationDays:                30,
		AgeRotationTargetRole:          string(RoleReadOnly),
		OnReAddSameEmail:               "prompt_user",
		RebalanceOnAdd:                 "manual",
		RebalanceImbalanceThresholdPct: 30,
		PathScheme:                     "year_month", // per user decision §11 #5: zostaje YYYY/MM
		PathRoot:                       "", // provider base ("dudenest") is the only root; non-"" double-nests (fixed 2026-07)
		DrainMaxConcurrentMigrations:   4,
		DrainBatchSizeBytes:            100 * 1024 * 1024,
		DrainBandwidthLimitMBPerSec:    0,
		DuplicateDetectionEnabled:      false,
		DuplicateDetectionMethod:       "sha256",
		DedupEnabled:                   false,
		DeepArchiveEnabled:             false,
		DeepArchiveMinAgeDays:          180,
		DeepArchiveCompressionLevel:    3,
	}
}

// PathFor renders the cloud-side path for a file given its name, content folder, and the
// timestamp the file should be filed under. Pure function — no I/O. Used by both the upload
// and move (rebucket) paths so they always agree.
func (cfg AccountPolicyConfig) PathFor(folder, name string, when time.Time) string {
	// The cloud provider already roots every file under its own base folder (--gdrive-path /
	// --mega-path, default "dudenest"). PathRoot is an OPTIONAL extra prefix ON TOP of that; a
	// non-empty default here double-nested every upload as dudenest/dudenest/… (fixed 2026-07).
	// Default "" → the provider base is the only root. Set PathRoot only to deliberately nest deeper.
	prefix := ""
	if cfg.PathRoot != "" {
		prefix = cfg.PathRoot + "/"
	}
	when = when.UTC()
	switch cfg.PathScheme {
	case "year_month_day":
		return fmt.Sprintf("%s%s/%04d/%02d/%02d/%s", prefix, folder, when.Year(), int(when.Month()), when.Day(), name)
	case "flat":
		return fmt.Sprintf("%s%s/%s", prefix, folder, name)
	default: // year_month (current production scheme) + unknown values
		return fmt.Sprintf("%s%s/%04d/%02d/%s", prefix, folder, when.Year(), int(when.Month()), name)
	}
}

// AcceptsContentType checks whether this account would accept a given content type.
// nil/empty override = accept anything. Case-insensitive comparison.
func (a *CloudAccount) AcceptsContentType(ct string) bool {
	if a.AcceptsContentTypes == nil || len(*a.AcceptsContentTypes) == 0 {
		return true
	}
	want := strings.ToLower(strings.TrimSpace(ct))
	for _, t := range *a.AcceptsContentTypes {
		if strings.ToLower(strings.TrimSpace(t)) == want {
			return true
		}
	}
	return false
}

// MarshalJSON / UnmarshalJSON for Role+Status are not needed — the string-typed enum
// serializes natively. Tests cover round-trip.

// Marshal helpers exposed for snapshot encryption (backup blob).
func MarshalAccounts(accounts []*CloudAccount) ([]byte, error) { return json.Marshal(accounts) }
func UnmarshalAccounts(b []byte) ([]*CloudAccount, error) {
	var out []*CloudAccount
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	return out, nil
}
func MarshalPolicy(cfg AccountPolicyConfig) ([]byte, error) { return json.Marshal(cfg) }
func UnmarshalPolicy(b []byte) (AccountPolicyConfig, error) {
	var out AccountPolicyConfig
	if err := json.Unmarshal(b, &out); err != nil {
		return AccountPolicyConfig{}, err
	}
	return out, nil
}
