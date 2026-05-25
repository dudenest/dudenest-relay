// gdrive changes.go implements types.CloudChangesPoller via Drive API changes.list.
// One pageToken per provider covers the entire Drive scope (root-anchored), so files
// the user uploads directly through Drive web UI also surface in /Files. s320 Phase 2.
package gdrive

import (
	"fmt"
	"time"

	"github.com/dudenest/dudenest-relay/pkg/types"
)

// Compile-time assertion: Provider satisfies CloudChangesPoller.
var _ types.CloudChangesPoller = (*Provider)(nil)

// GetStartPageToken returns Drive's current high-water-mark. The poller persists this on first run;
// the first GetChanges call will then return only changes that happened AFTER this token was issued.
func (p *Provider) GetStartPageToken() (string, error) {
	r, err := p.svc.Changes.GetStartPageToken().Do()
	if err != nil { return "", fmt.Errorf("changes.getStartPageToken: %w", err) }
	return r.StartPageToken, nil
}

// GetChanges drains all change pages from pageToken forward. Auto-pages until NewStartPageToken is set
// (signals end-of-log — that token becomes the seed for next poll). Skips folder-type entries.
// Filters: trashed files surface as Removed=true (caller deletes from blockmap if known).
func (p *Provider) GetChanges(pageToken string) ([]types.ChangedEntry, string, error) {
	if pageToken == "" { return nil, "", fmt.Errorf("pageToken required (call GetStartPageToken once)") }
	out := []types.ChangedEntry{}
	tok := pageToken
	var newStart string
	for { // Auto-page until newStartPageToken set
		r, err := p.svc.Changes.List(tok).
			Fields("changes(fileId,removed,time,file(id,name,mimeType,size,modifiedTime,trashed)),nextPageToken,newStartPageToken").
			Spaces("drive").
			PageSize(1000).
			IncludeRemoved(true).
			Do()
		if err != nil { return nil, "", fmt.Errorf("changes.list at token=%s: %w", tok, err) }
		for _, c := range r.Changes {
			if c.Removed { out = append(out, types.ChangedEntry{CloudID: c.FileId, Removed: true}); continue }
			if c.File == nil { continue }
			if c.File.Trashed { out = append(out, types.ChangedEntry{CloudID: c.FileId, Removed: true}); continue }
			if c.File.MimeType == "application/vnd.google-apps.folder" { continue } // skip folder events
			mtime, _ := time.Parse(time.RFC3339, c.File.ModifiedTime)
			out = append(out, types.ChangedEntry{
				CloudID: c.FileId, Name: c.File.Name, Path: c.File.Name,
				Size: c.File.Size, MTime: mtime,
			})
		}
		if r.NewStartPageToken != "" { newStart = r.NewStartPageToken }
		if r.NextPageToken == "" { break }
		tok = r.NextPageToken
	}
	if newStart == "" { newStart = pageToken } // defensive: keep prev token if Drive omits new one (shouldn't happen)
	return out, newStart, nil
}
