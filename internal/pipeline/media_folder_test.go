// media_folder_test.go — pins the content-type routing contract introduced in P2 of the Photos/Files redesign.
// uploadReplica calls mediaFolder() exactly once per upload to decide between PhotosFolder and FilesFolder.
// Misclassification here is user-visible: a misrouted photo lands in /dudenest/files/ instead of /dudenest/photos/
// and the future Photos screen (P3+P5) wouldn't show it. Tests cover magic-byte sniffs, extension fallbacks for
// formats Go stdlib can't recognize (HEIC/MOV/RAW), and the default-to-FilesFolder behavior for anything else.
package pipeline

import (
	"testing"

	"github.com/dudenest/dudenest-relay/pkg/types"
)

// Real magic-byte prefixes that net/http.DetectContentType recognizes verbatim.
var (
	jpegHeader = []byte{0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 'J', 'F', 'I', 'F'}
	pngHeader  = []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A}
	gifHeader  = []byte("GIF89a")
	webpHeader = append([]byte("RIFF\x00\x00\x00\x00WEBPVP8 "), make([]byte, 8)...)
	mp4Header  = []byte{0x00, 0x00, 0x00, 0x20, 'f', 't', 'y', 'p', 'i', 's', 'o', 'm'}
	pdfHeader  = []byte("%PDF-1.4\n")
	zipHeader  = []byte{'P', 'K', 0x03, 0x04}
	textHello  = []byte("Hello, world!\n")
	rawBytes   = []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B} // no recognized signature → octet-stream
)

func TestMediaFolder_MagicByteImage(t *testing.T) {
	for _, c := range []struct {
		name   string
		data   []byte
		expect string
	}{
		{"photo.jpg", jpegHeader, types.PhotosFolder},
		{"photo.png", pngHeader, types.PhotosFolder},
		{"photo.gif", gifHeader, types.PhotosFolder},
		{"photo.webp", webpHeader, types.PhotosFolder},
	} {
		if got := mediaFolder(c.name, c.data); got != c.expect {
			t.Errorf("mediaFolder(%q) = %q, want %q (magic-byte image)", c.name, got, c.expect)
		}
	}
}

func TestMediaFolder_MagicByteVideo(t *testing.T) {
	if got := mediaFolder("clip.mp4", mp4Header); got != types.PhotosFolder {
		t.Errorf("mediaFolder(mp4) = %q, want PhotosFolder", got)
	}
}

func TestMediaFolder_NonMedia(t *testing.T) {
	for _, c := range []struct {
		name   string
		data   []byte
		expect string
	}{
		{"doc.pdf", pdfHeader, types.FilesFolder},
		{"archive.zip", zipHeader, types.FilesFolder},
		{"note.txt", textHello, types.FilesFolder},
		{"unknown.bin", rawBytes, types.FilesFolder}, // unknown extension AND inconclusive sniff → default FilesFolder
	} {
		if got := mediaFolder(c.name, c.data); got != c.expect {
			t.Errorf("mediaFolder(%q) = %q, want %q (non-media)", c.name, got, c.expect)
		}
	}
}

// Critical case: iPhone photos arrive as HEIC, which DetectContentType returns as application/octet-stream.
// Without extension fallback, every iPhone photo would land in FilesFolder — the Photos screen would be empty.
func TestMediaFolder_ExtensionFallback_HEIC(t *testing.T) {
	if got := mediaFolder("IMG_1234.HEIC", rawBytes); got != types.PhotosFolder {
		t.Errorf("HEIC by extension: got %q, want PhotosFolder (iPhone photos depend on this)", got)
	}
	if got := mediaFolder("photo.heif", rawBytes); got != types.PhotosFolder {
		t.Errorf("HEIF by extension: got %q, want PhotosFolder", got)
	}
}

// Camera RAW formats — Sony/Nikon/Canon/Fujifilm/Olympus/Pentax/etc. All octet-stream by sniff,
// must be routed by extension so photographers see their library under Photos.
func TestMediaFolder_ExtensionFallback_RAW(t *testing.T) {
	rawExts := []string{".raw", ".arw", ".nef", ".cr2", ".cr3", ".dng", ".rw2", ".orf", ".pef", ".rwl", ".srw"}
	for _, ext := range rawExts {
		name := "DSC_0001" + ext
		if got := mediaFolder(name, rawBytes); got != types.PhotosFolder {
			t.Errorf("RAW %s by extension: got %q, want PhotosFolder", ext, got)
		}
	}
}

// QuickTime .mov and other video containers stdlib doesn't sniff confidently.
func TestMediaFolder_ExtensionFallback_Video(t *testing.T) {
	videoExts := []string{".mov", ".mkv", ".m4v", ".3gp", ".mts", ".m2ts", ".avi"}
	for _, ext := range videoExts {
		name := "clip" + ext
		if got := mediaFolder(name, rawBytes); got != types.PhotosFolder {
			t.Errorf("video %s by extension: got %q, want PhotosFolder", ext, got)
		}
	}
}

// Case-insensitivity: filename extensions from iOS/macOS are commonly upper-case.
func TestMediaFolder_CaseInsensitiveExt(t *testing.T) {
	if got := mediaFolder("IMG.HEIC", rawBytes); got != types.PhotosFolder { t.Errorf(".HEIC: got %q, want PhotosFolder", got) }
	if got := mediaFolder("clip.MOV", rawBytes); got != types.PhotosFolder { t.Errorf(".MOV: got %q, want PhotosFolder", got) }
}

// Tiny files (< 512 bytes) must not panic on data[:512] slice — pinning the size-guard inside mediaFolder.
func TestMediaFolder_ShortData(t *testing.T) {
	tiny := []byte{0xFF, 0xD8, 0xFF} // 3-byte JPEG-ish signature
	if got := mediaFolder("a.jpg", tiny); got != types.PhotosFolder { t.Errorf("short JPEG: got %q, want PhotosFolder", got) }
	if got := mediaFolder("empty", []byte{}); got != types.FilesFolder { t.Errorf("empty file: got %q, want FilesFolder", got) }
}

// Mismatch defense: file named .jpg but containing PDF data — sniff wins over extension. This is the
// intended behavior because the content is what gets stored/displayed, not the filename. Documents
// disguised as images stay in FilesFolder (where they belong).
func TestMediaFolder_SniffOverridesExtension(t *testing.T) {
	if got := mediaFolder("disguised.jpg", pdfHeader); got != types.FilesFolder {
		t.Errorf("PDF named .jpg: got %q, want FilesFolder (sniff > extension when sniff is conclusive)", got)
	}
}
