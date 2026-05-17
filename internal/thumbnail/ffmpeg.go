// Package thumbnail — ffmpeg utilities: auto-install, video thumbnail, HEIC conversion,
// medium preview (800px), and LQIP base64 placeholder generation.
package thumbnail

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"image"
	"image/jpeg"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

const PreviewSize = 800 // medium preview longest-side pixels (aspect preserved)

// EnsureFFmpeg checks if ffmpeg is in PATH; installs via apt-get on Linux if missing.
func EnsureFFmpeg() error {
	if _, err := exec.LookPath("ffmpeg"); err == nil { return nil }
	if runtime.GOOS != "linux" { return fmt.Errorf("ffmpeg not found; install manually") }
	log.Printf("📦 ffmpeg not found — installing via apt-get...")
	cmd := exec.Command("sh", "-c", "DEBIAN_FRONTEND=noninteractive apt-get update -qq && apt-get install -y -qq ffmpeg")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil { return fmt.Errorf("apt-get install ffmpeg: %w", err) }
	log.Printf("✅ ffmpeg installed successfully")
	return nil
}

// VideoThumbnail extracts the first frame of videoPath as a center-cropped ThumbSize×ThumbSize JPEG.
func VideoThumbnail(videoPath, dstPath string) error {
	filter := fmt.Sprintf("scale=%d:%d:force_original_aspect_ratio=increase,crop=%d:%d", ThumbSize, ThumbSize, ThumbSize, ThumbSize)
	cmd := exec.Command("ffmpeg", "-y", "-ss", "0", "-i", videoPath, "-vframes", "1", "-vf", filter, "-q:v", "3", dstPath)
	out, err := cmd.CombinedOutput()
	if err != nil { return fmt.Errorf("ffmpeg video thumbnail: %w: %s", err, out) }
	return nil
}

// ConvertHEIC converts HEIC/HEIF srcPath to JPEG dstPath via ffmpeg.
func ConvertHEIC(srcPath, dstPath string) error {
	cmd := exec.Command("ffmpeg", "-y", "-i", srcPath, "-q:v", "2", dstPath)
	out, err := cmd.CombinedOutput()
	if err != nil { return fmt.Errorf("ffmpeg heic→jpg: %w: %s", err, out) }
	return nil
}

// GenerateMedium creates a PreviewSize-px (longest side) JPEG preview preserving aspect ratio.
// Only downscales — images smaller than PreviewSize are kept at original size.
func GenerateMedium(srcPath, dstPath string) error {
	f, err := os.Open(srcPath)
	if err != nil { return err }
	defer f.Close()
	src, _, err := image.Decode(f)
	if err != nil { return err }
	b := src.Bounds()
	sw, sh := b.Dx(), b.Dy()
	nw, nh := sw, sh
	if sw > PreviewSize || sh > PreviewSize {
		if sw >= sh { nw = PreviewSize; nh = sh * PreviewSize / sw } else { nh = PreviewSize; nw = sw * PreviewSize / sh }
		if nh < 1 { nh = 1 }
		if nw < 1 { nw = 1 }
	}
	out, err := os.Create(dstPath)
	if err != nil { return err }
	defer out.Close()
	return jpeg.Encode(out, nearest(src, nw, nh), &jpeg.Options{Quality: 85})
}

// LQIPBase64 reads an existing thumbnail JPEG, downscales to 20px wide, returns a data-URI JPEG.
// Returns "" if thumbPath doesn't exist or decoding fails — caller should omit LQIP in that case.
func LQIPBase64(thumbPath string) string {
	f, err := os.Open(thumbPath)
	if err != nil { return "" }
	defer f.Close()
	src, _, err := image.Decode(f)
	if err != nil { return "" }
	b := src.Bounds()
	sw, sh := b.Dx(), b.Dy()
	const lqipW = 20
	lqipH := sh * lqipW / sw
	if lqipH < 1 { lqipH = 1 }
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, nearest(src, lqipW, lqipH), &jpeg.Options{Quality: 40}); err != nil { return "" }
	return "data:image/jpeg;base64," + base64.StdEncoding.EncodeToString(buf.Bytes())
}

// MediumPath returns the cache path for the 800px medium preview of fileID.
func (c *Cache) MediumPath(fileID string) string { return filepath.Join(c.dir, fileID+"_medium.jpg") }

// MediumExists reports whether a medium preview is cached.
func (c *Cache) MediumExists(fileID string) bool {
	_, err := os.Stat(c.MediumPath(fileID))
	return err == nil
}

// LQIPPath returns the cache path for the LQIP base64 data-URI of fileID.
func (c *Cache) LQIPPath(fileID string) string { return filepath.Join(c.dir, fileID+".lqip") }
