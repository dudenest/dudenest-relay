// Package thumbnail generates and caches JPEG thumbnails for uploaded files.
// Thumbnails are stored locally on the relay: <configDir>/thumbnails/<fileID>.jpg
// Supported sources: JPEG, PNG, GIF (stdlib decoders, no CGO, no external deps).
package thumbnail

import (
	"image"
	"image/draw"
	"image/jpeg"
	_ "image/gif"  // register gif decoder
	_ "image/png"  // register png decoder
	"os"
	"path/filepath"
)

const ThumbSize = 200 // square thumbnail side in pixels

// Cache manages thumbnail files on the local filesystem.
type Cache struct{ dir string }

// NewCache creates (or opens) the thumbnail cache directory.
func NewCache(configDir string) (*Cache, error) {
	dir := filepath.Join(configDir, "thumbnails")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, err
	}
	return &Cache{dir: dir}, nil
}

// Path returns the cache path for a given fileID.
func (c *Cache) Path(fileID string) string { return filepath.Join(c.dir, fileID+".jpg") }

// Exists reports whether a thumbnail is cached.
func (c *Cache) Exists(fileID string) bool {
	_, err := os.Stat(c.Path(fileID))
	return err == nil
}

// Generate reads srcPath (image file), creates a square thumbnail, writes to dstPath as JPEG.
// Returns error if srcPath is not a supported image format.
func Generate(srcPath, dstPath string) error {
	f, err := os.Open(srcPath)
	if err != nil { return err }
	defer f.Close()
	src, _, err := image.Decode(f)
	if err != nil { return err } // unsupported format → caller skips thumbnail
	thumb := resizeSquare(src, ThumbSize)
	out, err := os.Create(dstPath)
	if err != nil { return err }
	defer out.Close()
	return jpeg.Encode(out, thumb, &jpeg.Options{Quality: 78})
}

// resizeSquare crops src to a centered square then downscales to size×size.
func resizeSquare(src image.Image, size int) image.Image {
	b := src.Bounds()
	sw, sh := b.Dx(), b.Dy()
	// Center-crop to square
	cropSide := sw
	if sh < sw { cropSide = sh }
	x0 := b.Min.X + (sw-cropSide)/2
	y0 := b.Min.Y + (sh-cropSide)/2
	crop := image.Rect(x0, y0, x0+cropSide, y0+cropSide)
	// Use SubImage when available (avoids copying)
	type subImager interface{ SubImage(image.Rectangle) image.Image }
	var cropped image.Image
	if si, ok := src.(subImager); ok {
		cropped = si.SubImage(crop)
	} else {
		tmp := image.NewNRGBA(image.Rect(0, 0, cropSide, cropSide))
		draw.Draw(tmp, tmp.Bounds(), src, image.Pt(x0, y0), draw.Src)
		cropped = tmp
	}
	if cropSide <= size { return cropped } // already small enough
	return nearest(cropped, size, size)
}

// nearest downscales src to w×h using nearest-neighbour sampling (fast, no deps).
func nearest(src image.Image, w, h int) *image.NRGBA {
	dst := image.NewNRGBA(image.Rect(0, 0, w, h))
	b := src.Bounds()
	sw, sh := b.Dx(), b.Dy()
	for y := 0; y < h; y++ {
		sy := b.Min.Y + y*sh/h
		for x := 0; x < w; x++ {
			dst.SetNRGBA(x, y, nrgbaAt(src, b.Min.X+x*sw/w, sy))
		}
	}
	return dst
}

// nrgbaAt reads any pixel as NRGBA without interface overhead on hot path.
func nrgbaAt(img image.Image, x, y int) (c image.NRGBA) {
	r, g, b, a := img.At(x, y).RGBA()
	if a == 0 { return image.NRGBA{} }
	// pre-multiply → straight alpha
	return image.NRGBA{
		R: uint8(r * 0xff / a),
		G: uint8(g * 0xff / a),
		B: uint8(b * 0xff / a),
		A: uint8(a >> 8),
	}
}
