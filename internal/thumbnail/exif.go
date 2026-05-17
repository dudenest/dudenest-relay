// Package thumbnail — minimal JPEG EXIF reader for DateTimeOriginal.
// No external dependencies: parses TIFF IFD structure from raw bytes.
// Handles both little-endian (Intel, "II") and big-endian (Motorola, "MM") TIFF byte order.
package thumbnail

import (
	"encoding/binary"
	"io"
	"os"
	"time"
)

// exifDate returns the photo taken date (DateTimeOriginal) from a JPEG file.
// Falls back to DateTime if DateTimeOriginal is absent.
// Returns nil if EXIF is missing or unparseable.
func exifDate(path string) *time.Time {
	f, err := os.Open(path)
	if err != nil { return nil }
	defer f.Close()
	data, err := io.ReadAll(f)
	if err != nil { return nil }
	return parseExifDate(data)
}

// parseExifDate scans JPEG APP1 (FF E1) for EXIF TIFF data and extracts
// DateTimeOriginal (0x9003) or DateTime (0x0132).
func parseExifDate(data []byte) *time.Time {
	if len(data) < 4 || data[0] != 0xFF || data[1] != 0xD8 { return nil } // not JPEG
	i := 2
	for i+3 < len(data) {
		if data[i] != 0xFF { return nil }
		marker := data[i+1]
		segLen := int(data[i+2])<<8 | int(data[i+3]) // big-endian segment length (includes 2-byte len field)
		if segLen < 2 { return nil }
		end := i + 2 + segLen
		if end > len(data) { return nil }
		if marker == 0xE1 && segLen > 8 { // APP1 — may contain EXIF
			seg := data[i+4 : end] // skip FF E1 + 2-byte length
			if len(seg) >= 6 && seg[0] == 'E' && seg[1] == 'x' && seg[2] == 'i' && seg[3] == 'f' && seg[4] == 0 && seg[5] == 0 {
				tiff := seg[6:]
				if t := parseTIFF(tiff); t != nil { return t }
			}
		}
		if marker == 0xDA { break } // SOS (start of scan) — stop scanning
		i = end
	}
	return nil
}

// parseTIFF parses a TIFF block (from EXIF APP1) and returns DateTimeOriginal or DateTime.
func parseTIFF(t []byte) *time.Time {
	if len(t) < 8 { return nil }
	var order binary.ByteOrder
	switch {
	case t[0] == 'I' && t[1] == 'I': order = binary.LittleEndian
	case t[0] == 'M' && t[1] == 'M': order = binary.BigEndian
	default: return nil
	}
	magic := order.Uint16(t[2:4])
	if magic != 42 { return nil }
	ifd0Off := int(order.Uint32(t[4:8]))

	var fallback *time.Time // DateTime tag (less preferred)
	var exifIFDOff int

	// Walk IFD0
	scanIFD(t, ifd0Off, order, func(tag uint16, ascii string) {
		switch tag {
		case 0x9003: // DateTimeOriginal — best
			if ts := parseExifTime(ascii); ts != nil { exifIFDOff = -1; fallback = ts }
		case 0x0132: // DateTime — fallback
			if ts := parseExifTime(ascii); ts != nil && fallback == nil { fallback = ts }
		case 0x8769: // ExifIFD pointer — handled separately
		}
	})
	// If DateTimeOriginal found in IFD0 directly, return it
	if exifIFDOff == -1 { return fallback }

	// Walk ExifIFD (subdir pointer at tag 0x8769 in IFD0)
	scanIFD(t, ifd0Off, order, func(tag uint16, _ string) {}) // need raw uint32 for 0x8769
	exifOff := ifdTagUint32(t, ifd0Off, order, 0x8769)
	if exifOff > 0 {
		scanIFD(t, int(exifOff), order, func(tag uint16, ascii string) {
			if tag == 0x9003 {
				if ts := parseExifTime(ascii); ts != nil { fallback = ts }
			}
		})
	}
	return fallback
}

// scanIFD iterates over IFD entries at offset, calling fn for ASCII tags.
func scanIFD(t []byte, offset int, order binary.ByteOrder, fn func(uint16, string)) {
	if offset+2 > len(t) { return }
	count := int(order.Uint16(t[offset : offset+2]))
	base := offset + 2
	for i := 0; i < count; i++ {
		e := base + i*12
		if e+12 > len(t) { return }
		tag := order.Uint16(t[e : e+2])
		typ := order.Uint16(t[e+2 : e+4])
		cnt := int(order.Uint32(t[e+4 : e+8]))
		if typ == 2 { // ASCII
			var s string
			if cnt <= 4 {
				s = string(t[e+8 : e+8+cnt])
			} else {
				off := int(order.Uint32(t[e+8 : e+12]))
				if off+cnt <= len(t) { s = string(t[off : off+cnt]) }
			}
			fn(tag, trimNull(s))
		}
	}
}

// ifdTagUint32 returns the LONG (uint32) value of a specific tag in an IFD.
func ifdTagUint32(t []byte, offset int, order binary.ByteOrder, wantTag uint16) uint32 {
	if offset+2 > len(t) { return 0 }
	count := int(order.Uint16(t[offset : offset+2]))
	base := offset + 2
	for i := 0; i < count; i++ {
		e := base + i*12
		if e+12 > len(t) { return 0 }
		tag := order.Uint16(t[e : e+2])
		typ := order.Uint16(t[e+2 : e+4])
		if tag == wantTag && typ == 4 { // LONG
			return order.Uint32(t[e+8 : e+12])
		}
	}
	return 0
}

// parseExifTime parses EXIF ASCII date "YYYY:MM:DD HH:MM:SS" → time.Time.
func parseExifTime(s string) *time.Time {
	t, err := time.ParseInLocation("2006:01:02 15:04:05", s, time.Local)
	if err != nil { return nil }
	if t.Year() < 1900 || t.Year() > 2100 { return nil }
	return &t
}

func trimNull(s string) string {
	for i, c := range s {
		if c == 0 { return s[:i] }
	}
	return s
}
