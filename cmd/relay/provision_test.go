package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestProvisionRef(t *testing.T) {
	cases := map[string]string{"": "main", "dev": "main", "v0.25.0": "v0.25.0", "v1.2.3": "v1.2.3"}
	for in, want := range cases {
		if got := provisionRef(in); got != want {
			t.Errorf("provisionRef(%q)=%q, want %q", in, got, want)
		}
	}
}

func TestDownloadTo(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("print('sidecar')\n"))
	}))
	defer srv.Close()
	dest := filepath.Join(t.TempDir(), "rh_x.py")
	if err := downloadTo(srv.URL, dest); err != nil {
		t.Fatalf("downloadTo: %v", err)
	}
	b, _ := os.ReadFile(dest)
	if string(b) != "print('sidecar')\n" {
		t.Fatalf("content=%q", b)
	}
}

func TestDownloadToNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusNotFound)
	}))
	defer srv.Close()
	dest := filepath.Join(t.TempDir(), "rh_x.py")
	if err := downloadTo(srv.URL, dest); err == nil {
		t.Fatal("expected error on 404")
	}
	if _, err := os.Stat(dest); !os.IsNotExist(err) {
		t.Fatal("no file should be written on a failed download")
	}
}

func TestTail(t *testing.T) {
	if got := tail([]byte("abcdef"), 3); got != "def" {
		t.Errorf("tail=%q", got)
	}
	if got := tail([]byte("ab"), 5); got != "ab" {
		t.Errorf("tail=%q", got)
	}
}
