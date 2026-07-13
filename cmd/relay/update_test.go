package main

import "testing"

func TestVersionGreater(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{{"v0.24.7", "v0.24.6", true}, {"v0.24.6", "v0.24.6", false}, {"v0.24.5", "v0.24.6", false}, {"v0.25.0", "v0.24.99", true}, {"dev", "v0.24.6", false}}
	for _, tc := range cases {
		if got := versionGreater(tc.a, tc.b); got != tc.want {
			t.Fatalf("versionGreater(%q,%q)=%v want %v", tc.a, tc.b, got, tc.want)
		}
	}
}
