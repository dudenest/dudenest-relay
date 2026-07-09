package remotehand

import "testing"

func TestDisplayPoolAllocateUntilEmpty(t *testing.T) {
	p := NewDisplayPool(":99", ":100")
	if p.Available() != 2 {
		t.Fatalf("want 2 available, got %d", p.Available())
	}
	a, err := p.Allocate()
	if err != nil {
		t.Fatal(err)
	}
	b, err := p.Allocate()
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatalf("allocated same display twice: %s", a)
	}
	if _, err := p.Allocate(); err != ErrNoDisplay {
		t.Fatalf("want ErrNoDisplay, got %v", err)
	}
}

func TestDisplayPoolReleaseMakesAvailable(t *testing.T) {
	p := NewDisplayPool(":99")
	d, _ := p.Allocate()
	if p.Available() != 0 {
		t.Fatal("should be empty after allocate")
	}
	p.Release(d)
	if p.Available() != 1 {
		t.Fatal("release should restore availability")
	}
	d2, err := p.Allocate()
	if err != nil || d2 != d {
		t.Fatalf("want re-allocate %s, got %s err=%v", d, d2, err)
	}
}

func TestDisplayPoolReleaseIsIdempotentAndValidated(t *testing.T) {
	p := NewDisplayPool(":99")
	d, _ := p.Allocate()
	p.Release(d)
	p.Release(d)          // double release must not duplicate
	p.Release(":unknown") // foreign display must be ignored
	if p.Available() != 1 {
		t.Fatalf("want 1 available, got %d", p.Available())
	}
}

func TestDisplayPoolDefaultAndDedupe(t *testing.T) {
	if NewDisplayPool().Available() != 1 { // default :99
		t.Fatal("default pool should have 1 display")
	}
	if NewDisplayPool(":99", ":99").Available() != 1 { // dedupe seeds
		t.Fatal("duplicate seeds should dedupe")
	}
}
