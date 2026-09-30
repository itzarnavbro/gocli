package password

import (
	"bytes"
	"strings"
	"testing"

	"golang.org/x/crypto/argon2"
)

func TestHashVerify(t *testing.T) {
	h, err := Hash("correct horse")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$v=19$m=65536,t=3,p=2$") {
		t.Fatalf("unexpected format: %s", h)
	}

	ok, rehash, err := Verify("correct horse", h)
	if err != nil || !ok || rehash {
		t.Fatalf("good pw: ok=%v rehash=%v err=%v", ok, rehash, err)
	}
	ok, _, err = Verify("wrong horse", h)
	if err != nil || ok {
		t.Fatalf("bad pw: ok=%v err=%v", ok, err)
	}
}

func TestSaltsAreUnique(t *testing.T) {
	a, _ := Hash("same password")
	b, _ := Hash("same password")
	if a == b {
		t.Fatal("two hashes of the same password are identical")
	}
}

func TestNeedsRehash(t *testing.T) {
	weak := params{m: 8 * 1024, t: 1, p: 1, saltLen: 16, keyLen: 32}
	salt := bytes.Repeat([]byte{1}, 16)
	key := argon2.IDKey([]byte("hunter22"), salt, weak.t, weak.m, weak.p, weak.keyLen)

	ok, rehash, err := Verify("hunter22", encode(weak, salt, key))
	if err != nil || !ok || !rehash {
		t.Fatalf("weak hash: ok=%v rehash=%v err=%v", ok, rehash, err)
	}
}

func TestMalformed(t *testing.T) {
	bad := []string{
		"",
		"plaintext",
		"$argon2id$v=19$m=8,t=1,p=1$c2FsdHNhbHQ",                // missing hash
		"$argon2i$v=19$m=8,t=1,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNo", // wrong variant
		"$argon2id$v=18$m=8,t=1,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA",
		"$argon2id$v=19$m=99999999,t=1,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA", // memory bomb
		"$argon2id$v=19$m=8,t=0,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA",        // t=0 would panic argon2
		"$argon2id$v=19$m=8,t=1,p=0$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA",        // p=0 would panic argon2
		"$argon2id$v=19$m=8,t=1,p=1$!!!$aGFzaGhhc2hoYXNoaGFzaA",
	}
	for _, enc := range bad {
		if _, _, err := Verify("pw", enc); err == nil {
			t.Errorf("accepted %q", enc)
		}
	}
}

func TestValidatePolicy(t *testing.T) {
	if err := Validate("short"); err != ErrTooShort {
		t.Errorf("short: %v", err)
	}
	if err := Validate("longenough"); err != nil {
		t.Errorf("ok pw: %v", err)
	}
	if err := Validate(strings.Repeat("a", 129)); err != ErrTooLong {
		t.Errorf("long: %v", err)
	}
}

func TestDummyIsVerifiable(t *testing.T) {
	if _, _, err := Verify("anything", Dummy()); err != nil {
		t.Fatal(err)
	}
}

func FuzzVerify(f *testing.F) {
	f.Add("$argon2id$v=19$m=8,t=1,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA")
	f.Add("")
	f.Add("$$$$$")
	f.Fuzz(func(t *testing.T, enc string) {
		Verify("pw", enc) // must never panic
	})
}