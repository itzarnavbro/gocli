package auth

import "testing"

func TestUsernameTable(t *testing.T) {
	cases := []struct {
		in string
		ok bool
	}{
		{"arnav", true}, {"Arnav_01", true}, {"  arnav  ", true}, // trimmed and lowercased
		{"abc", true}, {"a_b", true},
		{"ab", false}, {"", false}, {"has space", false}, {"semi;colon", false},
		{"dash-ed", false}, {"arnav\n", true}, {"ärnav", false},
		{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", false}, // 33 chars
	}
	for _, c := range cases {
		if got := usernameRe.MatchString(normalize(c.in)); got != c.ok {
			t.Errorf("%q: got %v want %v", c.in, got, c.ok)
		}
	}
}

func FuzzUsername(f *testing.F) {
	for _, s := range []string{"arnav", "", "a b", "Ä", "\x00", "ok_name_1"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		n := normalize(in)
		if !usernameRe.MatchString(n) {
			return
		}
		// anything accepted must be 3-32 bytes of [a-z0-9_] only
		if len(n) < 3 || len(n) > 32 {
			t.Fatalf("bad length accepted: %q", n)
		}
		for i := 0; i < len(n); i++ {
			c := n[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_') {
				t.Fatalf("bad byte %q accepted in %q", c, n)
			}
		}
	})
}