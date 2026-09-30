package password

import "testing"

func BenchmarkHash(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if _, err := Hash("benchmark password"); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerify(b *testing.B) {
	h, _ := Hash("benchmark password")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if ok, _, _ := Verify("benchmark password", h); !ok {
			b.Fatal("verify failed")
		}
	}
}