package obfs

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestChameleonObfuscator(t *testing.T) {
	o, err := NewChameleonObfuscator([]byte("average_password"))
	assert.NoError(t, err)

	in := make([]byte, 1200)
	_, _ = rand.Read(in)
	oOut := make([]byte, 2048)
	dOut := make([]byte, 2048)

	for i := 0; i < 1000; i++ {
		_, _ = rand.Read(in)
		n := o.Obfuscate(in, oOut)
		assert.Greater(t, n, 0)

		n = o.Deobfuscate(oOut[:n], dOut)
		assert.Equal(t, len(in), n)
		assert.Equal(t, in, dOut[:n])
	}
}

func BenchmarkChameleonObfuscator_Obfuscate(b *testing.B) {
	o, _ := NewChameleonObfuscator([]byte("average_password"))
	in := make([]byte, 1200)
	_, _ = rand.Read(in)
	out := make([]byte, 2048)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		o.Obfuscate(in, out)
	}
}

func BenchmarkChameleonObfuscator_Deobfuscate(b *testing.B) {
	o, _ := NewChameleonObfuscator([]byte("average_password"))
	in := make([]byte, 1200)
	_, _ = rand.Read(in)
	out := make([]byte, 2048)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		o.Deobfuscate(in, out)
	}
}
