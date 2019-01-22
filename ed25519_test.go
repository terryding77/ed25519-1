// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ed25519

import (
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

func BenchmarkBaseMult(b *testing.B) {
	b.ResetTimer()
	c := Ed25519()
	b.ReportAllocs()
	b.StartTimer()
	k := []byte{32}
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			c.ScalarBaseMult(k)
		}
	})
}

func BenchmarkScalarMult(b *testing.B) {
	b.ResetTimer()
	c := Ed25519()
	_, x, y, _ := elliptic.GenerateKey(c, rand.Reader)
	priv, _, _, _ := elliptic.GenerateKey(c, rand.Reader)

	b.ReportAllocs()
	b.StartTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			c.ScalarMult(x, y, priv)
		}
	})
}
