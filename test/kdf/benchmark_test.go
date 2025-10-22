package kdf_test

import (
	"testing"

	"github.com/AeonDave/cryptonite-go/kdf"
)

func makeBytes(length int, seed byte) []byte {
	buf := make([]byte, length)
	for i := range buf {
		buf[i] = seed + byte(i)
	}
	return buf
}

func BenchmarkKDF(b *testing.B) {
	secret := makeBytes(32, 0x61)
	salt := makeBytes(16, 0x71)
	info := makeBytes(32, 0x81)
	password := makeBytes(16, 0x91)
	dkLen := 32

	b.Run("HKDF-SHA256", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(int64(dkLen))
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if out, err := kdf.HKDFSHA256(secret, salt, info, dkLen); err != nil || len(out) != dkLen {
				b.Fatalf("hkdf-sha256 failed: %v len=%d", err, len(out))
			}
		}
	})

	b.Run("HKDF-BLAKE2b", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(int64(dkLen))
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if out, err := kdf.HKDFBlake2b(secret, salt, info, dkLen); err != nil || len(out) != dkLen {
				b.Fatalf("hkdf-blake2b failed: %v len=%d", err, len(out))
			}
		}
	})

	b.Run("PBKDF2-SHA1", func(b *testing.B) {
		iterations := 10_000
		b.ReportAllocs()
		b.SetBytes(int64(dkLen))
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if out, err := kdf.PBKDF2SHA1(password, salt, iterations, dkLen); err != nil || len(out) != dkLen {
				b.Fatalf("pbkdf2-sha1 failed: %v len=%d", err, len(out))
			}
		}
	})

	b.Run("PBKDF2-SHA256", func(b *testing.B) {
		iterations := 10_000
		b.ReportAllocs()
		b.SetBytes(int64(dkLen))
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if out, err := kdf.PBKDF2SHA256(password, salt, iterations, dkLen); err != nil || len(out) != dkLen {
				b.Fatalf("pbkdf2-sha256 failed: %v len=%d", err, len(out))
			}
		}
	})

	b.Run("Argon2id", func(b *testing.B) {
		timeCost := uint32(1)
		memoryKiB := uint32(4 * 1024)
		threads := uint32(1)
		b.ReportAllocs()
		b.SetBytes(int64(dkLen))
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if out, err := kdf.Argon2id(secret, salt, timeCost, memoryKiB, threads, dkLen); err != nil || len(out) != dkLen {
				b.Fatalf("argon2id failed: %v len=%d", err, len(out))
			}
		}
	})

	b.Run("Scrypt", func(b *testing.B) {
		n := 1 << 15
		r := 8
		p := 1
		b.ReportAllocs()
		b.SetBytes(int64(dkLen))
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if out, err := kdf.Scrypt(password, salt, n, r, p, dkLen); err != nil || len(out) != dkLen {
				b.Fatalf("scrypt failed: %v len=%d", err, len(out))
			}
		}
	})
}
