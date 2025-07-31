package OPBench

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"testing"
)

func BenchmarkScalarMulG1(b *testing.B) {
	mod := bn254.ID.ScalarField()
	r, err := rand.Int(rand.Reader, mod)
	if err != nil {
		panic(errors.New("Error generating key: " + err.Error()))
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = new(bn254.G1Affine).ScalarMultiplicationBase(r)
	}
}

func BenchmarkScalarAddG1(b *testing.B) {
	mod := bn254.ID.ScalarField()
	r0, err := rand.Int(rand.Reader, mod)
	if err != nil {
		panic(errors.New("Error generating key: " + err.Error()))
	}
	r1, _ := rand.Int(rand.Reader, mod)
	B0 := new(bn254.G1Affine).ScalarMultiplicationBase(r0)
	B1 := new(bn254.G1Affine).ScalarMultiplicationBase(r1)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		new(bn254.G1Affine).Add(B0, B1)
	}
}

func BenchmarkScalarMulG2(b *testing.B) {
	mod := bn254.ID.ScalarField()
	r, err := rand.Int(rand.Reader, mod)
	if err != nil {
		panic(errors.New("Error generating key: " + err.Error()))
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = new(bn254.G2Affine).ScalarMultiplicationBase(r)
	}
}

func BenchmarkScalarAddG2(b *testing.B) {
	mod := bn254.ID.ScalarField()
	r0, err := rand.Int(rand.Reader, mod)
	if err != nil {
		panic(errors.New("Error generating key: " + err.Error()))
	}
	r1, _ := rand.Int(rand.Reader, mod)
	B0 := new(bn254.G2Affine).ScalarMultiplicationBase(r0)
	B1 := new(bn254.G2Affine).ScalarMultiplicationBase(r1)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		new(bn254.G2Affine).Add(B0, B1)
	}
}

func BenchmarkPairing(b *testing.B) {
	mod := bn254.ID.ScalarField()
	l0, err := rand.Int(rand.Reader, mod)
	if err != nil {
		panic(errors.New("Error generating key: " + err.Error()))
	}
	r0, _ := rand.Int(rand.Reader, mod)
	L0 := new(bn254.G1Affine).ScalarMultiplicationBase(l0)
	R0 := new(bn254.G2Affine).ScalarMultiplicationBase(r0)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = bn254.Pair([]bn254.G1Affine{*L0}, []bn254.G2Affine{*R0})
	}
}

func BenchmarkPairingCheck(b *testing.B) {
	mod := bn254.ID.ScalarField()
	l0, err := rand.Int(rand.Reader, mod)
	if err != nil {
		panic(errors.New("Error generating key: " + err.Error()))
	}
	l1, _ := rand.Int(rand.Reader, mod)
	r0, _ := rand.Int(rand.Reader, mod)
	r1, _ := rand.Int(rand.Reader, mod)
	L0 := new(bn254.G1Affine).ScalarMultiplicationBase(l0)
	L1 := new(bn254.G1Affine).ScalarMultiplicationBase(l1)
	R0 := new(bn254.G2Affine).ScalarMultiplicationBase(r0)
	R1 := new(bn254.G2Affine).ScalarMultiplicationBase(r1)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		P0, _ := bn254.Pair([]bn254.G1Affine{*L0}, []bn254.G2Affine{*R0})
		P1, _ := bn254.Pair([]bn254.G1Affine{*L1}, []bn254.G2Affine{*R1})
		if P0.Equal(&P1) {
			panic(errors.New("lucky"))
		}
	}
}

func BenchmarkSHA256(b *testing.B) {
	mod := bn254.ID.ScalarField()
	s, _ := rand.Int(rand.Reader, mod)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for j := 0; j < 10000; j++ {
			h := sha256.New()
			_, _ = h.Write(s.Bytes())
			h.Sum(nil)
		}
	}
}

func BenchmarkMiMC(b *testing.B) {
	s, _ := rand.Int(rand.Reader, fr.Modulus())
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h := mimc.NewMiMC()
		_, _ = h.Write(s.Bytes())
		h.Sum(nil)
	}
}

func TestSize(t *testing.T) {
	mod := bn254.ID.ScalarField()
	s1, err := rand.Int(rand.Reader, mod)
	if err != nil {
		panic(errors.New("Error generating key: " + err.Error()))
	}
	g1a := new(bn254.G1Affine).ScalarMultiplicationBase(s1)
	fmt.Println("G1Affine-Marshal: ", len(g1a.Marshal()))
	fmt.Println("G1Affine-Compress: ", len(g1a.Bytes()))
	fmt.Println("Scalar: ", len(s1.Bytes()))

	indG1A := g1a.Bytes()
	fmt.Println("G1Affine-Base64: ", len(base64.StdEncoding.EncodeToString(indG1A[:])))
}
