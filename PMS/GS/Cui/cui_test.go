package Cui

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"math/big"
	"strconv"
	"testing"
	"time"
)

func BenchmarkCUI_Setup_RA(b *testing.B) {
	b.ReportAllocs()
	mod := bn254.ID.ScalarField()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// RA key gen
		rsk, err := rand.Int(rand.Reader, mod)
		if err != nil {
			panic(err)
		}
		_ = new(bn254.G1Affine).ScalarMultiplicationBase(rsk)
	}
}

func BenchmarkCUI_Setup_ES(b *testing.B) {
	b.ReportAllocs()
	mod := bn254.ID.ScalarField()

	// RA key gen
	rsk, err := rand.Int(rand.Reader, mod)
	if err != nil {
		panic(err)
	}
	rpk := new(bn254.G1Affine).ScalarMultiplicationBase(rsk)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// ES key gen
		esid := "ESID"
		xi, _ := rand.Int(rand.Reader, mod)
		r1, _ := rand.Int(rand.Reader, mod)
		r2, _ := rand.Int(rand.Reader, mod)
		_ = new(bn254.G1Affine).ScalarMultiplication(rpk, new(big.Int).ModInverse(xi, mod))

		R1 := new(bn254.G1Affine).ScalarMultiplicationBase(r1)
		_ = new(bn254.G1Affine).ScalarMultiplicationBase(r2)
		h := sha256.New()
		h.Write([]byte(esid))
		h.Write(R1.Marshal())
		ho := new(big.Int).SetBytes(h.Sum(nil))
		esk := new(big.Int).Mod(new(big.Int).Add(r1, new(big.Int).Mul(rsk, ho)), mod)
		epk := new(bn254.G1Affine).ScalarMultiplicationBase(esk)

		h.Reset()
		h.Write(new(bn254.G1Affine).ScalarMultiplication(epk, rsk).Marshal())
		ho1 := new(big.Int).SetBytes(h.Sum(nil))
		v := new(big.Int).Add(r2, rsk)
		_ = new(big.Int).Xor(v, ho1)
	}
}

func BenchmarkCUI_UIdGen(b *testing.B) {
	b.ReportAllocs()
	mod := bn254.ID.ScalarField()

	// RA key gen
	rsk, err := rand.Int(rand.Reader, mod)
	if err != nil {
		panic(err)
	}
	rpk := new(bn254.G1Affine).ScalarMultiplicationBase(rsk)

	// ES key gen
	esid := "ESID"
	xi, _ := rand.Int(rand.Reader, mod)
	r1, _ := rand.Int(rand.Reader, mod)
	r2, _ := rand.Int(rand.Reader, mod)
	_ = new(bn254.G1Affine).ScalarMultiplication(rpk, new(big.Int).ModInverse(xi, mod))

	R1 := new(bn254.G1Affine).ScalarMultiplicationBase(r1)
	_ = new(bn254.G1Affine).ScalarMultiplicationBase(r2)
	h := sha256.New()
	h.Write([]byte(esid))
	h.Write(R1.Marshal())
	ho := new(big.Int).SetBytes(h.Sum(nil))
	esk := new(big.Int).Mod(new(big.Int).Add(r1, new(big.Int).Mul(rsk, ho)), mod)
	epk := new(bn254.G1Affine).ScalarMultiplicationBase(esk)

	h.Reset()
	h.Write(new(bn254.G1Affine).ScalarMultiplication(epk, rsk).Marshal())
	ho1 := new(big.Int).SetBytes(h.Sum(nil))
	v := new(big.Int).Add(r2, rsk)
	_ = new(big.Int).Xor(v, ho1)
	// // ommit verification

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// sd key gen
		sdid := "SDID"
		k, _ := rand.Int(rand.Reader, mod)
		K := new(bn254.G1Affine).ScalarMultiplicationBase(k)
		h.Reset()
		h.Write([]byte(sdid))
		h.Write(K.Marshal())
		ho2 := new(big.Int).SetBytes(h.Sum(nil))
		w := new(big.Int).Mod(new(big.Int).Add(k, new(big.Int).Mul(rsk, ho2)), mod)
		W := new(bn254.G1Affine).ScalarMultiplicationBase(w)
		_, err = Sign(rsk, rpk, W)
		if err != nil {
			panic(err)
		}
	}
}

func BenchmarkCUI_GenPsu(b *testing.B) {
	b.ReportAllocs()
	mod := bn254.ID.ScalarField()

	// RA key gen
	rsk, err := rand.Int(rand.Reader, mod)
	if err != nil {
		panic(err)
	}
	rpk := new(bn254.G1Affine).ScalarMultiplicationBase(rsk)

	// ES key gen
	esid := "ESID"
	xi, _ := rand.Int(rand.Reader, mod)
	r1, _ := rand.Int(rand.Reader, mod)
	r2, _ := rand.Int(rand.Reader, mod)
	U := new(bn254.G1Affine).ScalarMultiplication(rpk, new(big.Int).ModInverse(xi, mod))

	R1 := new(bn254.G1Affine).ScalarMultiplicationBase(r1)
	_ = new(bn254.G1Affine).ScalarMultiplicationBase(r2)
	h := sha256.New()
	h.Write([]byte(esid))
	h.Write(R1.Marshal())
	ho := new(big.Int).SetBytes(h.Sum(nil))
	esk := new(big.Int).Mod(new(big.Int).Add(r1, new(big.Int).Mul(rsk, ho)), mod)
	epk := new(bn254.G1Affine).ScalarMultiplicationBase(esk)

	h.Reset()
	h.Write(new(bn254.G1Affine).ScalarMultiplication(epk, rsk).Marshal())
	ho1 := new(big.Int).SetBytes(h.Sum(nil))
	v := new(big.Int).Add(r2, rsk)
	_ = new(big.Int).Xor(v, ho1)
	// // ommit verification

	// sd key gen
	sdid := "SDID"
	k, _ := rand.Int(rand.Reader, mod)
	K := new(bn254.G1Affine).ScalarMultiplicationBase(k)
	h.Reset()
	h.Write([]byte(sdid))
	h.Write(K.Marshal())
	ho2 := new(big.Int).SetBytes(h.Sum(nil))
	w := new(big.Int).Mod(new(big.Int).Add(k, new(big.Int).Mul(rsk, ho2)), mod)
	W := new(bn254.G1Affine).ScalarMultiplicationBase(w)
	_, err = Sign(rsk, rpk, W)
	if err != nil {
		panic(err)
	}
	// // ommit verification

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// psu gen
		// // ommit the sym enc
		ts := time.Now().Unix()
		//TK := new(bn254.G1Affine).ScalarMultiplication(epk, w)

		l := big.NewInt(2)
		z, _ := rand.Int(rand.Reader, mod)
		dl, _ := rand.Int(rand.Reader, mod)
		Dl := new(bn254.G1Affine).ScalarMultiplicationBase(dl)
		h.Reset()
		h.Write([]byte(strconv.FormatInt(ts, 10)))
		hto := new(big.Int).SetBytes(h.Sum(nil))
		hto.Add(hto, l)
		h.Reset()
		h.Write(esk.Bytes())
		h.Write(hto.Bytes())
		hesko := new(big.Int).SetBytes(h.Sum(nil))
		alpha := new(big.Int).Add(z, hesko)
		sigma1 := new(bn254.G1Affine).ScalarMultiplication(U, alpha)
		sigma2 := new(bn254.G1Affine).Add(W, new(bn254.G1Affine).ScalarMultiplication(rpk, alpha))
		h.Reset()
		h.Write(l.Bytes())
		h.Write(Dl.Marshal())
		h.Write(sigma1.Marshal())
		h.Write(sigma2.Marshal())
		hrhoo := new(big.Int).SetBytes(h.Sum(nil))
		_ = new(big.Int).Add(dl, new(big.Int).Mul(v, hrhoo))
	}
}

func BenchmarkCUI_Revoke(b *testing.B) {
	b.ReportAllocs()
	mod := bn254.ID.ScalarField()

	// RA key gen
	rsk, err := rand.Int(rand.Reader, mod)
	if err != nil {
		panic(err)
	}
	rpk := new(bn254.G1Affine).ScalarMultiplicationBase(rsk)

	// ES key gen
	esid := "ESID"
	xi, _ := rand.Int(rand.Reader, mod)
	r1, _ := rand.Int(rand.Reader, mod)
	r2, _ := rand.Int(rand.Reader, mod)
	U := new(bn254.G1Affine).ScalarMultiplication(rpk, new(big.Int).ModInverse(xi, mod))

	//assert.Equal(t, new(bn254.G1Affine).ScalarMultiplication(U, xi), rpk)

	R1 := new(bn254.G1Affine).ScalarMultiplicationBase(r1)
	_ = new(bn254.G1Affine).ScalarMultiplicationBase(r2)
	h := sha256.New()
	h.Write([]byte(esid))
	h.Write(R1.Marshal())
	ho := new(big.Int).SetBytes(h.Sum(nil))
	esk := new(big.Int).Mod(new(big.Int).Add(r1, new(big.Int).Mul(rsk, ho)), mod)
	epk := new(bn254.G1Affine).ScalarMultiplicationBase(esk)

	h.Reset()
	h.Write(new(bn254.G1Affine).ScalarMultiplication(epk, rsk).Marshal())
	ho1 := new(big.Int).SetBytes(h.Sum(nil))
	v := new(big.Int).Add(r2, rsk)
	_ = new(big.Int).Xor(v, ho1)
	// // ommit verification

	// sd key gen
	sdid := "SDID"
	k, _ := rand.Int(rand.Reader, mod)
	K := new(bn254.G1Affine).ScalarMultiplicationBase(k)
	h.Reset()
	h.Write([]byte(sdid))
	h.Write(K.Marshal())
	ho2 := new(big.Int).SetBytes(h.Sum(nil))
	w := new(big.Int).Mod(new(big.Int).Add(k, new(big.Int).Mul(rsk, ho2)), mod)
	W := new(bn254.G1Affine).ScalarMultiplicationBase(w)
	_, err = Sign(rsk, rpk, W)
	if err != nil {
		panic(err)
	}
	// // ommit verification

	// psu gen
	// // ommit the sym enc
	ts := time.Now().Unix()
	//TK := new(bn254.G1Affine).ScalarMultiplication(epk, w)

	l := big.NewInt(2)
	z, _ := rand.Int(rand.Reader, mod)
	dl, _ := rand.Int(rand.Reader, mod)
	Dl := new(bn254.G1Affine).ScalarMultiplicationBase(dl)
	h.Reset()
	h.Write([]byte(strconv.FormatInt(ts, 10)))
	hto := new(big.Int).SetBytes(h.Sum(nil))
	hto.Add(hto, l)
	h.Reset()
	h.Write(esk.Bytes())
	h.Write(hto.Bytes())
	hesko := new(big.Int).SetBytes(h.Sum(nil))
	alpha := new(big.Int).Add(z, hesko)
	sigma1 := new(bn254.G1Affine).ScalarMultiplication(U, alpha)
	sigma2 := new(bn254.G1Affine).Add(W, new(bn254.G1Affine).ScalarMultiplication(rpk, alpha))
	h.Reset()
	h.Write(l.Bytes())
	h.Write(Dl.Marshal())
	h.Write(sigma1.Marshal())
	h.Write(sigma2.Marshal())
	hrhoo := new(big.Int).SetBytes(h.Sum(nil))
	_ = new(big.Int).Add(dl, new(big.Int).Mul(v, hrhoo))

	// psu ver -- omit

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// revoke
		_ = new(bn254.G1Affine).Add(sigma2, new(bn254.G1Affine).ScalarMultiplication(sigma1, new(big.Int).Neg(esk)))
	}
}

//func TestCui(t *testing.T) {
//	mod := bn254.ID.ScalarField()
//
//	// RA key gen
//	rsk, err := rand.Int(rand.Reader, mod)
//	if err != nil {
//		t.Fatal(err)
//	}
//	rpk := new(bn254.G1Affine).ScalarMultiplicationBase(rsk)
//
//	// ES key gen
//	esid := "ESID"
//	xi, _ := rand.Int(rand.Reader, mod)
//	r1, _ := rand.Int(rand.Reader, mod)
//	r2, _ := rand.Int(rand.Reader, mod)
//	U := new(bn254.G1Affine).ScalarMultiplication(rpk, new(big.Int).ModInverse(xi, mod))
//
//	assert.Equal(t, new(bn254.G1Affine).ScalarMultiplication(U, xi), rpk)
//
//	R1 := new(bn254.G1Affine).ScalarMultiplicationBase(r1)
//	R2 := new(bn254.G1Affine).ScalarMultiplicationBase(r2)
//	h := sha256.New()
//	h.Write([]byte(esid))
//	h.Write(R1.Marshal())
//	ho := new(big.Int).SetBytes(h.Sum(nil))
//	esk := new(big.Int).Mod(new(big.Int).Add(r1, new(big.Int).Mul(rsk, ho)), mod)
//	epk := new(bn254.G1Affine).ScalarMultiplicationBase(esk)
//
//	h.Reset()
//	h.Write(new(bn254.G1Affine).ScalarMultiplication(epk, rsk).Marshal())
//	ho1 := new(big.Int).SetBytes(h.Sum(nil))
//	v := new(big.Int).Add(r2, rsk)
//	lambda := new(big.Int).Xor(v, ho1)
//	// // ommit verification
//
//	// sd key gen
//	sdid := "SDID"
//	k, _ := rand.Int(rand.Reader, mod)
//	K := new(bn254.G1Affine).ScalarMultiplicationBase(k)
//	h.Reset()
//	h.Write([]byte(sdid))
//	h.Write(K.Marshal())
//	ho2 := new(big.Int).SetBytes(h.Sum(nil))
//	w := new(big.Int).Mod(new(big.Int).Add(k, new(big.Int).Mul(rsk, ho2)), mod)
//	W := new(bn254.G1Affine).ScalarMultiplicationBase(w)
//	sigW, err := Sign(rsk, rpk, W)
//	if err != nil {
//		t.Fatal(err)
//	}
//	// // ommit verification
//
//	// psu gen
//	// // ommit the sym enc
//	ts := time.Now().Unix()
//	TK := new(bn254.G1Affine).ScalarMultiplication(epk, w)
//
//	l := big.NewInt(2)
//	z, _ := rand.Int(rand.Reader, mod)
//	dl, _ := rand.Int(rand.Reader, mod)
//	Dl := new(bn254.G1Affine).ScalarMultiplicationBase(dl)
//	h.Reset()
//	h.Write([]byte(strconv.FormatInt(ts, 10)))
//	hto := new(big.Int).SetBytes(h.Sum(nil))
//	hto.Add(hto, l)
//	h.Reset()
//	h.Write(esk.Bytes())
//	h.Write(hto.Bytes())
//	hesko := new(big.Int).SetBytes(h.Sum(nil))
//	alpha := new(big.Int).Add(z, hesko)
//	sigma1 := new(bn254.G1Affine).ScalarMultiplication(U, alpha)
//	sigma2 := new(bn254.G1Affine).Add(W, new(bn254.G1Affine).ScalarMultiplication(rpk, alpha))
//	h.Reset()
//	h.Write(l.Bytes())
//	h.Write(Dl.Marshal())
//	h.Write(sigma1.Marshal())
//	h.Write(sigma2.Marshal())
//	hrhoo := new(big.Int).SetBytes(h.Sum(nil))
//	rho := new(big.Int).Add(dl, new(big.Int).Mul(v, hrhoo))
//
//	// psu ver -- omit
//
//	// revoke
//	W_ := new(bn254.G1Affine).Add(sigma2, new(bn254.G1Affine).ScalarMultiplication(sigma1, new(big.Int).Neg(esk)))
//}

type Schnorr struct {
	s *big.Int
	R *bn254.G1Affine
}

func Sign(sk *big.Int, pk, M *bn254.G1Affine) (*Schnorr, error) {
	mod := bn254.ID.ScalarField()
	r, err := rand.Int(rand.Reader, mod)
	if err != nil {
		return nil, errors.New("failed to generate r: " + err.Error())
	}
	R := new(bn254.G1Affine).ScalarMultiplicationBase(r)
	h := sha256.New()
	h.Write(M.Marshal())
	h.Write(R.Marshal())
	h.Write(pk.Marshal())
	c := new(big.Int).SetBytes(h.Sum(nil))
	s := new(big.Int).Mod(new(big.Int).Add(r, new(big.Int).Mul(c, sk)), mod)
	return &Schnorr{s, R}, nil
}

func Verify(sig *Schnorr, pk, M *bn254.G1Affine) error {
	h := sha256.New()
	h.Write(M.Marshal())
	h.Write(sig.R.Marshal())
	h.Write(pk.Marshal())
	c := new(big.Int).SetBytes(h.Sum(nil))
	sG := new(bn254.G1Affine).ScalarMultiplicationBase(sig.s)
	RXc := new(bn254.G1Affine).Add(sig.R, new(bn254.G1Affine).ScalarMultiplication(pk, c))

	if !sG.Equal(RXc) {
		return errors.New("failed to verify")
	}
	return nil
}
