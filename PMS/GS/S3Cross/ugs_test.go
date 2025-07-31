package S3Cross

import (
	"crypto/rand"
	"errors"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/stretchr/testify/assert"
	"math/big"
	"testing"
)

func BenchmarkGroupSign(b *testing.B) {
	mod := bn254.ID.ScalarField()
	sk, err := rand.Int(rand.Reader, mod)
	if err != nil {
		panic(err)
	}
	gamma, _ := rand.Int(rand.Reader, mod)

	bbsSE, err := InitBbsSE(gamma, sk)
	if err != nil {
		panic(err)
	}

	y, _ := rand.Int(rand.Reader, mod)
	Y0 := new(bn254.G1Affine).ScalarMultiplication(bbsSE.h0, new(big.Int).Neg(y))
	Y := new(bn254.G1Affine).ScalarMultiplication(bbsSE.h, new(big.Int).Neg(y))
	user0, err := bbsSE.UserKeyGen(Y0, Y)
	if err != nil {
		panic(err)
	}
	user0.y = y

	M, err := getRandomG1Affine()
	if err != nil {
		panic(err)
	}
	r, err := rand.Int(rand.Reader, mod)
	if err != nil {
		panic(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err = user0.GroupSign(M, r)
		if err != nil {
			panic(errors.New("failed to sign group signature: " + err.Error()))
		}
	}
}

func BenchmarkGroupVerify(b *testing.B) {
	mod := bn254.ID.ScalarField()
	sk, err := rand.Int(rand.Reader, mod)
	if err != nil {
		panic(err)
	}
	gamma, _ := rand.Int(rand.Reader, mod)

	bbsSE, err := InitBbsSE(gamma, sk)
	if err != nil {
		panic(err)
	}

	y, _ := rand.Int(rand.Reader, mod)
	Y0 := new(bn254.G1Affine).ScalarMultiplication(bbsSE.h0, new(big.Int).Neg(y))
	Y := new(bn254.G1Affine).ScalarMultiplication(bbsSE.h, new(big.Int).Neg(y))
	user0, err := bbsSE.UserKeyGen(Y0, Y)
	if err != nil {
		panic(err)
	}
	user0.y = y

	M, err := getRandomG1Affine()
	if err != nil {
		panic(err)
	}
	r, err := rand.Int(rand.Reader, mod)
	if err != nil {
		panic(err)
	}
	gs, err := user0.GroupSign(M, r)
	if err != nil {
		panic(errors.New("failed to sign group signature: " + err.Error()))
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err = GroupVerify(gs, bbsSE.Params)
		if err != nil {
			panic(err)
		}
	}
}

func BenchmarkOpen(b *testing.B) {
	b.ReportAllocs()
	mod := bn254.ID.ScalarField()
	sk, err := rand.Int(rand.Reader, mod)
	if err != nil {
		panic(err)
	}
	gamma, _ := rand.Int(rand.Reader, mod)

	bbsSE, err := InitBbsSE(gamma, sk)
	if err != nil {
		panic(err)
	}

	// user key y
	y, _ := rand.Int(rand.Reader, mod)
	Y0 := new(bn254.G1Affine).ScalarMultiplication(bbsSE.h0, new(big.Int).Neg(y))
	Y := new(bn254.G1Affine).ScalarMultiplication(bbsSE.h, new(big.Int).Neg(y))
	user, err := bbsSE.UserKeyGen(Y0, Y)
	if err != nil {
		panic(err)
	}
	user.y = y

	M, err := getRandomG1Affine()
	if err != nil {
		panic(err)
	}
	r, err := rand.Int(rand.Reader, mod)
	if err != nil {
		panic(err)
	}
	gs, err := user.GroupSign(M, r)
	if err != nil {
		panic(err)
	}

	err = GroupVerify(gs, user.Params)
	if err != nil {
		panic(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = bbsSE.Open(gs)
	}
}

func BenchmarkRevokeGen(b *testing.B) {
	mod := bn254.ID.ScalarField()
	sk, err := rand.Int(rand.Reader, mod)
	if err != nil {
		panic(err)
	}
	gamma, _ := rand.Int(rand.Reader, mod)

	bbsSE, err := InitBbsSE(gamma, sk)
	if err != nil {
		panic(err)
	}

	// user 0
	y, _ := rand.Int(rand.Reader, mod)
	Y0 := new(bn254.G1Affine).ScalarMultiplication(bbsSE.h0, new(big.Int).Neg(y))
	Y := new(bn254.G1Affine).ScalarMultiplication(bbsSE.h, new(big.Int).Neg(y))
	user, err := bbsSE.UserKeyGen(Y0, Y)
	if err != nil {
		panic(err)
	}
	user.y = y

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = bbsSE.RevokeGen(user.x)
	}

}

func BenchmarkParamsUpdate(b *testing.B) {
	mod := bn254.ID.ScalarField()
	sk, err := rand.Int(rand.Reader, mod)
	if err != nil {
		panic(err)
	}
	gamma, _ := rand.Int(rand.Reader, mod)

	bbsSE, err := InitBbsSE(gamma, sk)
	if err != nil {
		panic(err)
	}

	// user 0
	y0, _ := rand.Int(rand.Reader, mod)
	Y00 := new(bn254.G1Affine).ScalarMultiplication(bbsSE.h0, new(big.Int).Neg(y0))
	Y0 := new(bn254.G1Affine).ScalarMultiplication(bbsSE.h, new(big.Int).Neg(y0))
	user0, err := bbsSE.UserKeyGen(Y00, Y0)
	if err != nil {
		panic(err)
	}
	user0.y = y0

	// user 1
	y1, _ := rand.Int(rand.Reader, mod)
	Y10 := new(bn254.G1Affine).ScalarMultiplication(bbsSE.h0, new(big.Int).Neg(y1))
	Y1 := new(bn254.G1Affine).ScalarMultiplication(bbsSE.h, new(big.Int).Neg(y1))
	user1, err := bbsSE.UserKeyGen(Y10, Y1)
	if err != nil {
		panic(err)
	}
	user1.y = y1

	rk := bbsSE.RevokeGen(user1.x)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = user0.RevokeExe(rk)
	}
}

// ========================= Test =========================

func TestKeyGen(t *testing.T) {
	mod := bn254.ID.ScalarField()
	sk, err := rand.Int(rand.Reader, mod)
	if err != nil {
		panic(err)
	}
	gamma, _ := rand.Int(rand.Reader, mod)

	bbsSE, err := InitBbsSE(gamma, sk)
	if err != nil {
		panic(err)
	}

	// user key y
	y, _ := rand.Int(rand.Reader, mod)
	Y0 := new(bn254.G1Affine).ScalarMultiplication(bbsSE.h0, new(big.Int).Neg(y))
	Y := new(bn254.G1Affine).ScalarMultiplication(bbsSE.h, new(big.Int).Neg(y))
	user, err := bbsSE.UserKeyGen(Y0, Y)
	if err != nil {
		panic(err)
	}
	user.y = y
	err = user.UserKeyVerify()
	if err != nil {
		panic(errors.New("failed to verify user key: " + err.Error()))
	}
}

func TestGroupSignature(t *testing.T) {
	mod := bn254.ID.ScalarField()
	sk, err := rand.Int(rand.Reader, mod)
	if err != nil {
		panic(err)
	}
	gamma, _ := rand.Int(rand.Reader, mod)

	bbsSE, err := InitBbsSE(gamma, sk)
	if err != nil {
		panic(err)
	}

	// user key y
	y, _ := rand.Int(rand.Reader, mod)
	Y0 := new(bn254.G1Affine).ScalarMultiplication(bbsSE.h0, new(big.Int).Neg(y))
	Y := new(bn254.G1Affine).ScalarMultiplication(bbsSE.h, new(big.Int).Neg(y))
	user, err := bbsSE.UserKeyGen(Y0, Y)
	if err != nil {
		panic(err)
	}
	user.y = y

	M, err := getRandomG1Affine()
	if err != nil {
		panic(err)
	}
	r, err := rand.Int(rand.Reader, mod)
	if err != nil {
		panic(err)
	}
	gs, err := user.GroupSign(M, r)
	if err != nil {
		panic(err)
	}

	err = GroupVerify(gs, user.Params)
	if err != nil {
		panic("failed to verify group signature: " + err.Error())
	}
}

func TestOpen(t *testing.T) {
	mod := bn254.ID.ScalarField()
	sk, err := rand.Int(rand.Reader, mod)
	assert.Nil(t, err)
	gamma, _ := rand.Int(rand.Reader, mod)

	bbsSE, err := InitBbsSE(gamma, sk)
	assert.Nil(t, err)

	// user key y
	y, _ := rand.Int(rand.Reader, mod)
	Y0 := new(bn254.G1Affine).ScalarMultiplication(bbsSE.h0, new(big.Int).Neg(y))
	Y := new(bn254.G1Affine).ScalarMultiplication(bbsSE.h, new(big.Int).Neg(y))
	user, err := bbsSE.UserKeyGen(Y0, Y)
	assert.Nil(t, err)
	user.y = y

	M, err := getRandomG1Affine()
	assert.Nil(t, err)
	r, err := rand.Int(rand.Reader, mod)
	assert.Nil(t, err)
	gs, err := user.GroupSign(M, r)
	assert.Nil(t, err)

	assert.Nil(t, GroupVerify(gs, user.Params))

	Y_ := bbsSE.Open(gs)
	assert.Equal(t, Y, Y_)
}

func TestRevoke(t *testing.T) {
	mod := bn254.ID.ScalarField()
	sk, err := rand.Int(rand.Reader, mod)
	if err != nil {
		panic(err)
	}
	gamma, _ := rand.Int(rand.Reader, mod)

	bbsSE, err := InitBbsSE(gamma, sk)
	if err != nil {
		panic(err)
	}

	// user 0
	y0, _ := rand.Int(rand.Reader, mod)
	Y00 := new(bn254.G1Affine).ScalarMultiplication(bbsSE.h0, new(big.Int).Neg(y0))
	Y0 := new(bn254.G1Affine).ScalarMultiplication(bbsSE.h, new(big.Int).Neg(y0))
	user0, err := bbsSE.UserKeyGen(Y00, Y0)
	if err != nil {
		panic(err)
	}
	user0.y = y0

	// user 1
	y1, _ := rand.Int(rand.Reader, mod)
	Y10 := new(bn254.G1Affine).ScalarMultiplication(bbsSE.h0, new(big.Int).Neg(y1))
	Y1 := new(bn254.G1Affine).ScalarMultiplication(bbsSE.h, new(big.Int).Neg(y1))
	user1, err := bbsSE.UserKeyGen(Y10, Y1)
	if err != nil {
		panic(err)
	}
	user1.y = y1

	assert.Nil(t, user0.UserKeyVerify())
	assert.Nil(t, user1.UserKeyVerify())

	M, err := getRandomG1Affine()
	if err != nil {
		panic(err)
	}
	r, err := rand.Int(rand.Reader, mod)
	if err != nil {
		panic(err)
	}
	gs, err := user0.GroupSign(M, r)
	if err != nil {
		panic(errors.New("failed to sign group signature: " + err.Error()))
	}
	assert.Nil(t, GroupVerify(gs, bbsSE.Params))

	rk := bbsSE.RevokeGen(user1.x)
	err = user0.RevokeExe(rk)
	if err != nil {
		panic(errors.New("failed to revoke group signature: " + err.Error()))
	}

	M1, _ := getRandomG1Affine()
	gs1, err := user1.GroupSign(M1, r)
	if err != nil {
		panic(errors.New("failed to sign group signature: " + err.Error()))
	}
	assert.Nil(t, GroupVerify(gs1, bbsSE.Params))
}
