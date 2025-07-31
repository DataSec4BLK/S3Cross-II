package s3cross

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"
	"github.com/stretchr/testify/assert"
	"log"
	"math/big"
	"os"
	"testing"
)

const numLeaves = 500

//const maxI = 16

// ==================== Benchmark ====================

func Benchmark_Setup(b *testing.B) {
	b.ReportAllocs()
	curve := twistededwards.GetEdwardsCurve()
	// circuit
	var circuit S3CrossCircuit
	circuit.ProofElements1 = make([]frontend.Variable, TreeDepth)

	for i := 0; i < b.N; i++ {
		// circuit
		ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
		if err != nil {
			b.Fatal(err)
		}
		_, _, err = groth16.Setup(ccs)
		if err != nil {
			b.Fatal(err)
		}
		// Issuer
		isk, err := rand.Int(rand.Reader, &curve.Order)
		if err != nil {
			panic(err)
		}
		ipk := new(twistededwards.PointAffine).ScalarMultiplication(&curve.Base, isk)
		_ = KeyPair{
			Sk: isk,
			Pk: ipk,
		}
		// Supervisor
		ssk, err := rand.Int(rand.Reader, &curve.Order)
		if err != nil {
			panic(err)
		}
		spk := new(twistededwards.PointAffine).ScalarMultiplication(&curve.Base, ssk)
		_ = KeyPair{
			Sk: ssk,
			Pk: spk,
		}
	}
}

func Benchmark_Issue(b *testing.B) {
	b.ReportAllocs()
	curve := twistededwards.GetEdwardsCurve()

	// Issuer
	isk, err := rand.Int(rand.Reader, &curve.Order)
	if err != nil {
		panic(err)
	}
	ipk := new(twistededwards.PointAffine).ScalarMultiplication(&curve.Base, isk)
	issuer := KeyPair{
		Sk: isk,
		Pk: ipk,
	}
	// User
	usk, err := rand.Int(rand.Reader, &curve.Order)
	if err != nil {
		panic(err)
	}
	upk := new(twistededwards.PointAffine).ScalarMultiplication(&curve.Base, usk)
	user := KeyPair{
		Sk: usk,
		Pk: upk,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err = issuer.Sign(user.Pk)
		if err != nil {
			panic(err)
		}
	}
}

func BenchmarkSnarkProve(b *testing.B) {
	b.ReportAllocs()
	curve := twistededwards.GetEdwardsCurve()

	// nonce
	nonce, err := getRandomPointAffine()
	if err != nil {
		b.Fatal(err)
	}

	// generate leaves (with a "0")
	leaves := make([]*big.Int, numLeaves+1)
	leaves[0] = big.NewInt(0)
	leaves[numLeaves] = new(big.Int).SetBytes(fr.Modulus().Bytes())
	for i := 1; i < numLeaves; i++ {
		var err error
		leaves[i], err = rand.Int(rand.Reader, fr.Modulus())
		assert.NoError(b, err)
	}

	// Issuer
	isk, err := rand.Int(rand.Reader, &curve.Order)
	if err != nil {
		panic(err)
	}
	ipk := new(twistededwards.PointAffine).ScalarMultiplication(&curve.Base, isk)
	issuer := KeyPair{
		Sk: isk,
		Pk: ipk,
	}
	// Supervisor
	ssk, err := rand.Int(rand.Reader, &curve.Order)
	if err != nil {
		panic(err)
	}
	spk := new(twistededwards.PointAffine).ScalarMultiplication(&curve.Base, ssk)
	supervisor := KeyPair{
		Sk: ssk,
		Pk: spk,
	}
	// User
	usk, err := rand.Int(rand.Reader, &curve.Order)
	if err != nil {
		panic(err)
	}
	upk := new(twistededwards.PointAffine).ScalarMultiplication(&curve.Base, usk)
	user := KeyPair{
		Sk: usk,
		Pk: upk,
	}
	sig, _, err := issuer.Sign(user.Pk)
	if err != nil {
		panic(err)
	}
	s3cross := S3Cross{
		&user,
		sig,
	}

	// non-member proof
	mp1, leafRight, err := s3cross.GenNonMemProof(leaves)
	if err != nil {
		panic(err)
	}
	// pseudonym
	num := big.NewInt(3)
	nc, psu, err := s3cross.NewPseudonym(num, nonce)
	if err != nil {
		panic(err)
	}
	// elgamal
	ct, r, err := EncryptElGamal(user.Pk, supervisor.Pk)
	if err != nil {
		panic(err)
	}

	circuit := S3CrossCircuit{}
	circuit.ProofElements1 = make([]frontend.Variable, TreeDepth)
	circuitWit := S3CrossCircuit{
		Root:        mp1.Root,
		ProofIndex1: mp1.Index,
		Leaf1:       mp1.Leaf,
		Leaf2:       leafRight,

		IPkX:     sig.SPk.X,
		IPkY:     sig.SPk.Y,
		Sig:      s3cross.Sig,
		RX:       s3cross.R.X,
		RY:       s3cross.R.Y,
		MessageX: user.Pk.X,
		MessageY: user.Pk.Y,

		PPkX:  psu.Pk.X,
		PPkY:  psu.Pk.Y,
		Nonce: nc,
		//MaxI:  maxI,
		USk: s3cross.Sk,
		I:   num,

		SPkX: supervisor.Pk.X,
		SPkY: supervisor.Pk.Y,
		C1X:  ct.C1.X,
		C1Y:  ct.C1.Y,
		C2X:  ct.C2.X,
		C2Y:  ct.C2.Y,
		R:    r,
	}
	circuitWit.ProofElements1 = make([]frontend.Variable, TreeDepth)
	for i := 0; i < TreeDepth; i++ {
		circuitWit.ProofElements1[i] = mp1.Proof[i]
	}

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		b.Fatal(err)
	}

	pk, _, err := groth16.Setup(ccs)
	if err != nil {
		b.Fatal(err)
	}

	secretWitness, err := frontend.NewWitness(&circuitWit, ecc.BN254.ScalarField())

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err = groth16.Prove(ccs, pk, secretWitness)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSnarkVerify(b *testing.B) {
	b.ReportAllocs()
	curve := twistededwards.GetEdwardsCurve()

	// nonce
	nonce, err := getRandomPointAffine()
	if err != nil {
		b.Fatal(err)
	}

	// generate leaves (with a "0")
	leaves := make([]*big.Int, numLeaves+1)
	leaves[0] = big.NewInt(0)
	leaves[numLeaves] = new(big.Int).SetBytes(fr.Modulus().Bytes())
	for i := 1; i < numLeaves; i++ {
		var err error
		leaves[i], err = rand.Int(rand.Reader, fr.Modulus())
		assert.NoError(b, err)
	}

	// Issuer
	isk, err := rand.Int(rand.Reader, &curve.Order)
	if err != nil {
		panic(err)
	}
	ipk := new(twistededwards.PointAffine).ScalarMultiplication(&curve.Base, isk)
	issuer := KeyPair{
		Sk: isk,
		Pk: ipk,
	}
	// Supervisor
	ssk, err := rand.Int(rand.Reader, &curve.Order)
	if err != nil {
		panic(err)
	}
	spk := new(twistededwards.PointAffine).ScalarMultiplication(&curve.Base, ssk)
	supervisor := KeyPair{
		Sk: ssk,
		Pk: spk,
	}
	// User
	usk, err := rand.Int(rand.Reader, &curve.Order)
	if err != nil {
		panic(err)
	}
	upk := new(twistededwards.PointAffine).ScalarMultiplication(&curve.Base, usk)
	user := KeyPair{
		Sk: usk,
		Pk: upk,
	}
	sig, _, err := issuer.Sign(user.Pk)
	if err != nil {
		panic(err)
	}
	s3cross := S3Cross{
		&user,
		sig,
	}

	// non-member proof
	mp1, leafRight, err := s3cross.GenNonMemProof(leaves)
	if err != nil {
		panic(err)
	}
	// pseudonym
	num := big.NewInt(3)
	nc, psu, err := s3cross.NewPseudonym(num, nonce)
	if err != nil {
		panic(err)
	}
	// elgamal
	ct, r, err := EncryptElGamal(user.Pk, supervisor.Pk)
	if err != nil {
		panic(err)
	}

	circuit := S3CrossCircuit{}
	circuit.ProofElements1 = make([]frontend.Variable, TreeDepth)
	circuitWit := S3CrossCircuit{
		Root:        mp1.Root,
		ProofIndex1: mp1.Index,
		Leaf1:       mp1.Leaf,
		Leaf2:       leafRight,

		IPkX:     sig.SPk.X,
		IPkY:     sig.SPk.Y,
		Sig:      s3cross.Sig,
		RX:       s3cross.R.X,
		RY:       s3cross.R.Y,
		MessageX: user.Pk.X,
		MessageY: user.Pk.Y,

		PPkX:  psu.Pk.X,
		PPkY:  psu.Pk.Y,
		Nonce: nc,
		//MaxI:  maxI,
		USk: s3cross.Sk,
		I:   num,

		SPkX: supervisor.Pk.X,
		SPkY: supervisor.Pk.Y,
		C1X:  ct.C1.X,
		C1Y:  ct.C1.Y,
		C2X:  ct.C2.X,
		C2Y:  ct.C2.Y,
		R:    r,
	}
	circuitWit.ProofElements1 = make([]frontend.Variable, TreeDepth)
	for i := 0; i < TreeDepth; i++ {
		circuitWit.ProofElements1[i] = mp1.Proof[i]
	}

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		b.Fatal(err)
	}

	gpk, gvk, err := groth16.Setup(ccs)
	if err != nil {
		b.Fatal(err)
	}

	secretWitness, err := frontend.NewWitness(&circuitWit, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}
	publicWitness, err := secretWitness.Public()
	if err != nil {
		panic(err)
	}
	proof, err := groth16.Prove(ccs, gpk, secretWitness)
	if err != nil {
		panic(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err = groth16.Verify(proof, gvk, publicWitness)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func Benchmark_Revoke(b *testing.B) {
	b.ReportAllocs()
	curve := twistededwards.GetEdwardsCurve()

	// generate leaves (with a "0")
	leaves := make([]*big.Int, numLeaves+1)
	leaves[numLeaves] = new(big.Int).SetBytes(fr.Modulus().Bytes())
	leaves[0] = big.NewInt(0)
	for i := 1; i < numLeaves; i++ {
		var err error
		leaves[i], err = rand.Int(rand.Reader, fr.Modulus())
		assert.NoError(b, err)
	}

	// User
	usk, err := rand.Int(rand.Reader, &curve.Order)
	if err != nil {
		panic(err)
	}
	upk := new(twistededwards.PointAffine).ScalarMultiplication(&curve.Base, usk)
	user := KeyPair{
		Sk: usk,
		Pk: upk,
	}
	s3cross := S3Cross{
		&user,
		&Signature{},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err = s3cross.GenNonMemProof(leaves)
		if err != nil {
			panic(err)
		}
	}
}

//func BenchmarkNonMemProof(b *testing.B) {
//	curve := twistededwards.GetEdwardsCurve()
//
//	// generate leaves (with a "0")
//	leaves := make([]*big.Int, numLeaves+1)
//	leaves[numLeaves] = new(big.Int).SetBytes(fr.Modulus().Bytes())
//	leaves[0] = big.NewInt(0)
//	for i := 1; i < numLeaves; i++ {
//		var err error
//		leaves[i], err = rand.Int(rand.Reader, fr.Modulus())
//		assert.NoError(b, err)
//	}
//
//	// User
//	usk, err := rand.Int(rand.Reader, &curve.Order)
//	if err != nil {
//		panic(err)
//	}
//	upk := new(twistededwards.PointAffine).ScalarMultiplication(&curve.Base, usk)
//	user := KeyPair{
//		Sk: usk,
//		Pk: upk,
//	}
//	s3cross := S3Cross{
//		&user,
//		&Signature{},
//	}
//
//	b.ResetTimer()
//	for i := 0; i < b.N; i++ {
//		_, _, err = s3cross.GenNonMemProof(leaves)
//		if err != nil {
//			panic(err)
//		}
//	}
//}
//
//func BenchmarkSchnorrVerify(b *testing.B) {
//	curve := twistededwards.GetEdwardsCurve()
//
//	// Issuer
//	isk, err := rand.Int(rand.Reader, &curve.Order)
//	if err != nil {
//		panic(err)
//	}
//	ipk := new(twistededwards.PointAffine).ScalarMultiplication(&curve.Base, isk)
//	issuer := KeyPair{
//		Sk: isk,
//		Pk: ipk,
//	}
//	// User
//	usk, err := rand.Int(rand.Reader, &curve.Order)
//	if err != nil {
//		panic(err)
//	}
//	upk := new(twistededwards.PointAffine).ScalarMultiplication(&curve.Base, usk)
//	user := KeyPair{
//		Sk: usk,
//		Pk: upk,
//	}
//	sig, _, err := issuer.Sign(user.Pk)
//	if err != nil {
//		panic(err)
//	}
//
//	b.ResetTimer()
//	for i := 0; i < b.N; i++ {
//		err = sig.Verify()
//		if err != nil {
//			panic(err)
//		}
//	}
//}
//
//func BenchmarkElGamalEncrypt(b *testing.B) {
//	curve := twistededwards.GetEdwardsCurve()
//
//	// Supervisor
//	ssk, err := rand.Int(rand.Reader, &curve.Order)
//	if err != nil {
//		panic(err)
//	}
//	spk := new(twistededwards.PointAffine).ScalarMultiplication(&curve.Base, ssk)
//	supervisor := KeyPair{
//		Sk: ssk,
//		Pk: spk,
//	}
//	// User
//	usk, err := rand.Int(rand.Reader, &curve.Order)
//	if err != nil {
//		panic(err)
//	}
//	upk := new(twistededwards.PointAffine).ScalarMultiplication(&curve.Base, usk)
//	user := KeyPair{
//		Sk: usk,
//		Pk: upk,
//	}
//
//	b.ResetTimer()
//	for i := 0; i < b.N; i++ {
//		_, _, _ = EncryptElGamal(user.Pk, supervisor.Pk)
//	}
//}
//
//func BenchmarkElGamalDecrypt(b *testing.B) {
//	curve := twistededwards.GetEdwardsCurve()
//
//	// Supervisor
//	ssk, err := rand.Int(rand.Reader, &curve.Order)
//	if err != nil {
//		panic(err)
//	}
//	spk := new(twistededwards.PointAffine).ScalarMultiplication(&curve.Base, ssk)
//	supervisor := KeyPair{
//		Sk: ssk,
//		Pk: spk,
//	}
//	// User
//	usk, err := rand.Int(rand.Reader, &curve.Order)
//	if err != nil {
//		panic(err)
//	}
//	upk := new(twistededwards.PointAffine).ScalarMultiplication(&curve.Base, usk)
//	user := KeyPair{
//		Sk: usk,
//		Pk: upk,
//	}
//	ct, _, err := EncryptElGamal(user.Pk, supervisor.Pk)
//	if err != nil {
//		panic(err)
//	}
//
//	b.ResetTimer()
//	for i := 0; i < b.N; i++ {
//		_, _ = supervisor.Decrypt(ct)
//	}
//}

// ==================== Test ====================

type TestParams struct {
	Leaves       [][]byte `json:"leaves"`    // Merkle树的叶节点：[]byte 数组
	IssuerSK     []byte   `json:"issuer_sk"` // Issuer私钥（16进制字符串）
	SupervisorSK []byte   `json:"supervisor_sk"`
}

func TestS3CrossS3CrossCircuit(t *testing.T) {
	curve := twistededwards.GetEdwardsCurve()

	// nonce
	nonce, err := getRandomPointAffine()
	if err != nil {
		t.Fatal(err)
	}

	// generate leaves (with a "0" and )
	leaves := make([]*big.Int, numLeaves+1)
	leaves[0] = big.NewInt(0)
	leaves[numLeaves] = new(big.Int).SetBytes(fr.Modulus().Bytes())
	for i := 1; i < numLeaves; i++ {
		var err error
		leaves[i], err = rand.Int(rand.Reader, fr.Modulus())
		assert.NoError(t, err)
	}

	// Issuer
	isk, err := rand.Int(rand.Reader, &curve.Order)
	if err != nil {
		panic(err)
	}
	ipk := new(twistededwards.PointAffine).ScalarMultiplication(&curve.Base, isk)
	issuer := KeyPair{
		Sk: isk,
		Pk: ipk,
	}
	// Supervisor
	ssk, err := rand.Int(rand.Reader, &curve.Order)
	if err != nil {
		panic(err)
	}
	spk := new(twistededwards.PointAffine).ScalarMultiplication(&curve.Base, ssk)
	supervisor := KeyPair{
		Sk: ssk,
		Pk: spk,
	}
	// User
	usk, err := rand.Int(rand.Reader, &curve.Order)
	if err != nil {
		panic(err)
	}
	upk := new(twistededwards.PointAffine).ScalarMultiplication(&curve.Base, usk)
	user := KeyPair{
		Sk: usk,
		Pk: upk,
	}
	sig, _, err := issuer.Sign(user.Pk)
	if err != nil {
		panic(err)
	}
	s3cross := S3Cross{
		&user,
		sig,
	}

	// non-member proof
	mp1, leafRight, err := s3cross.GenNonMemProof(leaves)
	if err != nil {
		panic(err)
	}
	//assert.Equal(t, mp1.Root, mp2.Root)
	// pseudonym
	i := big.NewInt(3)
	nc, psu, err := s3cross.NewPseudonym(i, nonce)
	if err != nil {
		panic(err)
	}
	// elgamal
	ct, r, err := EncryptElGamal(user.Pk, supervisor.Pk)
	if err != nil {
		panic(err)
	}

	circuit := S3CrossCircuit{}
	circuit.ProofElements1 = make([]frontend.Variable, TreeDepth)

	// constraints number
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		panic(err)
	}
	fmt.Println("Number of constraints:", cs.GetNbConstraints())

	circuitWit := S3CrossCircuit{
		Root:        mp1.Root,
		ProofIndex1: mp1.Index,
		Leaf1:       mp1.Leaf,
		Leaf2:       leafRight,

		IPkX:     sig.SPk.X,
		IPkY:     sig.SPk.Y,
		Sig:      s3cross.Sig,
		RX:       s3cross.R.X,
		RY:       s3cross.R.Y,
		MessageX: user.Pk.X,
		MessageY: user.Pk.Y,

		PPkX:  psu.Pk.X,
		PPkY:  psu.Pk.Y,
		Nonce: nc,
		//MaxI:  maxI,
		USk: s3cross.Sk,
		I:   i,

		SPkX: supervisor.Pk.X,
		SPkY: supervisor.Pk.Y,
		C1X:  ct.C1.X,
		C1Y:  ct.C1.Y,
		C2X:  ct.C2.X,
		C2Y:  ct.C2.Y,
		R:    r,
	}
	circuitWit.ProofElements1 = make([]frontend.Variable, TreeDepth)
	for i := 0; i < TreeDepth; i++ {
		circuitWit.ProofElements1[i] = mp1.Proof[i]
	}

	// Verify
	// // zkSNARKs
	ast := test.NewAssert(t)
	ast.ProverSucceeded(&circuit, &circuitWit, test.WithCurves(ecc.BN254))
}

func TestS3CrossS3CrossKeySize(t *testing.T) {
	curve := twistededwards.GetEdwardsCurve()

	// nonce
	nonce, err := getRandomPointAffine()
	if err != nil {
		t.Fatal(err)
	}

	// generate leaves (with a "0" and )
	leaves := make([]*big.Int, numLeaves+1)
	leaves[0] = big.NewInt(0)
	leaves[numLeaves] = new(big.Int).SetBytes(fr.Modulus().Bytes())
	for i := 1; i < numLeaves; i++ {
		var err error
		leaves[i], err = rand.Int(rand.Reader, fr.Modulus())
		assert.NoError(t, err)
	}

	// Issuer
	isk, err := rand.Int(rand.Reader, &curve.Order)
	if err != nil {
		panic(err)
	}
	ipk := new(twistededwards.PointAffine).ScalarMultiplication(&curve.Base, isk)
	issuer := KeyPair{
		Sk: isk,
		Pk: ipk,
	}
	// Supervisor
	ssk, err := rand.Int(rand.Reader, &curve.Order)
	if err != nil {
		panic(err)
	}
	spk := new(twistededwards.PointAffine).ScalarMultiplication(&curve.Base, ssk)
	supervisor := KeyPair{
		Sk: ssk,
		Pk: spk,
	}
	// User
	usk, err := rand.Int(rand.Reader, &curve.Order)
	if err != nil {
		panic(err)
	}
	upk := new(twistededwards.PointAffine).ScalarMultiplication(&curve.Base, usk)
	user := KeyPair{
		Sk: usk,
		Pk: upk,
	}
	sig, _, err := issuer.Sign(user.Pk)
	if err != nil {
		panic(err)
	}
	s3cross := S3Cross{
		&user,
		sig,
	}

	// non-member proof
	mp1, leafRight, err := s3cross.GenNonMemProof(leaves)
	if err != nil {
		panic(err)
	}
	//assert.Equal(t, mp1.Root, mp2.Root)
	// pseudonym
	i := big.NewInt(3)
	nc, psu, err := s3cross.NewPseudonym(i, nonce)
	if err != nil {
		panic(err)
	}
	// elgamal
	ct, r, err := EncryptElGamal(user.Pk, supervisor.Pk)
	if err != nil {
		panic(err)
	}

	circuit := S3CrossCircuit{}
	circuit.ProofElements1 = make([]frontend.Variable, TreeDepth)

	// constraints number
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		panic(err)
	}
	fmt.Println("Number of constraints:", cs.GetNbConstraints())

	circuitWit := S3CrossCircuit{
		Root:        mp1.Root,
		ProofIndex1: mp1.Index,
		Leaf1:       mp1.Leaf,
		Leaf2:       leafRight,

		IPkX:     sig.SPk.X,
		IPkY:     sig.SPk.Y,
		Sig:      s3cross.Sig,
		RX:       s3cross.R.X,
		RY:       s3cross.R.Y,
		MessageX: user.Pk.X,
		MessageY: user.Pk.Y,

		PPkX:  psu.Pk.X,
		PPkY:  psu.Pk.Y,
		Nonce: nc,
		//MaxI:  maxI,
		USk: s3cross.Sk,
		I:   i,

		SPkX: supervisor.Pk.X,
		SPkY: supervisor.Pk.Y,
		C1X:  ct.C1.X,
		C1Y:  ct.C1.Y,
		C2X:  ct.C2.X,
		C2Y:  ct.C2.Y,
		R:    r,
	}
	circuitWit.ProofElements1 = make([]frontend.Variable, TreeDepth)
	for i := 0; i < TreeDepth; i++ {
		circuitWit.ProofElements1[i] = mp1.Proof[i]
	}

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		t.Fatal(err)
	}
	gpk, gvk, err := groth16.Setup(ccs)
	if err != nil {
		t.Fatal(err)
	}
	secretWitness, err := frontend.NewWitness(&circuitWit, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}
	publicWitness, err := secretWitness.Public()

	var buf bytes.Buffer
	_, err = gvk.WriteTo(&buf)
	fmt.Println("gvk write to", len(buf.Bytes()))
	var buf2 bytes.Buffer
	_, err = gpk.WriteTo(&buf2)
	fmt.Println("gpk write to", len(buf2.Bytes()))

	var buf3 bytes.Buffer
	_, err = publicWitness.WriteTo(&buf3)
	fmt.Println("publicWitness.WriteTo", len(buf3.Bytes()))
}

func TestCSAndPVKey(t *testing.T) {
	curve := twistededwards.GetEdwardsCurve()

	// nonce
	nonce, err := getRandomPointAffine()
	if err != nil {
		t.Fatal(err)
	}

	// generate leaves (with a "0")
	leaves := make([]*big.Int, numLeaves+1)
	leaves[0] = big.NewInt(0)
	leaves[numLeaves] = new(big.Int).SetBytes(fr.Modulus().Bytes())
	for i := 1; i < numLeaves; i++ {
		var err error
		leaves[i], err = rand.Int(rand.Reader, fr.Modulus())
		assert.NoError(t, err)
	}

	// Issuer
	isk, err := rand.Int(rand.Reader, &curve.Order)
	if err != nil {
		panic(err)
	}
	ipk := new(twistededwards.PointAffine).ScalarMultiplication(&curve.Base, isk)
	issuer := KeyPair{
		Sk: isk,
		Pk: ipk,
	}
	// Supervisor
	ssk, err := rand.Int(rand.Reader, &curve.Order)
	if err != nil {
		panic(err)
	}
	spk := new(twistededwards.PointAffine).ScalarMultiplication(&curve.Base, ssk)
	supervisor := KeyPair{
		Sk: ssk,
		Pk: spk,
	}
	// User
	usk, err := rand.Int(rand.Reader, &curve.Order)
	if err != nil {
		panic(err)
	}
	upk := new(twistededwards.PointAffine).ScalarMultiplication(&curve.Base, usk)
	user := KeyPair{
		Sk: usk,
		Pk: upk,
	}
	sig, _, err := issuer.Sign(user.Pk)
	if err != nil {
		panic(err)
	}
	s3cross := S3Cross{
		&user,
		sig,
	}

	// non-member proof
	mp1, leafRight, err := s3cross.GenNonMemProof(leaves)
	if err != nil {
		panic(err)
	}
	// pseudonym
	num := big.NewInt(3)
	nc, psu, err := s3cross.NewPseudonym(num, nonce)
	if err != nil {
		panic(err)
	}
	// elgamal
	ct, r, err := EncryptElGamal(user.Pk, supervisor.Pk)
	if err != nil {
		panic(err)
	}

	circuit := S3CrossCircuit{}
	circuit.ProofElements1 = make([]frontend.Variable, TreeDepth)
	secWit := S3CrossCircuit{
		Root:        mp1.Root,
		ProofIndex1: mp1.Index,
		Leaf1:       mp1.Leaf,
		Leaf2:       leafRight,

		IPkX:     sig.SPk.X,
		IPkY:     sig.SPk.Y,
		Sig:      s3cross.Sig,
		RX:       s3cross.R.X,
		RY:       s3cross.R.Y,
		MessageX: user.Pk.X,
		MessageY: user.Pk.Y,

		PPkX:  psu.Pk.X,
		PPkY:  psu.Pk.Y,
		Nonce: nc,
		//MaxI:  maxI,
		USk: s3cross.Sk,
		I:   num,

		SPkX: supervisor.Pk.X,
		SPkY: supervisor.Pk.Y,
		C1X:  ct.C1.X,
		C1Y:  ct.C1.Y,
		C2X:  ct.C2.X,
		C2Y:  ct.C2.Y,
		R:    r,
	}
	secWit.ProofElements1 = make([]frontend.Variable, TreeDepth)
	for i := 0; i < TreeDepth; i++ {
		secWit.ProofElements1[i] = mp1.Proof[i]
	}

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		t.Fatal(err)
	}

	pkPath := "PGK.text"
	vkPath := "PVK.text"

	// ---------- 存储 Key ----------

	//gpk, gvk, err := groth16.Setup(ccs)
	//if err != nil {
	//	t.Fatal(err)
	//}
	//
	//err = SaveGroth16PKVK(gpk, gvk, pkPath, vkPath)
	//if err != nil {
	//	t.Fatal(errors.New("failed to save groth16 pk: " + err.Error()))
	//}

	// ---------- 读取 Key ----------

	rGpk, rGvk, err := LoadGroth16PKVK(pkPath, vkPath)

	vkStr := VerifyingKeyToBase64String(rGvk)
	sTest := vkStr
	rGvk2, err := base64StringToVerifyingKey(sTest)
	if err != nil {
		t.Fatal(fmt.Errorf("failed to verify groth16 pk: %s", err.Error()))
	}

	// ---------- 读取 Key ----------

	secretWitness, err := frontend.NewWitness(&secWit, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}
	publicWitness, err := secretWitness.Public()
	if err != nil {
		panic(err)
	}
	proof, err := groth16.Prove(ccs, rGpk, secretWitness)
	if err != nil {
		panic(err)
	}

	err = groth16.Verify(proof, *rGvk2, publicWitness)

	values := publicWitness.Vector().(fr.Vector)
	var elem = values[0]
	bs := elem.Bytes() // bs 是 [32]byte

	assert.Equal(t, bs[:], mp1.Root)
}

func TestStaticParams(t *testing.T) {
	curve := twistededwards.GetEdwardsCurve()
	leaves, issuerSK, supervisorSK, err := LoadTestParams("params")
	if err != nil {
		t.Fatal(err)
	}
	// nonce
	nonce, err := getRandomPointAffine()
	if err != nil {
		t.Fatal(err)
	}

	// issuer
	issuer := KeyPair{
		Sk: issuerSK,
		Pk: new(twistededwards.PointAffine).ScalarMultiplication(&curve.Base, issuerSK),
	}
	indIpk := issuer.Pk.Bytes()
	fmt.Println("ipkString: ", base64.StdEncoding.EncodeToString(indIpk[:]))
	// supervisor
	supervisor := KeyPair{
		Sk: supervisorSK,
		Pk: new(twistededwards.PointAffine).ScalarMultiplication(&curve.Base, supervisorSK),
	}
	indSpk := supervisor.Pk.Bytes()
	fmt.Println("spkString: ", base64.StdEncoding.EncodeToString(indSpk[:]))
	// User
	usk, err := rand.Int(rand.Reader, &curve.Order)
	if err != nil {
		panic(err)
	}
	upk := new(twistededwards.PointAffine).ScalarMultiplication(&curve.Base, usk)
	user := KeyPair{
		Sk: usk,
		Pk: upk,
	}
	sig, _, err := issuer.Sign(user.Pk)
	if err != nil {
		panic(err)
	}
	s3cross := S3Cross{
		&user,
		sig,
	}

	// non-member proof
	mp1, leafRight, err := s3cross.GenNonMemProof(leaves)
	if err != nil {
		panic(err)
	}
	fmt.Println("root: ", base64.StdEncoding.EncodeToString(mp1.Root))
	// pseudonym
	num := big.NewInt(3)
	nc, psu, err := s3cross.NewPseudonym(num, nonce)
	if err != nil {
		panic(err)
	}
	// elgamal
	ct, r, err := EncryptElGamal(user.Pk, supervisor.Pk)
	if err != nil {
		panic(err)
	}

	circuit := S3CrossCircuit{}
	circuit.ProofElements1 = make([]frontend.Variable, TreeDepth)
	secWit := S3CrossCircuit{
		Root:        mp1.Root,
		ProofIndex1: mp1.Index,
		Leaf1:       mp1.Leaf,
		Leaf2:       leafRight,

		IPkX:     sig.SPk.X,
		IPkY:     sig.SPk.Y,
		Sig:      s3cross.Sig,
		RX:       s3cross.R.X,
		RY:       s3cross.R.Y,
		MessageX: user.Pk.X,
		MessageY: user.Pk.Y,

		PPkX:  psu.Pk.X,
		PPkY:  psu.Pk.Y,
		Nonce: nc,
		//MaxI:  maxI,
		USk: s3cross.Sk,
		I:   num,

		SPkX: supervisor.Pk.X,
		SPkY: supervisor.Pk.Y,
		C1X:  ct.C1.X,
		C1Y:  ct.C1.Y,
		C2X:  ct.C2.X,
		C2Y:  ct.C2.Y,
		R:    r,
	}
	secWit.ProofElements1 = make([]frontend.Variable, TreeDepth)
	for i := 0; i < TreeDepth; i++ {
		secWit.ProofElements1[i] = mp1.Proof[i]
	}

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		t.Fatal(err)
	}

	// ---------- 存储 Key ----------

	pkPath := "PGK.text"
	vkPath := "PVK.text"

	rGpk, rGvk, err := LoadGroth16PKVK(pkPath, vkPath)

	vkStr := VerifyingKeyToBase64String(rGvk)
	fmt.Println("VerifyingKeyToHexString:", *vkStr)
	sTest := vkStr
	rGvk2, err := base64StringToVerifyingKey(sTest)
	if err != nil {
		t.Fatal(fmt.Errorf("failed to verify groth16 pk: %s", err.Error()))
	}

	// ---------- 读取 Key ----------

	secretWitness, err := frontend.NewWitness(&secWit, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}
	publicWitness, err := secretWitness.Public()
	if err != nil {
		panic(err)
	}
	proof, err := groth16.Prove(ccs, rGpk, secretWitness)
	if err != nil {
		panic(err)
	}
	err = groth16.Verify(proof, *rGvk2, publicWitness)
	assert.Nil(t, err)

	proofStr := ProofToBase64String(proof)
	fmt.Println("ProofToBase64String:", *proofStr)
	fmt.Println("ProofToBase64String-len:", len(*proofStr))

	witnessStr, err := WitnessToBase64String(publicWitness)
	if err != nil {
		panic(err)
	}
	fmt.Println("WitnessToBase64String:", *witnessStr)
	fmt.Println("WitnessToBase64String-len:", len(*witnessStr))

	indPPK := psu.Pk.Bytes()
	fmt.Println("psuStr: ", base64.StdEncoding.EncodeToString(indPPK[:]))

	//values := publicWitness.Vector().(fr.Vector)
	//var elem = values[0]
	//bs := elem.Bytes() // bs 是 [32]byte
	//
	//assert.Equal(t, bs[:], mp1.Root)
}

func SaveTestParams(filename string, leaves []*big.Int, issuerSK, supervisorSK *big.Int) error {
	leavesHex := make([][]byte, len(leaves))
	for i, l := range leaves {
		leavesHex[i] = l.Bytes()
	}
	params := &TestParams{
		Leaves:       leavesHex,
		IssuerSK:     issuerSK.Bytes(),
		SupervisorSK: supervisorSK.Bytes(),
	}
	data, err := json.MarshalIndent(params, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filename, data, 0644)
}

func LoadTestParams(filename string) ([]*big.Int, *big.Int, *big.Int, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, nil, nil, err
	}
	var params TestParams
	if err := json.Unmarshal(data, &params); err != nil {
		return nil, nil, nil, err
	}
	leaves := make([]*big.Int, len(params.Leaves))
	for i, b := range params.Leaves {
		leaves[i] = new(big.Int).SetBytes(b)
	}
	issuerSK := new(big.Int).SetBytes(params.IssuerSK)
	supervisorSK := new(big.Int).SetBytes(params.SupervisorSK)
	return leaves, issuerSK, supervisorSK, nil
}

func SaveGroth16PKVK(pk groth16.ProvingKey, vk groth16.VerifyingKey, pkFile, vkFile string) error {
	pkf, err := os.Create(pkFile)
	if err != nil {
		return err
	}
	defer func(pkf *os.File) {
		err = pkf.Close()
		if err != nil {
			panic(err)
		}
	}(pkf)
	if _, err := pk.WriteTo(pkf); err != nil {
		return err
	}

	vkf, err := os.Create(vkFile)
	if err != nil {
		return err
	}
	defer func(vkf *os.File) {
		err = vkf.Close()
		if err != nil {
			panic(err)
		}
	}(vkf)
	_, err = vk.WriteTo(vkf)
	return err
}

func LoadGroth16PKVK(pkFile, vkFile string) (groth16.ProvingKey, groth16.VerifyingKey, error) {
	pkf, err := os.Open(pkFile)
	if err != nil {
		return nil, nil, err
	}
	defer func(pkf *os.File) {
		err = pkf.Close()
		if err != nil {
			panic(err)
		}
	}(pkf)
	pk := groth16.NewProvingKey(ecc.BN254) // curve: 你使用的曲线类型，如 ecc.BN254
	if _, err := pk.ReadFrom(pkf); err != nil {
		return nil, nil, err
	}

	vkf, err := os.Open(vkFile)
	if err != nil {
		return nil, nil, err
	}
	defer func(vkf *os.File) {
		err = vkf.Close()
		if err != nil {
			panic(err)
		}
	}(vkf)
	vk := groth16.NewVerifyingKey(ecc.BN254)
	if _, err := vk.ReadFrom(vkf); err != nil {
		return nil, nil, err
	}
	return pk, vk, nil
}

func VerifyingKeyToBase64String(vk groth16.VerifyingKey) *string {
	var buf bytes.Buffer
	_, err := vk.WriteTo(&buf)
	if err != nil {
		log.Fatalf("failed to serialize verifying key: %v", err)
	}
	vkStr := base64.StdEncoding.EncodeToString(buf.Bytes())
	return &vkStr
}

func base64StringToVerifyingKey(encoded *string) (*groth16.VerifyingKey, error) {
	data, err := base64.StdEncoding.DecodeString(*encoded)
	if err != nil {
		return nil, err
	}
	buf := bytes.NewBuffer(data)
	vk := groth16.NewVerifyingKey(ecc.BN254)
	_, err = vk.ReadFrom(buf)
	return &vk, err
}

func getRandomPointAffine() (*twistededwards.PointAffine, error) {
	curve := twistededwards.GetEdwardsCurve()
	r, err := rand.Int(rand.Reader, &curve.Order)
	if err != nil {
		return &twistededwards.PointAffine{}, err
	}
	R := new(twistededwards.PointAffine).ScalarMultiplication(&curve.Base, r)
	return R, nil
}

// Proof 序列化为 hex 字符串
func ProofToBase64String(proof groth16.Proof) *string {
	var buf bytes.Buffer
	_, err := proof.WriteTo(&buf)
	fmt.Println("proofBufSize: ", buf.Len())
	if err != nil {
		log.Fatalf("failed to serialize proof: %v", err)
	}
	proofStr := base64.StdEncoding.EncodeToString(buf.Bytes())
	fmt.Println("proofB64Size: ", len(proofStr))
	return &proofStr
}

// base64 字符串反序列化为 Proof
func base64StringToProof(encoded *string) (groth16.Proof, error) {
	data, err := base64.StdEncoding.DecodeString(*encoded)
	if err != nil {
		return nil, err
	}
	buf := bytes.NewBuffer(data)
	proof := groth16.NewProof(ecc.BN254)
	_, err = proof.ReadFrom(buf)
	if err != nil {
		return nil, err
	}
	return proof, nil
}

// witness 序列化为 hex 字符串
func WitnessToBase64String(wit witness.Witness) (*string, error) {
	var buf bytes.Buffer
	_, err := wit.WriteTo(&buf)
	if err != nil {
		return nil, err
	}
	witStr := base64.StdEncoding.EncodeToString(buf.Bytes())
	return &witStr, nil
}

// base64 字符串反序列化为 witness
func base64StringToWitness(str *string) (witness.Witness, error) {
	data, err := base64.StdEncoding.DecodeString(*str)
	if err != nil {
		return nil, err
	}
	buf := bytes.NewBuffer(data)
	wit, err := frontend.NewWitness(nil, ecc.BN254.ScalarField())
	if err != nil {
		return nil, err
	}
	_, err = wit.ReadFrom(buf)
	return wit, err
}
