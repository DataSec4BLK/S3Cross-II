package S3Cross

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"math/big"
	"os"
	"testing"
)

func BenchmarkS3Cross_Setup(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		// setup borromean
		_ = GenPedersenParams()

		// setup group signature
		mod := bn254.ID.ScalarField()
		sk, err := rand.Int(rand.Reader, mod)
		if err != nil {
			panic(err)
		}
		gamma, _ := rand.Int(rand.Reader, mod)

		_, err = InitBbsSE(gamma, sk)
		if err != nil {
			panic(err)
		}
	}
}

func BenchmarkS3Cross_Issue(b *testing.B) {
	b.ReportAllocs()
	// setup borromean
	pp := GenPedersenParams()

	// setup group signature
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

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// user key y
		y, _ := rand.Int(rand.Reader, mod)
		Y0 := new(bn254.G1Affine).ScalarMultiplication(bbsSE.h0, new(big.Int).Neg(y))
		Y := new(bn254.G1Affine).ScalarMultiplication(bbsSE.h, new(big.Int).Neg(y))
		user, err := bbsSE.UserKeyGen(Y0, Y)
		if err != nil {
			panic(err)
		}
		user.y = y

		// setup s3cross
		_ = &S3Cross{
			UserKey:        user,
			PedersenParams: pp,
		}
	}
}

func BenchmarkS3Cross_GenPseudonym(b *testing.B) {
	b.ReportAllocs()
	// setup borromean
	bits := 4
	v := big.NewInt(7)
	pp := GenPedersenParams()

	// setup group signature
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

	nonce, _ := rand.Int(rand.Reader, mod)
	M, err := getRandomG1Affine()
	if err != nil {
		panic(err)
	}

	// setup s3cross
	s3c := &S3Cross{
		UserKey:        user,
		PedersenParams: pp,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err = s3c.GenPseudonym(M, nonce, v, bits)
		if err != nil {
			panic(err)
		}
	}
}

func BenchmarkS3Cross_VerifyPseudonym(b *testing.B) {
	b.ReportAllocs()
	// setup borromean
	bits := 4
	v := big.NewInt(7)
	pp := GenPedersenParams()

	// setup group signature
	mod := bn254.ID.ScalarField()
	sk, err := rand.Int(rand.Reader, mod)
	if err != nil {
		panic(err)
	}
	gamma, _ := rand.Int(rand.Reader, mod)

	// group manager
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

	nonce, _ := rand.Int(rand.Reader, mod)

	M, err := getRandomG1Affine()
	if err != nil {
		panic(err)
	}

	// setup s3cross
	s3c := &S3Cross{
		UserKey:        user,
		PedersenParams: pp,
	}
	_, s3cP, err := s3c.GenPseudonym(M, nonce, v, bits)
	if err != nil {
		panic(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err = VerifyPseudonym(s3cP, pp, bbsSE.Params, nonce, bits)
		if err != nil {
			panic(err)
		}
	}
}

func TestS3Cross(t *testing.T) {
	// setup borromean
	bits := 4
	v := big.NewInt(7)
	pp := GenPedersenParams()

	// setup group signature
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

	//nonce, _ := rand.Int(rand.Reader, mod)
	//fmt.Println("nonce: ", nonce)

	// use static nonce
	nStr := "17077557196202813204801775360160812872901728681867794927808072673056060376603"
	nonce, _ := new(big.Int).SetString(nStr, 10)

	M, err := getRandomG1Affine()
	if err != nil {
		panic(err)
	}

	// setup s3cross
	s3c := &S3Cross{
		UserKey:        user,
		PedersenParams: pp,
	}
	_, s3cP, err := s3c.GenPseudonym(M, nonce, v, bits)
	if err != nil {
		panic(err)
	}

	err = VerifyPseudonym(s3cP, pp, bbsSE.Params, nonce, bits)
	if err != nil {
		panic(err)
	}
}

func TestS3CrossStaticParam(t *testing.T) {
	// setup borromean
	bits := 4
	v := big.NewInt(7)
	mod := bn254.ID.ScalarField()

	// ===== write the parameters =====
	//pp := GenPedersenParams()
	//// setup group signature
	//sk, err := rand.Int(rand.Reader, mod)
	//if err != nil {
	//	panic(err)
	//}
	//gamma, _ := rand.Int(rand.Reader, mod)
	//
	//bbsSE, err := InitBbsSE(gamma, sk)
	//if err != nil {
	//	panic(err)
	//}
	//
	//err = SaveTestParams("params", pp, bbsSE)
	//if err != nil {
	//	panic(err)
	//}

	// ===== read the parameters =====
	pp, bbsSE, err := LoadTestParams("params")
	if err != nil {
		panic(err)
	}

	ppStr := pedersenParamsToBase64String(pp)
	gpStr := groupParamsToBase64String(bbsSE.Params)

	fmt.Println("pp: ", *ppStr)
	fmt.Println("bbsSE: ", *gpStr)

	pp2, _ := base64StringToPedersenParams(ppStr)
	gp2, _ := base64StringToGroupParams(gpStr)

	// user key y
	y, _ := rand.Int(rand.Reader, mod)
	Y0 := new(bn254.G1Affine).ScalarMultiplication(bbsSE.h0, new(big.Int).Neg(y))
	Y := new(bn254.G1Affine).ScalarMultiplication(bbsSE.h, new(big.Int).Neg(y))
	user, err := bbsSE.UserKeyGen(Y0, Y)
	if err != nil {
		panic(err)
	}
	user.y = y

	//nonce, _ := rand.Int(rand.Reader, mod)
	//fmt.Println("nonce: ", nonce)

	// use static nonce
	nStr := "17077557196202813204801775360160812872901728681867794927808072673056060376603"
	nonce, _ := new(big.Int).SetString(nStr, 10)

	M, err := getRandomG1Affine()
	if err != nil {
		panic(err)
	}

	// setup s3cross
	s3c := &S3Cross{
		UserKey:        user,
		PedersenParams: pp2,
	}
	_, s3cP, err := s3c.GenPseudonym(M, nonce, v, bits)
	if err != nil {
		panic(err)
	}

	// ===== s3cP to string =====
	s3cStr := s3crossProofToBase64String(s3cP)

	fmt.Println("s3cStr: ", *s3cStr)
	fmt.Println("s3cStr-len: ", len(*s3cStr))
	indC1 := s3cP.C1.Bytes()
	fmt.Println("ppk:    ", base64.StdEncoding.EncodeToString(indC1[:]))

	s3cP2, err := base64StringToS3CrossProof(s3cStr)
	if err != nil {
		panic(err)
	}

	err = VerifyPseudonym(s3cP, pp2, gp2, nonce, bits)
	if err != nil {
		panic(errors.New("original: " + err.Error()))
	}

	err = VerifyPseudonym(s3cP2, pp2, gp2, nonce, bits)
	if err != nil {
		panic(errors.New("marshal: " + err.Error()))
	}
}

type StaticParams struct {
	StaticPP
	StaticGP
}

type StaticPP struct {
	G   []byte `json:"G"`
	H   []byte `json:"H"`
	Mod []byte `json:"mod"`
}

type StaticGP struct {
	Gamma []byte `json:"gamma"`
	Sk    []byte `json:"Sk"`

	G1 []byte `json:"g1"`
	G2 []byte `json:"g2"`
	PK []byte `json:"pk"`
	W  []byte `json:"w"`
	H_ []byte `json:"h"`
	H0 []byte `json:"h0"`
}

func SaveTestParams(filename string, pp *PedersenParams, bbsSE *BbsSE) error {
	indG := pp.G.Bytes()
	indH := pp.H.Bytes()

	indg1 := bbsSE.g1.Bytes()
	indg2 := bbsSE.g2.Bytes()
	indpk := bbsSE.pk.Bytes()
	indw := bbsSE.w.Bytes()
	indh := bbsSE.h.Bytes()
	indh0 := bbsSE.h0.Bytes()

	params := &StaticParams{
		StaticPP: StaticPP{
			G:   indG[:],
			H:   indH[:],
			Mod: pp.Mod.Bytes(),
		},
		StaticGP: StaticGP{
			Gamma: bbsSE.gamma.Bytes(),
			Sk:    bbsSE.sk.Bytes(),
			G1:    indg1[:],
			G2:    indg2[:],
			PK:    indpk[:],
			W:     indw[:],
			H_:    indh[:],
			H0:    indh0[:],
		},
	}
	data, err := json.MarshalIndent(params, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filename, data, 0644)
}

func LoadTestParams(filename string) (*PedersenParams, *BbsSE, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, nil, err
	}
	var params StaticParams
	if err = json.Unmarshal(data, &params); err != nil {
		return nil, nil, err
	}

	var pp PedersenParams
	pp.G = new(bn254.G1Affine)
	_, err = pp.G.SetBytes(params.G)
	if err != nil {
		return nil, nil, err
	}
	pp.H = new(bn254.G1Affine)
	_, _ = pp.H.SetBytes(params.H)
	pp.Mod = new(big.Int).SetBytes(params.Mod)

	var bbsSE BbsSE
	bbsSE.gamma = new(big.Int).SetBytes(params.Gamma)
	bbsSE.sk = new(big.Int).SetBytes(params.Sk)

	var gp Params
	gp.g1 = new(bn254.G1Affine)
	gp.g2 = new(bn254.G2Affine)
	gp.pk = new(bn254.G1Affine)
	gp.w = new(bn254.G2Affine)
	gp.h = new(bn254.G1Affine)
	gp.h0 = new(bn254.G1Affine)
	_, _ = gp.g1.SetBytes(params.G1)
	_, _ = gp.g2.SetBytes(params.G2)
	_, _ = gp.pk.SetBytes(params.PK)
	_, _ = gp.w.SetBytes(params.W)
	_, _ = gp.h.SetBytes(params.H_)
	_, _ = gp.h0.SetBytes(params.H0)
	bbsSE.Params = &gp

	return &pp, &bbsSE, nil
}

func pedersenParamsToBase64String(pp *PedersenParams) *string {
	indG := pp.G.Bytes()
	indH := pp.H.Bytes()

	spp := StaticPP{
		G:   indG[:],
		H:   indH[:],
		Mod: pp.Mod.Bytes(),
	}
	ppJson, _ := json.MarshalIndent(spp, "", "  ")
	ppStr := base64.StdEncoding.EncodeToString(ppJson)
	return &ppStr
}

func base64StringToPedersenParams(ppStr *string) (*PedersenParams, error) {
	ppJson, _ := base64.StdEncoding.DecodeString(*ppStr)
	var tpp StaticPP
	if err := json.Unmarshal(ppJson, &tpp); err != nil {
		return nil, errors.New("Pedersen params json.Unmarshal failed: " + err.Error())
	}
	var pp PedersenParams
	pp.G = new(bn254.G1Affine)
	_, err := pp.G.SetBytes(tpp.G)
	if err != nil {
		return nil, err
	}
	pp.H = new(bn254.G1Affine)
	_, _ = pp.G.SetBytes(tpp.G)
	pp.Mod = new(big.Int).SetBytes(tpp.Mod)

	return &pp, nil
}

func groupParamsToBase64String(gp *Params) *string {
	indg1 := gp.g1.Bytes()
	indg2 := gp.g2.Bytes()
	indpk := gp.pk.Bytes()
	indw := gp.w.Bytes()
	indh := gp.h.Bytes()
	indh0 := gp.h0.Bytes()

	sgp := StaticGP{
		G1: indg1[:],
		G2: indg2[:],
		PK: indpk[:],
		W:  indw[:],
		H_: indh[:],
		H0: indh0[:],
	}
	gpJson, _ := json.MarshalIndent(sgp, "", "  ")
	gpStr := base64.StdEncoding.EncodeToString(gpJson)
	return &gpStr
}

func base64StringToGroupParams(gpStr *string) (*Params, error) {
	gpJson, _ := base64.StdEncoding.DecodeString(*gpStr)
	var tgp StaticGP
	if err := json.Unmarshal(gpJson, &tgp); err != nil {
		return nil, errors.New("Group params json.Unmarshal failed: " + err.Error())
	}
	var gp Params
	gp.g1 = new(bn254.G1Affine)
	gp.g2 = new(bn254.G2Affine)
	gp.pk = new(bn254.G1Affine)
	gp.w = new(bn254.G2Affine)
	gp.h = new(bn254.G1Affine)
	gp.h0 = new(bn254.G1Affine)
	_, err := gp.g1.SetBytes(tgp.G1)
	if err != nil {
		return nil, err
	}
	_, _ = gp.g2.SetBytes(tgp.G2)
	_, _ = gp.pk.SetBytes(tgp.PK)
	_, _ = gp.w.SetBytes(tgp.W)
	_, _ = gp.h.SetBytes(tgp.H_)
	_, _ = gp.h0.SetBytes(tgp.H0)

	return &gp, nil
}

type S3CProofJson struct {
	BorromeanProofJson
	GroupSignatureJson
	PsuProofJson
}

type BorromeanProofJson struct {
	C  []byte   `json:"C"`
	E0 []byte   `json:"e0"`
	C_ [][]byte `json:"C_"`
	S  [][]byte `json:"s"`
}

type GroupSignatureJson struct {
	M    []byte `json:"M"`
	C1   []byte `json:"C1"`
	C2   []byte `json:"C2"`
	A1   []byte `json:"A1"`
	A_   []byte `json:"A_"`
	D    []byte `json:"d"`
	CInt []byte `json:"c"`
	SX   []byte `json:"sX"`
	SY   []byte `json:"sY"`
	SR   []byte `json:"sR"`
	SR2  []byte `json:"sR2"`
	SR3  []byte `json:"sR3"`
	SS   string `json:"sS"` // not loose of sign
}

type PsuProofJson struct {
	CP  []byte `json:"cp"`
	SYP []byte `json:"sYP"`
	SVP []byte `json:"sVP"`
	SRP []byte `json:"sRP"`
	SPP []byte `json:"sPP"`
}

func s3crossProofToBase64String(s3p *S3CProof) *string {
	// BorromeanProof.CInt
	C_ := make([][]byte, len(s3p.C_))
	for i, v := range s3p.C_ {
		ind := v.Bytes()
		C_[i] = ind[:]
	}
	// BorromeanProof.s
	S := make([][]byte, len(s3p.s))
	for i, v := range s3p.s {
		S[i] = v.Bytes()
	}

	// Borromean
	indBo_C := s3p.C.Bytes()
	// GS
	indGS_M := s3p.M.Bytes()
	indGS_C1 := s3p.C1.Bytes()
	indGS_C2 := s3p.C2.Bytes()
	indGS_A1 := s3p.A1.Bytes()
	indGS_A_ := s3p.A_.Bytes()
	indGS_D := s3p.d.Bytes()
	// Psu
	s3pJ := S3CProofJson{
		BorromeanProofJson: BorromeanProofJson{
			C:  indBo_C[:],
			E0: s3p.e0.Bytes(),
			C_: C_,
			S:  S,
		},
		GroupSignatureJson: GroupSignatureJson{
			M:    indGS_M[:],
			C1:   indGS_C1[:],
			C2:   indGS_C2[:],
			A1:   indGS_A1[:],
			A_:   indGS_A_[:],
			D:    indGS_D[:],
			CInt: s3p.c.Bytes(),
			SX:   s3p.sX.Bytes(),
			SY:   s3p.sY.Bytes(),
			SR:   s3p.sR.Bytes(),
			SR2:  s3p.sR2.Bytes(),
			SR3:  s3p.sR3.Bytes(),
			SS:   s3p.sS.String(),
		},
		PsuProofJson: PsuProofJson{
			CP:  s3p.cp.Bytes(),
			SYP: s3p.sYP.Bytes(),
			SVP: s3p.sVP.Bytes(),
			SRP: s3p.sRP.Bytes(),
			SPP: s3p.sPP.Bytes(),
		},
	}

	s3pJson, _ := json.MarshalIndent(s3pJ, "", "  ")
	s3pStr := base64.StdEncoding.EncodeToString(s3pJson)
	return &s3pStr
}

func base64StringToS3CrossProof(s3pStr *string) (*S3CProof, error) {
	s3pJson, _ := base64.StdEncoding.DecodeString(*s3pStr)
	var s3pJ S3CProofJson
	if err := json.Unmarshal(s3pJson, &s3pJ); err != nil {
		return nil, errors.New("Group params json.Unmarshal failed: " + err.Error())
	}
	var s3p S3CProof
	// BorromeanProof
	var bp BorromeanProof
	bp.C = new(bn254.G1Affine)
	_, err := bp.C.SetBytes(s3pJ.C)
	if err != nil {
		return nil, err
	}

	bp.e0 = new(big.Int).SetBytes(s3pJ.E0)

	C_ := make([]*bn254.G1Affine, len(s3pJ.CInt))
	for i, v := range s3pJ.C_ {
		C_[i] = new(bn254.G1Affine)
		_, _ = C_[i].SetBytes(v)
	}
	bp.C_ = C_

	s := make([]*big.Int, len(s3pJ.S))
	for i, v := range s3pJ.S {
		s[i] = new(big.Int).SetBytes(v)
	}
	bp.s = s
	s3p.BorromeanProof = &bp

	// GroupSignature
	var gs GroupSignature
	gs.M = new(bn254.G1Affine)
	gs.C1 = new(bn254.G1Affine)
	gs.C2 = new(bn254.G1Affine)
	gs.A1 = new(bn254.G1Affine)
	gs.A_ = new(bn254.G1Affine)
	gs.d = new(bn254.G1Affine)
	_, _ = gs.M.SetBytes(s3pJ.M)
	_, _ = gs.C1.SetBytes(s3pJ.C1)
	_, _ = gs.C2.SetBytes(s3pJ.C2)
	_, _ = gs.A1.SetBytes(s3pJ.A1)
	_, _ = gs.A_.SetBytes(s3pJ.A_)
	_, _ = gs.d.SetBytes(s3pJ.D)
	gs.c = new(big.Int).SetBytes(s3pJ.CInt)
	gs.sX = new(big.Int).SetBytes(s3pJ.SX)
	gs.sY = new(big.Int).SetBytes(s3pJ.SY)
	gs.sR = new(big.Int).SetBytes(s3pJ.SR)
	gs.sR2 = new(big.Int).SetBytes(s3pJ.SR2)
	gs.sR3 = new(big.Int).SetBytes(s3pJ.SR3)
	gs.sS, _ = new(big.Int).SetString(s3pJ.SS, 10)
	s3p.GroupSignature = &gs

	// PsuProof
	var psuP PsuProof
	psuP.cp = new(big.Int).SetBytes(s3pJ.CP)
	psuP.sYP = new(big.Int).SetBytes(s3pJ.SYP)
	psuP.sVP = new(big.Int).SetBytes(s3pJ.SVP)
	psuP.sRP = new(big.Int).SetBytes(s3pJ.SRP)
	psuP.sPP = new(big.Int).SetBytes(s3pJ.SPP)
	s3p.PsuProof = &psuP

	return &s3p, nil
}
