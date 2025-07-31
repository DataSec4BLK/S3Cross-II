package S3Cross

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"math/big"
)

type S3Cross struct {
	*UserKey        // Group signature
	*PedersenParams // For borromean range proof
}

type KeyPair struct {
	sk *big.Int
	pk *bn254.G1Affine
}

type PsuProof struct {
	cp                 *big.Int
	sYP, sVP, sRP, sPP *big.Int
}

type S3CProof struct {
	*BorromeanProof
	*GroupSignature
	*PsuProof
}

// GenPseudonym generate the pseudonym with zkp
func (s *S3Cross) GenPseudonym(M *bn254.G1Affine, nonce, v *big.Int, bits int) (*KeyPair, *S3CProof, error) {
	// range proof
	// // 0 < v < 2^bits
	boProof, r, err := BorromeanProve(s.PedersenParams, v, bits)
	if err != nil {
		panic(errors.New("GenPseudonym: BorromeanProve error due to -- " + err.Error()))
	}

	// generate pseudonym
	// // p = nonce/(y+v+1)
	p := new(big.Int).Mul(nonce, new(big.Int).ModInverse(new(big.Int).Add(new(big.Int).Add(s.y, v), big.NewInt(1)), s.Mod))

	// group signature
	gs, err := s.GroupSign(M, p)
	if err != nil {
		panic(err)
	}

	// psu proof
	r_y, err := rand.Int(rand.Reader, s.Mod)
	if err != nil {
		panic(err)
	}
	r_v, _ := rand.Int(rand.Reader, s.Mod)
	r_r, _ := rand.Int(rand.Reader, s.Mod)
	r_p, _ := rand.Int(rand.Reader, s.Mod)

	PM1 := new(bn254.G1Affine).ScalarMultiplication(gs.C1, new(big.Int).Add(r_y, r_v))
	PM2 := s.PedersenParams.Commit(r_v, r_r)
	PM3 := new(bn254.G1Affine).Add(new(bn254.G1Affine).ScalarMultiplication(s.pk, r_p), new(bn254.G1Affine).ScalarMultiplication(s.h, new(big.Int).Neg(r_y)))
	h := sha256.New()
	h.Write(gs.c.Bytes())
	h.Write(s.G.Marshal())
	h.Write(s.H.Marshal())
	h.Write(boProof.C.Marshal())
	h.Write(PM1.Marshal())
	h.Write(PM2.Marshal())
	h.Write(PM3.Marshal())
	cp := new(big.Int).SetBytes(h.Sum(nil))

	sYP := new(big.Int).Add(r_y, new(big.Int).Mul(cp, s.y))
	sVP := new(big.Int).Add(r_v, new(big.Int).Mul(cp, v))
	sRP := new(big.Int).Add(r_r, new(big.Int).Mul(cp, r))
	sPP := new(big.Int).Add(r_p, new(big.Int).Mul(cp, p))

	return &KeyPair{
			sk: p,
			pk: gs.C1,
		}, &S3CProof{
			BorromeanProof: boProof,
			GroupSignature: gs,
			PsuProof: &PsuProof{
				cp:  cp,
				sYP: sYP,
				sVP: sVP,
				sRP: sRP,
				sPP: sPP,
			},
		}, nil
}

func VerifyPseudonym(s3cP *S3CProof, pp *PedersenParams, gp *Params, nonce *big.Int, bits int) error {
	// verify range proof
	err := BorromeanVerify(pp, s3cP.BorromeanProof, bits)
	if err != nil {
		return errors.New("S3CProof: BorromeanVerify failed due to -- " + err.Error())
	}

	// verify group signature
	err = GroupVerify(s3cP.GroupSignature, gp)
	if err != nil {
		return errors.New("S3CProof: GroupVerify failed due to -- " + err.Error())
	}

	// verify the psu proof
	BK1 := new(bn254.G1Affine).Sub(new(bn254.G1Affine).ScalarMultiplication(gp.h, nonce), s3cP.C1)
	PM1 := new(bn254.G1Affine).ScalarMultiplication(s3cP.C1, new(big.Int).Add(s3cP.PsuProof.sYP, s3cP.PsuProof.sVP))
	PM1.Sub(PM1, new(bn254.G1Affine).ScalarMultiplication(BK1, s3cP.cp))

	PM2 := pp.Commit(s3cP.PsuProof.sVP, s3cP.PsuProof.sRP)
	PM2.Sub(PM2, new(bn254.G1Affine).ScalarMultiplication(s3cP.C, s3cP.cp))

	PM3 := new(bn254.G1Affine).Add(new(bn254.G1Affine).ScalarMultiplication(gp.pk, s3cP.PsuProof.sPP), new(bn254.G1Affine).ScalarMultiplication(gp.h, new(big.Int).Neg(s3cP.PsuProof.sYP)))
	PM3.Sub(PM3, new(bn254.G1Affine).ScalarMultiplication(s3cP.C2, s3cP.cp))

	h := sha256.New()
	h.Write(s3cP.c.Bytes())
	h.Write(pp.G.Marshal())
	h.Write(pp.H.Marshal())
	h.Write(s3cP.C.Marshal())
	h.Write(PM1.Marshal())
	h.Write(PM2.Marshal())
	h.Write(PM3.Marshal())
	cp := new(big.Int).SetBytes(h.Sum(nil))

	if cp.Cmp(s3cP.cp) != 0 {
		return errors.New("S3CProof: PseudonymVerify failed")
	}

	return nil
}
