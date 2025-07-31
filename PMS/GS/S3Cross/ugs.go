package S3Cross

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
)

// BbsSE BBS group signature with Strong Exculpability
type BbsSE struct {
	gamma, sk *big.Int // For sig and dec
	*Params
}

type Params struct {
	g1 *bn254.G1Affine
	g2 *bn254.G2Affine

	pk *bn254.G1Affine
	w  *bn254.G2Affine

	h, h0 *bn254.G1Affine
}

type UserKey struct {
	x, y *big.Int
	A    *bn254.G1Affine

	*Params
}

type RevokedKey struct {
	xi     *big.Int
	Ai, hi *bn254.G1Affine
	Ai_    *bn254.G2Affine
}

type GroupSignature struct {
	M         *bn254.G1Affine // Message (can be omitted)
	C1, C2    *bn254.G1Affine // ElGamal ciphertext
	A1, A_, d *bn254.G1Affine // SoK

	c, sX, sY, sR, sR2, sR3, sS *big.Int
}

func InitBbsSE(gamma, sk *big.Int) (*BbsSE, error) {
	_, _, G1AffGen, G2AffGen := bn254.Generators()

	w := new(bn254.G2Affine).ScalarMultiplication(&G2AffGen, gamma)
	h, err := getRandomG1Affine()
	if err != nil {
		return nil, errors.New("getRandomG1Affine failed: " + err.Error())
	}
	h0, _ := getRandomG1Affine()
	pk := new(bn254.G1Affine).ScalarMultiplication(h, sk)

	bbsSE := &BbsSE{
		gamma: gamma,
		sk:    sk,
		Params: &Params{
			g1: &bn254.G1Affine{
				X: G1AffGen.X,
				Y: G1AffGen.Y,
			},
			g2: &bn254.G2Affine{
				X: G2AffGen.X,
				Y: G2AffGen.Y,
			},
			pk: pk,
			w:  w,
			h:  h,
			h0: h0,
		},
	}

	return bbsSE, nil
}

func (bbsSE *BbsSE) UserKeyGen(Y0, Y *bn254.G1Affine) (*UserKey, error) {
	mod := bn254.ID.ScalarField()
	x, err := rand.Int(rand.Reader, mod)
	if err != nil {
		return nil, nil
	}

	A := new(bn254.G1Affine).ScalarMultiplication(new(bn254.G1Affine).Add(bbsSE.g1, Y0), new(big.Int).ModInverse(new(big.Int).Add(bbsSE.gamma, x), mod))

	// store Y for tracing
	_ = Y
	// lack y
	user := &UserKey{
		x: x,
		A: A,
		Params: &Params{
			g1: bbsSE.g1,
			g2: bbsSE.g2,
			pk: bbsSE.pk,
			w:  bbsSE.w,
			h:  bbsSE.h,
			h0: bbsSE.h0,
		},
	}
	return user, nil
}

func (bbsSE *BbsSE) RevokeGen(xi *big.Int) *RevokedKey {
	mod := bn254.ID.ScalarField()
	Ai := new(bn254.G1Affine).ScalarMultiplication(bbsSE.g1, new(big.Int).ModInverse(new(big.Int).Add(bbsSE.gamma, xi), mod))
	hi := new(bn254.G1Affine).ScalarMultiplication(bbsSE.h0, new(big.Int).ModInverse(new(big.Int).Add(bbsSE.gamma, xi), mod))
	Ai_ := new(bn254.G2Affine).ScalarMultiplication(bbsSE.g2, new(big.Int).ModInverse(new(big.Int).Add(bbsSE.gamma, xi), mod))

	rk := &RevokedKey{
		xi:  xi,
		Ai:  Ai,
		hi:  hi,
		Ai_: Ai_,
	}

	return rk
}

func (bbsSE *BbsSE) Open(gs *GroupSignature) *bn254.G1Affine {
	C1SK := new(bn254.G1Affine).ScalarMultiplication(gs.C1, bbsSE.sk)
	M := new(bn254.G1Affine).Sub(gs.C2, C1SK)

	return M
}

func (para *Params) UpdateParams(rk *RevokedKey) {
	para.g1 = rk.Ai
	para.g2 = rk.Ai_
	para.h0 = rk.hi
	para.w = new(bn254.G2Affine).Add(para.g2, new(bn254.G2Affine).ScalarMultiplication(rk.Ai_, new(big.Int).Neg(rk.xi)))
}

func (usk *UserKey) RevokeExe(rk *RevokedKey) error {
	mod := bn254.ID.ScalarField()

	usk.Params.UpdateParams(rk)

	ind := new(big.Int).ModInverse(new(big.Int).Sub(usk.x, rk.xi), mod)
	if ind == nil {
		return errors.New("RevokedKey is invalid")
	}
	nA := new(bn254.G1Affine).Add(new(bn254.G1Affine).ScalarMultiplication(rk.Ai, ind), new(bn254.G1Affine).ScalarMultiplication(rk.hi, new(big.Int).Mul(new(big.Int).Neg(usk.y), ind)))
	nA.Sub(nA, new(bn254.G1Affine).ScalarMultiplication(usk.A, ind))
	usk.A = nA

	return nil
}

func (usk *UserKey) UserKeyVerify() error {
	p0Right := new(bn254.G2Affine).Add(usk.w, new(bn254.G2Affine).ScalarMultiplication(usk.g2, usk.x))
	p1Left := new(bn254.G1Affine).Add(usk.g1, new(bn254.G1Affine).ScalarMultiplication(usk.h0, new(big.Int).Neg(usk.y)))
	res0, err := bn254.Pair([]bn254.G1Affine{*usk.A}, []bn254.G2Affine{*p0Right})
	if err != nil {
		return err
	}
	res1, err := bn254.Pair([]bn254.G1Affine{*p1Left}, []bn254.G2Affine{*usk.g2})
	if err != nil {
		return err
	}
	if !res0.Equal(&res1) {
		return errors.New("invalid result")
	}
	return nil
}

// GroupSign group signature scheme
// M: the message to be signed
// p: can be a random scalar or the pseudonym secret key
func (usk *UserKey) GroupSign(M *bn254.G1Affine, p *big.Int) (*GroupSignature, error) {
	mod := bn254.ID.ScalarField()
	r1, _ := rand.Int(rand.Reader, mod)
	r2, _ := rand.Int(rand.Reader, mod)

	r3 := new(big.Int).ModInverse(r1, mod)
	s := new(big.Int).Neg(new(big.Int).Mul(r2, r3))

	// ElGamal Enc
	// C1 can also be treated as the pseudonym public key
	C1 := new(bn254.G1Affine).ScalarMultiplication(usk.h, p)
	C2 := new(bn254.G1Affine).Add(new(bn254.G1Affine).ScalarMultiplication(usk.h, new(big.Int).Neg(usk.y)), new(bn254.G1Affine).ScalarMultiplication(usk.pk, p))

	// Group Sig
	A1 := new(bn254.G1Affine).ScalarMultiplication(usk.A, r1)
	ind := new(bn254.G1Affine).ScalarMultiplication(new(bn254.G1Affine).Add(usk.g1, new(bn254.G1Affine).ScalarMultiplication(usk.h0, new(big.Int).Neg(usk.y))), r1)
	A_ := new(bn254.G1Affine).Add(new(bn254.G1Affine).ScalarMultiplication(A1, new(big.Int).Neg(usk.x)), ind)
	d := new(bn254.G1Affine).Add(ind, new(bn254.G1Affine).ScalarMultiplication(usk.h0, new(big.Int).Neg(r2)))

	// Random Mask
	nX, _ := rand.Int(rand.Reader, mod)
	nY, _ := rand.Int(rand.Reader, mod)
	nR, _ := rand.Int(rand.Reader, mod)
	nR2, _ := rand.Int(rand.Reader, mod)
	nR3, _ := rand.Int(rand.Reader, mod)
	nS, _ := rand.Int(rand.Reader, mod)

	// Equation
	E1 := new(bn254.G1Affine).Add(new(bn254.G1Affine).ScalarMultiplication(A1, new(big.Int).Neg(nX)), new(bn254.G1Affine).ScalarMultiplication(usk.h0, nR2))
	E2 := new(bn254.G1Affine).Add(new(bn254.G1Affine).ScalarMultiplication(d, nR3), new(bn254.G1Affine).ScalarMultiplication(usk.h0, nY))
	E2.Add(E2, new(bn254.G1Affine).ScalarMultiplication(usk.h0, new(big.Int).Neg(nS)))
	E3 := new(bn254.G1Affine).ScalarMultiplication(usk.h, nR)
	E4 := new(bn254.G1Affine).Add(new(bn254.G1Affine).ScalarMultiplication(usk.h, new(big.Int).Neg(nY)), new(bn254.G1Affine).ScalarMultiplication(usk.pk, nR))

	//fmt.Println("E1: ", E1.String())
	//fmt.Println("E2: ", E2.String())
	//fmt.Println("E3: ", E3.String())
	//fmt.Println("E4: ", E4.String())

	h := sha256.New()
	// message
	h.Write(M.Marshal())
	// params
	h.Write(usk.g1.Marshal())
	h.Write(usk.g2.Marshal())
	h.Write(usk.pk.Marshal())
	h.Write(usk.w.Marshal())
	h.Write(usk.h.Marshal())
	h.Write(usk.h0.Marshal())
	// ElGamal
	h.Write(C1.Marshal())
	h.Write(C2.Marshal())
	// Group
	h.Write(A1.Marshal())
	h.Write(A_.Marshal())
	h.Write(d.Marshal())
	// SoK
	h.Write(E1.Marshal())
	h.Write(E2.Marshal())
	h.Write(E3.Marshal())
	h.Write(E4.Marshal())
	c := new(big.Int).SetBytes(h.Sum(nil))

	sX := new(big.Int).Add(nX, new(big.Int).Mul(c, usk.x))
	sY := new(big.Int).Add(nY, new(big.Int).Mul(c, usk.y))
	sR := new(big.Int).Add(nR, new(big.Int).Mul(c, p))
	sR2 := new(big.Int).Add(nR2, new(big.Int).Mul(c, r2))
	sR3 := new(big.Int).Add(nR3, new(big.Int).Mul(c, r3))
	sS := new(big.Int).Add(nS, new(big.Int).Mul(c, s))

	return &GroupSignature{
		M:   M,
		C1:  C1,
		C2:  C2,
		A1:  A1,
		A_:  A_,
		d:   d,
		c:   c,
		sX:  sX,
		sY:  sY,
		sR:  sR,
		sR2: sR2,
		sR3: sR3,
		sS:  sS,
	}, nil
}

func GroupVerify(gs *GroupSignature, para *Params) error {
	// new version
	// g1Z := new(bn254.G1Affine).SetInfinity()

	// old version
	g1Z := new(bn254.G1Affine)
	g1Z.X.SetZero()
	g1Z.Y.SetZero()

	if g1Z.Equal(gs.A1) {
		return errors.New("group verify fail (gs.A1 is infinity)")
	}

	res1, err := bn254.Pair([]bn254.G1Affine{*gs.A1}, []bn254.G2Affine{*para.w})
	if err != nil {
		return errors.New("pairing failure: " + err.Error())
	}
	res2, _ := bn254.Pair([]bn254.G1Affine{*gs.A_}, []bn254.G2Affine{*para.g2})
	if !res1.Equal(&res2) {
		return errors.New("pairing verification for gs failed")
	}

	E1_ := new(bn254.G1Affine).Add(new(bn254.G1Affine).ScalarMultiplication(gs.A1, new(big.Int).Neg(gs.sX)), new(bn254.G1Affine).ScalarMultiplication(para.h0, gs.sR2))
	ind1 := new(bn254.G1Affine).Sub(gs.A_, gs.d)
	ind1.ScalarMultiplication(ind1, gs.c)
	E1_.Sub(E1_, ind1)

	E2_ := new(bn254.G1Affine).Add(new(bn254.G1Affine).ScalarMultiplication(gs.d, gs.sR3), new(bn254.G1Affine).ScalarMultiplication(para.h0, gs.sY))
	E2_.Add(E2_, new(bn254.G1Affine).ScalarMultiplication(para.h0, new(big.Int).Neg(gs.sS)))
	E2_.Sub(E2_, new(bn254.G1Affine).ScalarMultiplication(para.g1, gs.c))

	E3_ := new(bn254.G1Affine).ScalarMultiplication(para.h, gs.sR)
	E3_.Sub(E3_, new(bn254.G1Affine).ScalarMultiplication(gs.C1, gs.c))

	E4_ := new(bn254.G1Affine).Add(new(bn254.G1Affine).ScalarMultiplication(para.h, new(big.Int).Neg(gs.sY)), new(bn254.G1Affine).ScalarMultiplication(para.pk, gs.sR))
	E4_.Sub(E4_, new(bn254.G1Affine).ScalarMultiplication(gs.C2, gs.c))

	//fmt.Println("E1_: ", E1_.String())
	//fmt.Println("E2_: ", E2_.String())
	//fmt.Println("E3_: ", E3_.String())
	//fmt.Println("E4_: ", E4_.String())

	h := sha256.New()
	// message
	h.Write(gs.M.Marshal())
	// params
	h.Write(para.g1.Marshal())
	h.Write(para.g2.Marshal())
	h.Write(para.pk.Marshal())
	h.Write(para.w.Marshal())
	h.Write(para.h.Marshal())
	h.Write(para.h0.Marshal())
	// ElGamal
	h.Write(gs.C1.Marshal())
	h.Write(gs.C2.Marshal())
	// Group
	h.Write(gs.A1.Marshal())
	h.Write(gs.A_.Marshal())
	h.Write(gs.d.Marshal())
	// SoK
	h.Write(E1_.Marshal())
	h.Write(E2_.Marshal())
	h.Write(E3_.Marshal())
	h.Write(E4_.Marshal())
	c := new(big.Int).SetBytes(h.Sum(nil))

	if c.Cmp(gs.c) != 0 {
		return errors.New("sok verification for gs failed")
	}
	return nil
}

func getRandomG1Affine() (*bn254.G1Affine, error) {
	mod := bn254.ID.ScalarField()
	r, err := rand.Int(rand.Reader, mod)
	if err != nil {
		panic(err)
	}
	R := new(bn254.G1Affine).ScalarMultiplicationBase(r)
	return R, nil
}
