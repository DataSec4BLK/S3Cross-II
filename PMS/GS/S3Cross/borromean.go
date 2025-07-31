package S3Cross

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"math/big"
)

type PedersenParams struct {
	G, H *bn254.G1Affine
	Mod  *big.Int
}

type BorromeanProof struct {
	C *bn254.G1Affine // the pedersen commitment (function ``BorromeanProve'' also outputs the value of ``r'')

	e0 *big.Int
	C_ []*bn254.G1Affine
	s  []*big.Int
}

func BitDecompose(x uint64, bits int) []uint8 {
	res := make([]uint8, bits)
	for i := 0; i < bits; i++ {
		res[i] = uint8((x >> uint(i)) & 1)
	}
	return res
}

func GenPedersenParams() *PedersenParams {
	_, _, G1, _ := bn254.Generators()
	H, err := getRandomG1()
	if err != nil {
		panic(err)
	}
	return &PedersenParams{&bn254.G1Affine{
		X: G1.X,
		Y: G1.Y,
	}, H, new(big.Int).Set(bn254.ID.ScalarField())}
}

func (pp *PedersenParams) Commit(x, r *big.Int) *bn254.G1Affine {
	var gx, hr, res bn254.G1Affine
	gx.ScalarMultiplication(pp.H, x)
	hr.ScalarMultiplication(pp.G, r)
	res.Add(&gx, &hr)
	return &res
}

func HashG1ToInt(affine *bn254.G1Affine) *big.Int {
	h := sha256.New()
	h.Write(affine.Marshal())

	return new(big.Int).SetBytes(h.Sum(nil))
}

// BorromeanProve
// pp: Pedersen parameters
// v, r: C_ = vG + rH
// bits: maximum bit length
func BorromeanProve(pp *PedersenParams, v *big.Int, bits int) (*BorromeanProof, *big.Int, error) {
	// 1
	bitsVal := BitDecompose(v.Uint64(), bits)
	k := make([][2]*big.Int, bits)
	k_ := make([]*big.Int, bits)
	R := make([]*bn254.G1Affine, bits)
	r_ := make([]*big.Int, bits)
	C_ := make([]*bn254.G1Affine, bits)
	e := make([][2]*big.Int, bits)
	s := make([]*big.Int, bits)

	var err error
	// 2
	for i := 0; i < bits; i++ {
		if bitsVal[i] == 0 {
			k[i][0], err = rand.Int(rand.Reader, pp.Mod)
			if err != nil {
				panic(err)
			}
			R[i] = new(bn254.G1Affine).ScalarMultiplication(pp.G, k[i][0])
		} else {
			// i
			r_[i], _ = rand.Int(rand.Reader, pp.Mod)
			C_[i] = pp.Commit(new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(i)), nil), r_[i])

			// ii
			k_[i], _ = rand.Int(rand.Reader, pp.Mod)
			e[i][1] = HashG1ToInt(new(bn254.G1Affine).ScalarMultiplication(pp.G, k_[i]))

			// iii -- no-op
			// iv
			R[i] = new(bn254.G1Affine).ScalarMultiplication(C_[i], e[i][1])
		}
	}

	// 3
	h := sha256.New()
	for i := 0; i < bits; i++ {
		h.Write(R[i].Marshal())
	}
	e0 := new(big.Int).SetBytes(h.Sum(nil))

	// 4
	for i := 0; i < bits; i++ {
		if bitsVal[i] == 0 {
			// i
			e[i][0] = e0
			k[i][1], _ = rand.Int(rand.Reader, pp.Mod)
			indE := new(big.Int).Mul(e[i][0], new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(i)), nil))
			e[i][1] = HashG1ToInt(new(bn254.G1Affine).Add(new(bn254.G1Affine).ScalarMultiplication(pp.G, k[i][1]), new(bn254.G1Affine).ScalarMultiplication(pp.H, indE)))

			// ii
			//C_[i] = new(bn254.G1Affine).ScalarMultiplication(pp.G, new(big.Int).Mul(k[i][0], new(big.Int).ModInverse(e[i][1], pp.Mod)))
			C_[i] = new(bn254.G1Affine).ScalarMultiplication(new(bn254.G1Affine).ScalarMultiplication(pp.G, k[i][0]), new(big.Int).ModInverse(e[i][1], pp.Mod))
			// ===== extra =====
			r_[i] = new(big.Int).Mul(k[i][0], new(big.Int).ModInverse(e[i][1], pp.Mod))
			r_[i].Mod(r_[i], pp.Mod)

			// iii
			s[i] = new(big.Int).Add(k[i][1], new(big.Int).Mul(new(big.Int).Mul(k[i][0], e[i][0]), new(big.Int).ModInverse(e[i][1], pp.Mod)))
			s[i].Mod(s[i], pp.Mod)
		} else {
			// i -- no-op
			// ii
			e[i][0] = e0
			s[i] = new(big.Int).Add(k_[i], new(big.Int).Mul(e[i][0], r_[i]))
		}
	}

	// ===== extra =====
	rr := new(big.Int).Set(r_[0])
	for i := 1; i < bits; i++ {
		rr.Add(rr, r_[i])
	}
	//CC := pp.Commit(v, rr)
	//fmt.Println("CC:  ", CC)
	//rr_ := new(big.Int).Mod(rr, pp.Mod)
	//CC_ := pp.Commit(v, rr_)
	//fmt.Println("CC_: ", CC_)

	// 5
	C := new(bn254.G1Affine).Set(C_[0])
	for i := 1; i < bits; i++ {
		C.Add(C, C_[i])
	}

	//fmt.Println("C: ", C)

	return &BorromeanProof{
		C:  C,
		e0: e0,
		C_: C_,
		s:  s,
	}, rr, nil
}

func BorromeanVerify(pp *PedersenParams, bp *BorromeanProof, bits int) error {
	e := make([][2]*big.Int, bits)
	R := make([]*bn254.G1Affine, bits)

	// 1
	for i := 0; i < bits; i++ {
		// a
		e[i][0] = bp.e0

		// b
		eInd := new(bn254.G1Affine).ScalarMultiplication(pp.G, bp.s[i])
		eInd2 := new(bn254.G1Affine).Sub(bp.C_[i], new(bn254.G1Affine).ScalarMultiplication(pp.H, new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(i)), nil)))
		e[i][1] = HashG1ToInt(new(bn254.G1Affine).Sub(eInd, eInd2.ScalarMultiplication(eInd2, e[i][0])))

		// c
		R[i] = new(bn254.G1Affine).ScalarMultiplication(bp.C_[i], e[i][1])
	}

	// 2
	h := sha256.New()
	for i := 0; i < bits; i++ {
		h.Write(R[i].Marshal())
	}
	e0 := new(big.Int).SetBytes(h.Sum(nil))

	// 3
	C__ := new(bn254.G1Affine).Set(bp.C_[0])
	for i := 1; i < bits; i++ {
		C__.Add(C__, bp.C_[i])
	}
	//fmt.Println("bp.e0:   ", bp.e0)
	//fmt.Println("e0: ", e0)
	//fmt.Println("C:   ", bp.C)
	//fmt.Println("C__: ", C__)
	if !bp.C.Equal(C__) || e0.Cmp(bp.e0) != 0 {
		return errors.New("BorromeanVerify error")
	}

	return nil
}

func getRandomG1() (*bn254.G1Affine, error) {
	mod := bn254.ID.ScalarField()
	h, err := rand.Int(rand.Reader, mod)
	if err != nil {
		return nil, errors.New("bn254: failed to generate random h" + err.Error())
	}
	H := new(bn254.G1Affine).ScalarMultiplicationBase(h)
	return H, nil
}
