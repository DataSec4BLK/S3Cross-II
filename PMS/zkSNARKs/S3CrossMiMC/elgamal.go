package s3cross

import (
	"crypto/rand"
	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"math/big"
)

type ElGamal struct {
	C1 *twistededwards.PointAffine `json:"c1"`
	C2 *twistededwards.PointAffine `json:"c2"`
}

func EncryptElGamal(M, Pk *twistededwards.PointAffine) (*ElGamal, *big.Int, error) {
	curve := twistededwards.GetEdwardsCurve()

	r, err := rand.Int(rand.Reader, &curve.Order)
	if err != nil {
		panic(err)
	}
	C1 := new(twistededwards.PointAffine).ScalarMultiplication(&curve.Base, r)

	C2 := new(twistededwards.PointAffine).ScalarMultiplication(Pk, r)
	C2.Add(M, C2)

	return &ElGamal{
		C1: C1,
		C2: C2,
	}, r, nil
}

func (kp *KeyPair) Decrypt(eg *ElGamal) (*twistededwards.PointAffine, error) {
	ind := new(twistededwards.PointAffine).ScalarMultiplication(eg.C1, kp.Sk)
	M := new(twistededwards.PointAffine).Add(eg.C2, new(twistededwards.PointAffine).Neg(ind))
	return M, nil
}
