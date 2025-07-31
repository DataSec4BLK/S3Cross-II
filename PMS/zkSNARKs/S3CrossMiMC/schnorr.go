package s3cross

import (
	"crypto/rand"
	"errors"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
)

type KeyPair struct {
	Sk *big.Int                    `json:"sk"`
	Pk *twistededwards.PointAffine `json:"pk"`
}

type Signature struct {
	Sig *big.Int                    `json:"sig"`
	R   *twistededwards.PointAffine `json:"r"`
	M   *twistededwards.PointAffine `json:"m"`
	SPk *twistededwards.PointAffine `json:"spk"`
}

func (kp *KeyPair) Sign(message *twistededwards.PointAffine) (*Signature, *big.Int, error) {
	curve := twistededwards.GetEdwardsCurve()

	r, err := rand.Int(rand.Reader, &curve.Order)
	if err != nil {
		panic(err)
	}

	// 计算 R = r·G
	R := new(twistededwards.PointAffine).ScalarMultiplication(&curve.Base, r)

	// Mimc hash: H(pk || R || m)
	h := mimc.NewMiMC()

	// 写入 Pk
	_, err = h.Write(kp.Pk.X.Marshal())
	if err != nil {
		return &Signature{}, r, err
	}
	_, err = h.Write(kp.Pk.Y.Marshal())
	// 写入 R
	_, err = h.Write(R.X.Marshal())
	_, err = h.Write(R.Y.Marshal())
	// 写入消息
	_, err = h.Write(message.X.Marshal())
	_, err = h.Write(message.Y.Marshal())

	c := new(big.Int).SetBytes(h.Sum(nil))

	// s = r + c·sk
	s := new(big.Int).Add(r, new(big.Int).Mul(c, kp.Sk))
	s.Mod(s, &curve.Order) // 需要手动mod

	return &Signature{
		Sig: s,
		R:   R,
		M:   message,
		SPk: kp.Pk,
	}, r, nil
}

func (s *Signature) Verify() error {
	curve := twistededwards.GetEdwardsCurve()

	// Mimc hash: H(pk || R || m)
	h := mimc.NewMiMC()
	_, err := h.Write(s.SPk.X.Marshal())
	if err != nil {
		return err
	}
	_, err = h.Write(s.SPk.Y.Marshal())
	_, err = h.Write(s.R.X.Marshal())
	_, err = h.Write(s.R.Y.Marshal())
	_, err = h.Write(s.M.X.Marshal())
	_, err = h.Write(s.M.Y.Marshal())

	c := new(big.Int).SetBytes(h.Sum(nil))

	// 验证：s·G == R + c·X
	sG := new(twistededwards.PointAffine).ScalarMultiplication(&curve.Base, s.Sig)

	Xc := new(twistededwards.PointAffine).ScalarMultiplication(s.SPk, c)
	RXc := new(twistededwards.PointAffine).Add(s.R, Xc)

	if !sG.Equal(RXc) {
		return errors.New("invalid signature")
	}
	return nil
}
