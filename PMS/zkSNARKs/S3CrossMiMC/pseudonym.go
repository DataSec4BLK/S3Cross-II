package s3cross

import (
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"math/big"
)

// GenPsu use fr.Element to process the interior calculation
func GenPsu(sk, i, nonce *big.Int) (*KeyPair, error) {
	curve := twistededwards.GetEdwardsCurve()

	// convert to fr.Element format
	var skFr, iFr, nonceFr fr.Element
	skFr.SetBigInt(sk)
	iFr.SetBigInt(i)
	nonceFr.SetBigInt(nonce)

	// ensure the mimc function is correct
	h := mimc.NewMiMC()
	_, err := h.Write(nonceFr.Marshal())
	if err != nil {
		return &KeyPair{}, err
	}
	_, err = h.Write(iFr.Marshal())
	hOut := h.Sum(nil)

	// hOut转fr.Element
	var hFr fr.Element
	hFr.SetBytes(hOut)

	psk := skFr
	psk.Add(&psk, &hFr)
	pskInv := psk
	pskInv.Inverse(&pskInv)

	// pskInv 转 big.Int
	pskInvBig := pskInv.BigInt(new(big.Int))
	ppk := new(twistededwards.PointAffine).ScalarMultiplication(&curve.Base, pskInvBig)

	return &KeyPair{
		Sk: pskInvBig,
		Pk: ppk,
	}, nil
}
