package s3cross

import (
	twistededwards2 "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/frontend"
	twistededwards1 "github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/rangecheck"
	//"github.com/consensys/gnark/std/rangecheck"
)

type S3CrossCircuit struct {
	// ordered Merkle tree proof
	Root frontend.Variable `gnark:",public"` // 0
	// // left path
	ProofElements1 []frontend.Variable // private
	ProofIndex1    frontend.Variable   // private
	Leaf1          frontend.Variable   `gnark:",public"` // 1 // mimc hash of the public key
	// // right node
	Leaf2 frontend.Variable `gnark:",public"` // 2 // mimc hash of the public key

	// schnorr proof
	IPkX frontend.Variable `gnark:",public"` // 3
	IPkY frontend.Variable `gnark:",public"` // 4

	Sig frontend.Variable // private
	RX  frontend.Variable // private
	RY  frontend.Variable // private

	MessageX frontend.Variable // private
	MessageY frontend.Variable // private

	// psu proof
	PPkX  frontend.Variable `gnark:",public"` // 5
	PPkY  frontend.Variable `gnark:",public"` // 6
	Nonce frontend.Variable `gnark:",public"` // 7 // current nonce for SR, should mod curve.Order
	//MaxI  frontend.Variable `gnark:",public"` // max psu number
	USk frontend.Variable // private
	I   frontend.Variable // private

	// elgamal proof
	SPkX frontend.Variable `gnark:",public"` // 8
	SPkY frontend.Variable `gnark:",public"` // 9
	C1X  frontend.Variable `gnark:",public"` // 10
	C1Y  frontend.Variable `gnark:",public"` // 11
	C2X  frontend.Variable `gnark:",public"` // 12
	C2Y  frontend.Variable `gnark:",public"` // 13
	R    frontend.Variable // private
}

func (circuit *S3CrossCircuit) Define(api frontend.API) error {
	const numBits = 4 // max psu number is 2^numBits - 1

	curve, err := twistededwards1.NewEdCurve(api, twistededwards2.BN254)
	if err != nil {
		return err
	}
	base := twistededwards1.Point{
		X: curve.Params().Base[0],
		Y: curve.Params().Base[1],
	}

	h, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	// check Merkle proof
	// // path 1
	hashed := circuit.Leaf1
	depth := len(circuit.ProofElements1)
	proofIndices := api.ToBinary(circuit.ProofIndex1, depth)
	for i := 0; i < depth; i++ {
		sibling := circuit.ProofElements1[i]
		index := proofIndices[i]

		left := api.Select(index, sibling, hashed)
		right := api.Select(index, hashed, sibling)

		h.Reset()
		h.Write(left, right)
		hashed = h.Sum()
	}
	api.AssertIsEqual(hashed, circuit.Root)

	upk := curve.ScalarMul(base, circuit.USk)
	h.Reset()
	h.Write(upk.X, upk.Y)
	hUpk := h.Sum()
	// // // ProofIndex1 < upk < ProofIndex2
	api.AssertIsLessOrEqual(api.Add(circuit.Leaf1, 1), hUpk)
	api.AssertIsLessOrEqual(api.Add(hUpk, 1), circuit.Leaf2)

	// check schnorr signature
	IPk := twistededwards1.Point{
		X: circuit.IPkX,
		Y: circuit.IPkY,
	}
	R := twistededwards1.Point{
		X: circuit.RX,
		Y: circuit.RY,
	}
	h.Reset()
	h.Write(IPk.X, IPk.Y, R.X, R.Y, circuit.MessageX, circuit.MessageY)
	c := h.Sum()
	// // g^{Sig} = R·X^c
	S := curve.ScalarMul(base, circuit.Sig)
	Xc := curve.ScalarMul(IPk, c)
	RXc := curve.Add(R, Xc)
	api.AssertIsEqual(S.X, RXc.X)
	api.AssertIsEqual(S.Y, RXc.Y)
	// // Message = upk
	api.AssertIsEqual(upk.X, circuit.MessageX)
	api.AssertIsEqual(upk.Y, circuit.MessageY)

	// check pseudonym
	// // I > 0
	api.AssertIsDifferent(circuit.I, 0)

	rc := rangecheck.New(api)
	rc.Check(circuit.I, numBits)

	h.Reset()
	h.Write(circuit.Nonce, circuit.I)
	hOut := h.Sum()
	psk := api.Inverse(api.Add(circuit.USk, hOut))
	ppk := curve.ScalarMul(base, psk)

	api.AssertIsEqual(ppk.X, circuit.PPkX)
	api.AssertIsEqual(ppk.Y, circuit.PPkY)

	// check elgamal
	spk := twistededwards1.Point{
		X: circuit.SPkX,
		Y: circuit.SPkY,
	}
	C1_ := curve.ScalarMul(base, circuit.R)
	C2_ := curve.ScalarMul(spk, circuit.R)
	C2_ = curve.Add(C2_, upk)

	api.AssertIsEqual(circuit.C1X, C1_.X)
	api.AssertIsEqual(circuit.C1Y, C1_.Y)
	api.AssertIsEqual(circuit.C2X, C2_.X)
	api.AssertIsEqual(circuit.C2Y, C2_.Y)

	return nil
}
