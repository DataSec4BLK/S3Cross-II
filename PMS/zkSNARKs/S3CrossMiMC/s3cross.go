package s3cross

import (
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"math/big"
	"slices"
)

type S3Cross struct {
	*KeyPair
	*Signature
}

const TreeDepth = 30

// NewPseudonym generate new psu
func (s *S3Cross) NewPseudonym(i *big.Int, nonce *twistededwards.PointAffine) (*big.Int, *KeyPair, error) {
	h := mimc.NewMiMC()
	_, err := h.Write(nonce.X.Marshal())
	if err != nil {
		return &big.Int{}, &KeyPair{}, err
	}
	_, err = h.Write(nonce.Y.Marshal())
	nc := new(big.Int).SetBytes(h.Sum(nil))
	psu, err := GenPsu(s.Sk, i, nc)

	return nc, psu, err
}

// GenNonMemProof
// leaves: current ordered merkle tree
func (s *S3Cross) GenNonMemProof(leaves []*big.Int) (*MerkleProof, *big.Int, error) {
	slices.SortFunc(leaves, func(a, b *big.Int) int {
		return a.Cmp(b)
	})

	h := mimc.NewMiMC()
	_, err := h.Write(s.Pk.X.Marshal())
	if err != nil {
		return &MerkleProof{}, nil, err
	}
	_, err = h.Write(s.Pk.Y.Marshal())
	c := new(big.Int).SetBytes(h.Sum(nil))

	var tl1, tl2 int
	for i := 1; i < len(leaves); i++ {
		if c.Cmp(leaves[i]) < 0 {
			tl1 = i - 1
			tl2 = i
			break
		}
	}

	leavesBS := make([][]byte, len(leaves))
	for i, v := range leaves {
		leavesBS[i] = v.Bytes()
	}

	dl := computeMaxDefaultLevels(TreeDepth)
	root := CalcRoot(leavesBS, dl)
	nodes := BuildPartialTree(leavesBS, dl)

	// path left
	proof1 := MerkleProofSiblings(nodes, dl, tl1)
	//proof2 := MerkleProofSiblings(nodes, dl, tl2)

	return &MerkleProof{
		Root:  root,
		Proof: proof1,
		Index: tl1,
		Leaf:  leaves[tl1],
	}, leaves[tl2], nil
}
