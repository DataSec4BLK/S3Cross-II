package s3cross

import (
	"bytes"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"math/big"
)

type MerkleProof struct {
	Root  []byte   `json:"root"`
	Proof [][]byte `json:"proof"`
	Index int      `json:"index"`
	Leaf  *big.Int `json:"leaf"`
}

func CalcRoot(leaves [][]byte, defaultLevels [][]byte) []byte {
	nodes := make(map[int]map[int][]byte) // level -> index -> hash
	nodes[0] = make(map[int][]byte)
	for i, leaf := range leaves {
		nodes[0][i] = leaf
	}

	levelSize := len(leaves)
	for level := 0; level < len(defaultLevels); level++ {
		nodes[level+1] = make(map[int][]byte)
		for i := 0; i < (levelSize+1)/2; i++ {
			left := nodes[level][2*i]
			right, ok := nodes[level][2*i+1]
			if !ok {
				if left == nil {
					left = defaultLevels[level]
				}
				right = defaultLevels[level]
			}
			if left == nil {
				left = defaultLevels[level]
			}
			hashV := hashMiMCLR(left, right) // Your hash function
			nodes[level+1][i] = hashV
		}
		levelSize = (levelSize + 1) / 2
	}

	root := nodes[len(defaultLevels)][0]
	if root == nil {
		root = defaultLevels[len(defaultLevels)]
	}
	return root
}

func hashMiMCLR(left, right []byte) []byte {
	h := mimc.NewMiMC()
	_, err := h.Write(left)
	if err != nil {
		return nil
	}
	_, err = h.Write(right)
	return h.Sum(nil)
}

// computeMaxDefaultLevels
// treeHeight: the maximum depth of the ordered Merkle tree
func computeMaxDefaultLevels(treeHeight int) [][]byte {
	defaultLevels := make([][]byte, treeHeight)

	// use 0xFF as the default leaf value
	//defaultLeaf := bytes.Repeat([]byte{0xFF}, 32)
	defaultLeaf := fr.Modulus().Bytes()
	defaultLevels[0] = defaultLeaf

	for i := 1; i < treeHeight; i++ {
		prev := defaultLevels[i-1]
		defaultLevels[i] = hashMiMCLR(prev, prev)
	}

	return defaultLevels
}

func BuildPartialTree(leaves [][]byte, defaultLevels [][]byte) map[int]map[int][]byte {
	nodes := make(map[int]map[int][]byte)
	nodes[0] = make(map[int][]byte)
	for i, leaf := range leaves {
		nodes[0][i] = leaf
	}

	levelSize := len(leaves)
	for level := 0; level < len(defaultLevels); level++ {
		nodes[level+1] = make(map[int][]byte)
		for i := 0; i < (levelSize+1)/2; i++ {
			left := nodes[level][2*i]
			right := nodes[level][2*i+1]
			if left == nil {
				left = defaultLevels[level]
			}
			if right == nil {
				right = defaultLevels[level]
			}
			parentHash := hashMiMCLR(left, right)
			nodes[level+1][i] = parentHash
		}
		levelSize = (levelSize + 1) / 2
	}
	return nodes
}

func MerkleProofSiblings(nodes map[int]map[int][]byte, defaultLevels [][]byte, leafIndex int) [][]byte {
	proof := make([][]byte, 0, len(defaultLevels))
	index := leafIndex
	for level := 0; level < len(defaultLevels); level++ {
		siblingIndex := index ^ 1
		sibling := nodes[level][siblingIndex]
		if sibling == nil {
			sibling = defaultLevels[level]
		}
		proof = append(proof, sibling)
		index /= 2
	}
	return proof
}

func VerifyProof(mp *MerkleProof) bool {
	hashV := mp.Leaf.Bytes()
	for _, sibling := range mp.Proof {
		if mp.Index%2 == 0 {
			hashV = hashMiMCLR(hashV, sibling)
		} else {
			hashV = hashMiMCLR(sibling, hashV)
		}
		mp.Index = mp.Index / 2
	}
	return bytes.Equal(hashV, mp.Root)
}
