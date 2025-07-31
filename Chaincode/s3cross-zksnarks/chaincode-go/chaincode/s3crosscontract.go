package chaincode

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/std/rangecheck"
	"github.com/hyperledger/fabric-chaincode-go/v2/shim"
	"github.com/hyperledger/fabric-contract-api-go/v2/contractapi"
	"strconv"
	"time"

	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	twistededwards2 "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/frontend"
	twistededwards1 "github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
)

type SmartContract struct {
	contractapi.Contract
}

type Pseudonym struct {
	PublicKey string `json:"publickey"`
	TimeStamp int64  `json:"timestamp"`
	Used      bool   `json:"used"`

	// ElGamal Encryption
	C1 string `json:"c1"`
	C2 string `json:"c2"`
}

// PagedPseudonymResult For GetAllPseudonyms
type PagedPseudonymResult struct {
	Records  []*Pseudonym `json:"records"`
	Bookmark string       `json:"bookmark"`
	More     bool         `json:"more"`
}

// InitLedger Init some public parameters
// IPK: Issuer public key (for Schnorr signature)
// SPK: Supervisor public key (for ElGamal encryption)
// Root: Merkle Root
// GVK: Circuit verification key
func (s *SmartContract) InitLedger(
	ctx contractapi.TransactionContextInterface,
	ipkStr, spkStr, rootStr, gvkStr string,
) error {
	// ipkStr
	ipkStrJson, err := json.Marshal(ipkStr)
	if err != nil {
		return fmt.Errorf("failed to marshal ipkStr. %v", err)
	}
	err = ctx.GetStub().PutState("IPK", ipkStrJson)
	if err != nil {
		return fmt.Errorf("failed to store ipkStr. %v", err)
	}

	// spkStr
	spkStrJson, err := json.Marshal(spkStr)
	if err != nil {
		return fmt.Errorf("failed to marshal spkStr. %v", err)
	}
	err = ctx.GetStub().PutState("SPK", spkStrJson)
	if err != nil {
		return fmt.Errorf("failed to store spkStr. %v", err)
	}

	// rootStr
	rootStrJson, err := json.Marshal(rootStr)
	if err != nil {
		return fmt.Errorf("failed to marshal rootStr. %v", err)
	}
	err = ctx.GetStub().PutState("ROOT", rootStrJson)
	if err != nil {
		return fmt.Errorf("failed to store rootStr. %v", err)
	}

	gvkStringJson, err := json.Marshal(gvkStr)
	if err != nil {
		return fmt.Errorf("failed to marshal gvkStr. %v", err)
	}
	err = ctx.GetStub().PutState("GVK", gvkStringJson)
	if err != nil {
		return fmt.Errorf("failed to store gvkStr. %v", err)
	}
	return nil
}

// UpdateGVK update the gvk
func (s *SmartContract) UpdateGVK(
	ctx contractapi.TransactionContextInterface,
	gvkString string,
) error {
	_, err := base64StringToVerifyingKey(&gvkString)
	if err != nil {
		return fmt.Errorf("failed to convert gvk string to verifying key: %w", err)
	}
	gvkStringJson, err := json.Marshal(gvkString)
	if err != nil {
		return fmt.Errorf("failed to marshal gvkString. %v", err)
	}
	err = ctx.GetStub().PutState("GVK", gvkStringJson)
	if err != nil {
		return fmt.Errorf("failed to store gvkStringJson. %v", err)
	}
	return nil
}

func (s *SmartContract) CreatePseudonym(
	ctx contractapi.TransactionContextInterface,
	proofStr, pubWitStr string,
) error {
	// convert string to object
	proof, err := base64StringToProof(&proofStr)
	if err != nil {
		return fmt.Errorf("failed to convert proof string to verifyingKey. %v", err)
	}

	publicWitness, err := base64StringToWitness(&pubWitStr)
	if err != nil {
		return fmt.Errorf("failed to convert publicWitness string to witness. %v", err)
	}

	// verify circuit proof
	gvkStringJson, err := ctx.GetStub().GetState("GVK")
	if err != nil {
		return fmt.Errorf("failed to get gvk string from world state. %v", err)
	}
	var gvkString string
	err = json.Unmarshal(gvkStringJson, &gvkString)
	if err != nil {
		return fmt.Errorf("failed to convert gvkStringJson to gvk string. %v", err)
	}
	gvk, err := base64StringToVerifyingKey(&gvkString)
	if err != nil {
		return fmt.Errorf("failed to convert gvk string to verifying key. %v", err)
	}
	err = groth16.Verify(proof, *gvk, publicWitness)
	if err != nil {
		return fmt.Errorf("failed to verify circuit proof. %v", err)
	}

	// omit the check of nonce
	values := publicWitness.Vector().(fr.Vector)
	// // check the consistency of isk, spk and root
	root := values[0].Bytes()
	//fmt.Println("root from publicWitness", root)
	ipk := twistededwards.PointAffine{
		X: values[3],
		Y: values[4],
	}
	spk := twistededwards.PointAffine{
		X: values[8],
		Y: values[9],
	}

	indIpk := ipk.Bytes()
	ipkStr := base64.StdEncoding.EncodeToString(indIpk[:])
	ipkStringJson, err := ctx.GetStub().GetState("IPK")
	if err != nil {
		return fmt.Errorf("failed to get ipk string from world state. %v", err)
	}
	var ipkString string
	err = json.Unmarshal(ipkStringJson, &ipkString)
	if err != nil {
		return fmt.Errorf("failed to convert ipkStringJson to gsk string. %v", err)
	}
	if ipkStr != ipkString {
		return fmt.Errorf("ipk does not match")
	}

	indSpk := spk.Bytes()
	spkStr := base64.StdEncoding.EncodeToString(indSpk[:])
	spkStringJson, err := ctx.GetStub().GetState("SPK")
	if err != nil {
		return fmt.Errorf("failed to get spk string from world state. %v", err)
	}
	var spkString string
	err = json.Unmarshal(spkStringJson, &spkString)
	if err != nil {
		return fmt.Errorf("failed to convert spkStringJson to spk string. %v", err)
	}
	if spkStr != spkString {
		return fmt.Errorf("spk does not match")
	}
	
	rootStr := base64.StdEncoding.EncodeToString(root[:])
	rootStringJson, err := ctx.GetStub().GetState("ROOT")
	if err != nil {
		return fmt.Errorf("failed to get root string from world state. %v", err)
	}
	var rootString string
	err = json.Unmarshal(rootStringJson, &rootString)
	if err != nil {
		return fmt.Errorf("failed to convert rootStringJson to root string. %v", err)
	}
	if rootStr != rootString {
		return fmt.Errorf("root does not match")
	}

	// // store the pseudonym
	pusPubKey := twistededwards.PointAffine{
		X: values[5],
		Y: values[6],
	}
	c1 := twistededwards.PointAffine{
		X: values[10],
		Y: values[11],
	}
	c2 := twistededwards.PointAffine{
		X: values[12],
		Y: values[13],
	}
	indPPK := pusPubKey.Bytes()
	pusB64Key := base64.StdEncoding.EncodeToString(indPPK[:])
	indC1 := c1.Bytes()
	b64C1Key := base64.StdEncoding.EncodeToString(indC1[:])
	indC2 := c2.Bytes()
	b64C2Key := base64.StdEncoding.EncodeToString(indC2[:])
	psu := Pseudonym{
		PublicKey: pusB64Key,
		TimeStamp: time.Now().Unix(),
		Used:      false,
		C1:        b64C1Key,
		C2:        b64C2Key,
	}

	psuJson, err := json.Marshal(psu)
	if err != nil {
		return fmt.Errorf("failed to marshal psu. %v", err)
	}
	err = ctx.GetStub().PutState("PSU_"+pusB64Key, psuJson)
	if err != nil {
		return fmt.Errorf("failed to store pseudonym. %v", err)
	}
	return nil
}

// GetAllPseudonymsPaged query given number of Pseudonyms
// pageSizeStr: pseudonym number
// bookmark: First time set as "", next use the "Bookmark" context from the last query
func (s *SmartContract) GetAllPseudonymsPaged(
	ctx contractapi.TransactionContextInterface,
	pageSizeStr string,
	bookmark string,
) (*PagedPseudonymResult, error) {
	pageSize, err := strconv.Atoi(pageSizeStr)
	if err != nil || pageSize <= 0 {
		return nil, fmt.Errorf("invalid page size: %v", err)
	}

	iter, respMeta, err := ctx.GetStub().GetStateByRangeWithPagination(
		"PSU_", "PSU_~", int32(pageSize), bookmark)
	if err != nil {
		return nil, err
	}
	defer func(iter shim.StateQueryIteratorInterface) {
		err = iter.Close()
		if err != nil {
			panic(err)
		}
	}(iter)

	var psus []*Pseudonym
	for iter.HasNext() {
		queryResponse, err := iter.Next()
		if err != nil {
			return nil, err
		}
		var asset Pseudonym
		err = json.Unmarshal(queryResponse.Value, &asset)
		if err != nil {
			return nil, err
		}
		psus = append(psus, &asset)
	}

	more := false
	if len(psus) == pageSize && respMeta.Bookmark != "" {
		more = true
	}

	return &PagedPseudonymResult{
		Records:  psus,
		Bookmark: respMeta.Bookmark,
		More:     more,
	}, nil
}

// QueryPseudonymByPBK query the condition of a pseudonym by the public key string
func (s *SmartContract) QueryPseudonymByPBK(
	ctx contractapi.TransactionContextInterface,
	pbk string,
) (*Pseudonym, error) {
	key := "PSU_" + pbk
	data, err := ctx.GetStub().GetState(key)
	if err != nil {
		return nil, fmt.Errorf("failed to query state: %v", err)
	}
	if data == nil {
		return nil, fmt.Errorf("no pseudonym found for public key: %s", pbk)
	}
	var psu Pseudonym
	if err := json.Unmarshal(data, &psu); err != nil {
		return nil, fmt.Errorf("failed to parse psu data: %v", err)
	}
	return &psu, nil
}

func (s *SmartContract) IsPseudonymValid(
	ctx contractapi.TransactionContextInterface,
	pbk string,
) (bool, error) {
	key := "PSU_" + pbk
	data, err := ctx.GetStub().GetState(key)
	if err != nil {
		return false, fmt.Errorf("failed to query state: %v", err)
	}
	if data == nil {
		return false, fmt.Errorf("no pseudonym found for public key: %s", pbk)
	}
	var psu Pseudonym
	if err := json.Unmarshal(data, &psu); err != nil {
		return false, fmt.Errorf("failed to parse psu data: %v", err)
	}
	now := time.Now().Unix()
	const ExpirySeconds = 7200
	if psu.Used == false && now-psu.TimeStamp < ExpirySeconds {
		return true, nil // 有效
	}
	return false, nil // 已失效
}

// 改变 Pseudonym 的 used 状态

// ---------- Ciruit ----------

type Circuit struct {
	// ordered Merkle tree proof
	Root frontend.Variable `gnark:",public"`
	// // left path
	ProofElements1 []frontend.Variable // private
	ProofIndex1    frontend.Variable   // private
	Leaf1          frontend.Variable   `gnark:",public"` // mimc hash of the public key
	// // right node
	Leaf2 frontend.Variable `gnark:",public"` // mimc hash of the public key

	// schnorr proof
	IPkX frontend.Variable `gnark:",public"`
	IPkY frontend.Variable `gnark:",public"`

	Sig frontend.Variable // private
	RX  frontend.Variable // private
	RY  frontend.Variable // private

	MessageX frontend.Variable // private
	MessageY frontend.Variable // private

	// psu proof
	PPkX  frontend.Variable `gnark:",public"`
	PPkY  frontend.Variable `gnark:",public"`
	Nonce frontend.Variable `gnark:",public"` // current nonce for SR, should mod curve.Order
	//MaxI  frontend.Variable `gnark:",public"` // max psu number
	USk frontend.Variable // private
	I   frontend.Variable // private

	// elgamal proof
	SPkX frontend.Variable `gnark:",public"`
	SPkY frontend.Variable `gnark:",public"`
	C1X  frontend.Variable `gnark:",public"`
	C1Y  frontend.Variable `gnark:",public"`
	C2X  frontend.Variable `gnark:",public"`
	C2Y  frontend.Variable `gnark:",public"`
	R    frontend.Variable // private
}

func (circuit *Circuit) Define(api frontend.API) error {
	numBits := 4 // max psu number is 2^numBits - 1

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
	//isEqual := api.IsZero(circuit.I)
	//api.AssertIsEqual(isEqual, 0)
	// // I <= MaxI
	//api.AssertIsLessOrEqual(circuit.I, circuit.MaxI)
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

func base64StringToVerifyingKey(encoded *string) (*groth16.VerifyingKey, error) {
	data, err := base64.StdEncoding.DecodeString(*encoded)
	if err != nil {
		return nil, err
	}
	buf := bytes.NewBuffer(data)
	vk := groth16.NewVerifyingKey(ecc.BN254)
	_, err = vk.ReadFrom(buf)
	return &vk, err
}

func base64StringToProof(encoded *string) (groth16.Proof, error) {
	data, err := base64.StdEncoding.DecodeString(*encoded)
	if err != nil {
		return nil, err
	}
	buf := bytes.NewBuffer(data)
	proof := groth16.NewProof(ecc.BN254)
	_, err = proof.ReadFrom(buf)
	if err != nil {
		return nil, err
	}
	return proof, nil
}

func base64StringToWitness(str *string) (witness.Witness, error) {
	data, err := base64.StdEncoding.DecodeString(*str)
	if err != nil {
		return nil, err
	}
	buf := bytes.NewBuffer(data)
	wit, err := frontend.NewWitness(nil, ecc.BN254.ScalarField())
	if err != nil {
		return nil, err
	}
	_, err = wit.ReadFrom(buf)
	return wit, err
}
