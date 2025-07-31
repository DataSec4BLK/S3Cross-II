package chaincode

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/hyperledger/fabric-chaincode-go/v2/shim"
	"github.com/hyperledger/fabric-contract-api-go/v2/contractapi"
	"math/big"
	"strconv"
	"time"
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
// PP: Generator H and G for Pedersen commitment (for Borromean range proof)
// GP: Parameters for group signature (g1 g2 h h0 w for group signature, pk for ElGamal encryption)
func (s *SmartContract) InitLedger(
	ctx contractapi.TransactionContextInterface,
	ppStr, gpStr string,
) error {
	// ppStr
	ppStrJson, err := json.Marshal(ppStr)
	if err != nil {
		return fmt.Errorf("failed to marshal ppStr. %v", err)
	}
	err = ctx.GetStub().PutState("PP", ppStrJson)
	if err != nil {
		return fmt.Errorf("failed to store ppStr. %v", err)
	}

	// gpStr
	gpStrJson, err := json.Marshal(gpStr)
	if err != nil {
		return fmt.Errorf("failed to marshal gpStr. %v", err)
	}
	err = ctx.GetStub().PutState("GP", gpStrJson)
	if err != nil {
		return fmt.Errorf("failed to store gpStr. %v", err)
	}
	return nil
}

// UpdatePP update the PP
func (s *SmartContract) UpdatePP(
	ctx contractapi.TransactionContextInterface,
	ppStr string,
) error {
	_, err := base64StringToPedersenParams(&ppStr)
	if err != nil {
		return fmt.Errorf("failed to convert pp string to Pedersen parameters: %w", err)
	}
	ppStrJson, err := json.Marshal(ppStr)
	if err != nil {
		return fmt.Errorf("failed to marshal ppStr. %v", err)
	}
	err = ctx.GetStub().PutState("PP", ppStrJson)
	if err != nil {
		return fmt.Errorf("failed to store ppStrJson. %v", err)
	}
	return nil
}

// UpdateGP update the GP
func (s *SmartContract) UpdateGP(
	ctx contractapi.TransactionContextInterface,
	gpStr string,
) error {
	_, err := base64StringToGroupParams(&gpStr)
	if err != nil {
		return fmt.Errorf("failed to convert gp string to group parameters: %w", err)
	}
	gpStrJson, err := json.Marshal(gpStr)
	if err != nil {
		return fmt.Errorf("failed to marshal gpStr. %v", err)
	}
	err = ctx.GetStub().PutState("GP", gpStrJson)
	if err != nil {
		return fmt.Errorf("failed to store gpStrJson. %v", err)
	}
	return nil
}

func (s *SmartContract) CreatePseudonym(
	ctx contractapi.TransactionContextInterface,
	s3cProofStr string,
) error {
	// use static nonce for test
	nStr := "17077557196202813204801775360160812872901728681867794927808072673056060376603"
	nonce, _ := new(big.Int).SetString(nStr, 10)
	bits := 4

	// convert proof string to object
	proof, err := base64StringToS3CrossProof(&s3cProofStr)
	if err != nil {
		return fmt.Errorf("failed to convert proof string to object. %v", err)
	}

	// get the pedersen commitment parameters
	ppStrJson, err := ctx.GetStub().GetState("PP")
	if err != nil {
		return fmt.Errorf("failed to get pp string from world state. %v", err)
	}
	var ppStr string
	err = json.Unmarshal(ppStrJson, &ppStr)
	if err != nil {
		return fmt.Errorf("failed to convert ppStrJson to ppStr. %v", err)
	}
	pp, err := base64StringToPedersenParams(&ppStr)
	if err != nil {
		return fmt.Errorf("failed to convert ppStr string to pedersen parameters. %v", err)
	}

	// get the group signature parameters
	gpStrJson, err := ctx.GetStub().GetState("GP")
	if err != nil {
		return fmt.Errorf("failed to get gp string from world state. %v", err)
	}
	var gpStr string
	err = json.Unmarshal(gpStrJson, &gpStr)
	if err != nil {
		return fmt.Errorf("failed to convert gpStrJson to gpStr. %v", err)
	}
	groupParams, err := base64StringToGroupParams(&gpStr)
	if err != nil {
		return fmt.Errorf("failed to convert gpStr string to group parameters. %v", err)
	}

	// verify s3cross proof
	err = VerifyPseudonym(proof, pp, groupParams, nonce, bits)
	if err != nil {
		panic(err)
	}

	// // store the pseudonym
	c1 := bn254.G1Affine{
		X: proof.C1.X,
		Y: proof.C1.Y,
	}
	c2 := bn254.G1Affine{
		X: proof.C2.X,
		Y: proof.C2.Y,
	}
	indC1 := c1.Bytes()
	pusB64Key := base64.StdEncoding.EncodeToString(indC1[:])
	indC2 := c2.Bytes()
	b64C2Key := base64.StdEncoding.EncodeToString(indC2[:])
	psu := Pseudonym{
		PublicKey: pusB64Key,
		TimeStamp: time.Now().Unix(),
		Used:      false,
		C1:        pusB64Key,
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

// ===== Tool Structs =====

type StaticParams struct {
	StaticPP
	StaticGP
}

type StaticPP struct {
	G   []byte `json:"G"`
	H   []byte `json:"H"`
	Mod []byte `json:"mod"`
}

type StaticGP struct {
	Gamma []byte `json:"gamma"`
	Sk    []byte `json:"Sk"`

	G1 []byte `json:"g1"`
	G2 []byte `json:"g2"`
	PK []byte `json:"pk"`
	W  []byte `json:"w"`
	H_ []byte `json:"h"`
	H0 []byte `json:"h0"`
}

type S3CProofJson struct {
	BorromeanProofJson
	GroupSignatureJson
	PsuProofJson
}

type BorromeanProofJson struct {
	C  []byte   `json:"C"`
	E0 []byte   `json:"e0"`
	C_ [][]byte `json:"C_"`
	S  [][]byte `json:"s"`
}

type GroupSignatureJson struct {
	M    []byte `json:"M"`
	C1   []byte `json:"C1"`
	C2   []byte `json:"C2"`
	A1   []byte `json:"A1"`
	A_   []byte `json:"A_"`
	D    []byte `json:"d"`
	CInt []byte `json:"c"`
	SX   []byte `json:"sX"`
	SY   []byte `json:"sY"`
	SR   []byte `json:"sR"`
	SR2  []byte `json:"sR2"`
	SR3  []byte `json:"sR3"`
	SS   string `json:"sS"` // not loose of sign
}

type PsuProofJson struct {
	CP  []byte `json:"cp"`
	SYP []byte `json:"sYP"`
	SVP []byte `json:"sVP"`
	SRP []byte `json:"sRP"`
	SPP []byte `json:"sPP"`
}

// ===== Tool Functions =====
func base64StringToPedersenParams(ppStr *string) (*PedersenParams, error) {
	ppJson, _ := base64.StdEncoding.DecodeString(*ppStr)
	var tpp StaticPP
	if err := json.Unmarshal(ppJson, &tpp); err != nil {
		return nil, errors.New("Pedersen params json.Unmarshal failed: " + err.Error())
	}
	var pp PedersenParams
	pp.G = new(bn254.G1Affine)
	_, err := pp.G.SetBytes(tpp.G)
	if err != nil {
		return nil, err
	}
	pp.H = new(bn254.G1Affine)
	_, _ = pp.G.SetBytes(tpp.G)
	pp.Mod = new(big.Int).SetBytes(tpp.Mod)

	return &pp, nil
}

func base64StringToGroupParams(gpStr *string) (*Params, error) {
	gpJson, _ := base64.StdEncoding.DecodeString(*gpStr)
	var tgp StaticGP
	if err := json.Unmarshal(gpJson, &tgp); err != nil {
		return nil, errors.New("Group params json.Unmarshal failed: " + err.Error())
	}
	var gp Params
	gp.g1 = new(bn254.G1Affine)
	gp.g2 = new(bn254.G2Affine)
	gp.pk = new(bn254.G1Affine)
	gp.w = new(bn254.G2Affine)
	gp.h = new(bn254.G1Affine)
	gp.h0 = new(bn254.G1Affine)
	_, err := gp.g1.SetBytes(tgp.G1)
	if err != nil {
		return nil, err
	}
	_, _ = gp.g2.SetBytes(tgp.G2)
	_, _ = gp.pk.SetBytes(tgp.PK)
	_, _ = gp.w.SetBytes(tgp.W)
	_, _ = gp.h.SetBytes(tgp.H_)
	_, _ = gp.h0.SetBytes(tgp.H0)

	return &gp, nil
}

func base64StringToS3CrossProof(s3pStr *string) (*S3CProof, error) {
	s3pJson, _ := base64.StdEncoding.DecodeString(*s3pStr)
	var s3pJ S3CProofJson
	if err := json.Unmarshal(s3pJson, &s3pJ); err != nil {
		return nil, errors.New("Group params json.Unmarshal failed: " + err.Error())
	}
	var s3p S3CProof
	// BorromeanProof
	var bp BorromeanProof
	bp.C = new(bn254.G1Affine)
	_, err := bp.C.SetBytes(s3pJ.C)
	if err != nil {
		return nil, err
	}

	bp.e0 = new(big.Int).SetBytes(s3pJ.E0)

	C_ := make([]*bn254.G1Affine, len(s3pJ.CInt))
	for i, v := range s3pJ.C_ {
		C_[i] = new(bn254.G1Affine)
		_, _ = C_[i].SetBytes(v)
	}
	bp.C_ = C_

	s := make([]*big.Int, len(s3pJ.S))
	for i, v := range s3pJ.S {
		s[i] = new(big.Int).SetBytes(v)
	}
	bp.s = s
	s3p.BorromeanProof = &bp

	// GroupSignature
	var gs GroupSignature
	gs.M = new(bn254.G1Affine)
	gs.C1 = new(bn254.G1Affine)
	gs.C2 = new(bn254.G1Affine)
	gs.A1 = new(bn254.G1Affine)
	gs.A_ = new(bn254.G1Affine)
	gs.d = new(bn254.G1Affine)
	_, _ = gs.M.SetBytes(s3pJ.M)
	_, _ = gs.C1.SetBytes(s3pJ.C1)
	_, _ = gs.C2.SetBytes(s3pJ.C2)
	_, _ = gs.A1.SetBytes(s3pJ.A1)
	_, _ = gs.A_.SetBytes(s3pJ.A_)
	_, _ = gs.d.SetBytes(s3pJ.D)
	gs.c = new(big.Int).SetBytes(s3pJ.CInt)
	gs.sX = new(big.Int).SetBytes(s3pJ.SX)
	gs.sY = new(big.Int).SetBytes(s3pJ.SY)
	gs.sR = new(big.Int).SetBytes(s3pJ.SR)
	gs.sR2 = new(big.Int).SetBytes(s3pJ.SR2)
	gs.sR3 = new(big.Int).SetBytes(s3pJ.SR3)
	gs.sS, _ = new(big.Int).SetString(s3pJ.SS, 10)
	s3p.GroupSignature = &gs

	// PsuProof
	var psuP PsuProof
	psuP.cp = new(big.Int).SetBytes(s3pJ.CP)
	psuP.sYP = new(big.Int).SetBytes(s3pJ.SYP)
	psuP.sVP = new(big.Int).SetBytes(s3pJ.SVP)
	psuP.sRP = new(big.Int).SetBytes(s3pJ.SRP)
	psuP.sPP = new(big.Int).SetBytes(s3pJ.SPP)
	s3p.PsuProof = &psuP

	return &s3p, nil
}
