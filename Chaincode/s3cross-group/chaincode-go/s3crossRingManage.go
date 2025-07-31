package main

import (
	"github.com/hyperledger/fabric-contract-api-go/v2/contractapi"
	"log"
	"s3cross-ring/chaincode-go/chaincode"
)

func main() {
	psuChaincode, err := contractapi.NewChaincode(&chaincode.SmartContract{})
	if err != nil {
		log.Panicf("Error creating psu-manage chaincode: %v", err)
	}

	if err := psuChaincode.Start(); err != nil {
		log.Panicf("Error starting psu-manage chaincode: %v", err)
	}
}
