package test

import (
	"github.com/celer-network/brevis-circuits/fabric/receipt-proof/core"
	"github.com/celer-network/brevis-circuits/fabric/receipt-proof/util"
	"testing"

	"github.com/celer-network/goutils/log"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"
)

func TestReceiptSingleNumSumCircuit(t *testing.T) {
	assert := test.NewAssert(t)
	contractAddr := "0x87c644c9b0bd2c14f0952aed75e242237e7e3510"
	topic := "0x7ae1420774474a63c6da37d66e70351e80273a7f6a538d8c05d21d727571dded"
	fromAddr := "0x58b529F9084D7eAA598EB3477Fe36064C5B7bbC1"
	txHash := "0x78a175f07d49f3d57e35ec40eca2b7e160dc9cf04fa8103812ede1ca128e7149"
	smtRoot := "0x0000000000000000000000000000000000000000000000000000000000000001"
	vol := uint64(14)
	rpc := "https://goerli.blockpi.network/v1/rpc/public"

	witness, _, err := util.GenerateReceiptSingleNumSumCircuitProofWitness(rpc, smtRoot, txHash, contractAddr, fromAddr, topic, vol)
	if err != nil {
		log.Fatalln(err)
	}

	err = test.IsSolved(&core.SingleNumSumCircuit{}, witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}
