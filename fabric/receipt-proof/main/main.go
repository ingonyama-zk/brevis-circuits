package main

import (
	"github.com/celer-network/brevis-circuits/common"
	"github.com/celer-network/brevis-circuits/fabric/receipt-proof/core"
	"github.com/celer-network/brevis-circuits/fabric/receipt-proof/util"
	"github.com/celer-network/goutils/log"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"sync"
)

func main() {
	contractAddr := "0x87c644c9b0bd2c14f0952aed75e242237e7e3510"
	topic := "0x7ae1420774474a63c6da37d66e70351e80273a7f6a538d8c05d21d727571dded"
	fromAddr := "0x58b529F9084D7eAA598EB3477Fe36064C5B7bbC1"
	txHash := "0x78a175f07d49f3d57e35ec40eca2b7e160dc9cf04fa8103812ede1ca128e7149"
	smtRoot := "0x0000000000000000000000000000000000000000000000000000000000000001"
	vol := uint64(14)
	rpc := "https://goerli.blockpi.network/v1/rpc/public"

	assignment, _, err := util.GenerateReceiptSingleNumSumCircuitProofWitness(rpc, smtRoot, txHash, contractAddr, fromAddr, topic, vol)
	if err != nil {
		log.Fatalln(err)
	}

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &core.SingleNumSumCircuit{})
	if err != nil {
		log.Errorf("Receipt failed to compile for: %s\n", err.Error())
		return
	}

	log.Info("Start to setup pk")
	var pk = groth16.NewProvingKey(ecc.BN254)
	err = common.ReadProvingKey("test_single_number_circuit.pk", pk)
	if err != nil {
		log.Warnf("Failed to read pk %s, and try create", err.Error())
		pk, _, err = groth16.Setup(ccs)
		if err != nil {
			log.Fatalln(err)
		}
		common.WriteProvingKey(pk, "test_single_number_circuit.pk")
	}

	log.Infoln("pk load done.")

	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())

	if err != nil {
		log.Errorf("Receipt failed to setup for: %s\n", err.Error())
		return
	}

	var wg sync.WaitGroup

	log.Infoln("start prove")
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err = groth16.Prove(ccs, pk, witness)
			if err != nil {
				log.Errorf("Receipt failed to prove for: %s\n", err.Error())
				return
			}
		}()
	}
	wg.Wait()

	_, err = groth16.Prove(ccs, pk, witness)
	if err != nil {
		log.Errorf("Receipt failed to prove for: %s\n", err.Error())
		return
	}

	log.Infoln("finish prove")
}
