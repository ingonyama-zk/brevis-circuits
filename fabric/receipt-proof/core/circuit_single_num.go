package core

import (
	espcore "github.com/celer-network/brevis-circuits/fabric/eth-storage-proof/core"
	"github.com/celer-network/brevis-circuits/gadgets/keccak"
	"github.com/celer-network/brevis-circuits/gadgets/mpt"
	"github.com/celer-network/brevis-circuits/gadgets/rlp"
	"github.com/celer-network/goutils/log"
	"github.com/consensys/gnark/frontend"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/common/math"
)

type SingleNumSumCircuit struct {
	SmtRoot frontend.Variable `gnark:",public"`
	//// decode receipt logs
	Volume frontend.Variable `gnark:",public"`
	From   frontend.Variable `gnark:",public"`
	// use ContractAddr and Topic to constraint the log is the correct event.
	LogIndex frontend.Variable
	// mpt
	Key                  [ReceiptMPTProofKeyMaxLength]frontend.Variable
	KeyLength            frontend.Variable
	RootHash             [ReceiptMPTRootHashLength]frontend.Variable
	KeyFragmentStarts    [ReceiptMPTProofMaxDepth]frontend.Variable
	NodeRlp              [ReceiptMPTProofMaxDepth - 1][272 * 4]frontend.Variable
	NodeRlpRoundIndexes  [ReceiptMPTProofMaxDepth - 1]frontend.Variable
	NodePathPrefixLength [ReceiptMPTProofMaxDepth - 1]frontend.Variable
	NodeTypes            [ReceiptMPTProofMaxDepth - 1]frontend.Variable
	Depth                frontend.Variable

	BlockHashRlp    [mpt.EthBlockHeadMaxBlockHexSize]frontend.Variable
	BlockFieldsNum  frontend.Variable // block heard fields number
	BlockRoundIndex frontend.Variable

	// connect
	LeafHash        [2]frontend.Variable   //`gnark:",public"`
	LeafValue       [800]frontend.Variable //`gnark:",public"` // keccak is leaf hash
	LeafValuePadded [272 * 3]frontend.Variable

	ReceiptRlpHexLen frontend.Variable
	ReceiptRlp       [784]frontend.Variable // without 02 prefix, not receipt raw
}

func (c *SingleNumSumCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(c.LogIndex, 0) // for uniswap, it will be other index, may not 0
	//// check leafValue and leafHash
	// padded := keccak.Pad101()
	// padded := keccak.Pad101Bits(api, 4, 800, 800, c.LeafValue[:], 800)

	nibbles := keccak.NibblesToU64Array(api, c.LeafValuePadded[:])
	roundIndex := 800 / 272
	leafHashResult := *rlp.Keccak256AsNibbles(api, 4, nibbles, roundIndex)

	//log.Info("LeafHashResult", leafHashResult.Output)
	//log.Info("Leaf Hash C", c.LeafHash)

	// c59b9d0e4d42a451e1c673bbdd24b84e
	// eb5947b165409c781b5cb297e73cedf5

	var leafHashResult0, leafHashResult1 frontend.Variable = 0, 0

	for i := 0; i < 32; i++ {
		leafHashResult0 = api.Add(leafHashResult0, api.Mul(leafHashResult.Output[31-i], math.BigPow(16, int64(i))))
	}

	for i := 0; i < 32; i++ {
		leafHashResult1 = api.Add(leafHashResult1, api.Mul(leafHashResult.Output[63-i], math.BigPow(16, int64(i))))
	}

	api.AssertIsEqual(c.LeafHash[0], leafHashResult0)
	api.AssertIsEqual(c.LeafHash[1], leafHashResult1)

	////// decode receipt Raw

	// mpt
	var nodeRlp [][]frontend.Variable
	for i := 0; i < len(c.NodeRlp); i++ {
		nodeRlp = append(nodeRlp, c.NodeRlp[i][:])
	}

	result := mpt.CheckMPTInclusionNoBranchTermination(
		api,
		ReceiptMPTProofMaxDepth,
		ReceiptMPTProofKeyMaxLength,
		c.Key[:],
		c.KeyLength,
		c.RootHash,
		c.KeyFragmentStarts[:],
		c.LeafHash,
		nodeRlp,
		c.NodeRlpRoundIndexes[:],
		c.NodePathPrefixLength[:],
		c.NodeTypes[:],
		c.Depth,
	)

	api.AssertIsEqual(result.Output, 1)

	rlpBlockHashResult := mpt.CheckEthBlockHash(api, c.BlockHashRlp, c.BlockFieldsNum, c.BlockRoundIndex)

	for i := 0; i < 64; i++ {
		api.AssertIsEqual(c.RootHash[i], rlpBlockHashResult.ReceiptsRoot[i])
	}

	arrayCheckLeafRlp := &rlp.ArrayCheck{
		MaxHexLen:            800,
		MaxFields:            2,
		ArrayPrefixMaxHexLen: 6,
		FieldMinHexLen:       []int{0, 0},
		FieldMaxHexLen:       []int{2, 786},
	}
	out, _, _, leafs := arrayCheckLeafRlp.RlpNestArrayCheck(api, c.LeafValue[:])
	api.AssertIsEqual(out, 1)
	//log.Infof("leafs len:%d", len(leafs))

	api.AssertIsEqual(0, leafs[1][0])
	api.AssertIsEqual(2, leafs[1][1])

	for i, v := range c.ReceiptRlp {
		// TODO, check left 0
		api.AssertIsEqual(v, leafs[1][i+2])
	}

	arrayCheckParamsTxRlp0 := &rlp.ArrayCheck{
		MaxHexLen:            784,
		MaxFields:            4,
		ArrayPrefixMaxHexLen: 6,
		FieldMinHexLen:       []int{0, 0, 0, 0},
		FieldMaxHexLen:       []int{2, 6, 512, 246},
	}

	out, txRlpHexLen, fieldsLen, fields := arrayCheckParamsTxRlp0.RlpNestArrayCheck(api, c.ReceiptRlp[:])
	api.AssertIsEqual(out, 1)
	api.AssertIsEqual(txRlpHexLen, 784)
	api.AssertIsEqual(len(fieldsLen), 4)

	arrayCheckParamsTxRlp0Sub := &rlp.ArrayCheck{
		MaxHexLen:            250,
		MaxFields:            1,
		ArrayPrefixMaxHexLen: 4,
		FieldMinHexLen:       []int{0},
		FieldMaxHexLen:       []int{242},
	}

	logsField := fields[3]
	out, _, _, logs := arrayCheckParamsTxRlp0Sub.RlpNestArrayCheck(api, logsField)
	api.AssertIsEqual(out, 1)

	arrayCheckParamsTxRlp0Sub2 := &rlp.ArrayCheck{
		MaxHexLen:            246,
		MaxFields:            3,
		ArrayPrefixMaxHexLen: 4,
		FieldMinHexLen:       []int{0, 0, 0},
		FieldMaxHexLen:       []int{40, 66, 128},
	}

	// use data1[0] contract and data1[2] data
	out, _, _, data1 := arrayCheckParamsTxRlp0Sub2.RlpArrayCheck(api, logs[0])
	api.AssertIsEqual(out, 1)

	// TODO add zero prefix check
	var contract, from, vol frontend.Variable
	contract = 0
	from = 0
	vol = 0

	for i := 0; i < 40; i++ {
		contract = api.Add(contract, api.Mul(data1[0][39-i], math.BigPow(16, int64(i))))
	}
	// const
	// contractAddr := new(big.Int).SetBytes(utils.Hex2Bytes("0x87c644c9b0bd2c14f0952aed75e242237e7e3510"))
	// api.AssertIsEqual(contract, contractAddr)

	for i := 0; i < 40; i++ {
		from = api.Add(from, api.Mul(data1[2][63-i], math.BigPow(16, int64(i))))
	}
	api.AssertIsEqual(from, c.From)

	for i := 0; i < 64; i++ {
		vol = api.Add(vol, api.Mul(data1[2][127-i], math.BigPow(16, int64(i))))
	}
	api.AssertIsEqual(vol, c.Volume)

	// decode topic
	arrayCheckParamsTxRlp0Sub3 := &rlp.ArrayCheck{
		MaxHexLen:            246,
		MaxFields:            3,
		ArrayPrefixMaxHexLen: 4,
		FieldMinHexLen:       []int{0, 0, 0},
		FieldMaxHexLen:       []int{40, 68, 128},
	}
	out, _, _, data2 := arrayCheckParamsTxRlp0Sub3.RlpNestArrayCheck(api, logs[0])
	api.AssertIsEqual(out, 1)

	arrayCheckParamsTxRlp0Sub4 := &rlp.ArrayCheck{
		MaxHexLen:            68,
		MaxFields:            1,
		ArrayPrefixMaxHexLen: 4,
		FieldMinHexLen:       []int{0},
		FieldMaxHexLen:       []int{64},
	}
	out, _, _, data3 := arrayCheckParamsTxRlp0Sub4.RlpArrayCheck(api, data2[1])
	api.AssertIsEqual(out, 1)
	log.Infof("%d", len(data3))

	// const
	evTopicBytes, err := hexutil.Decode("0x7ae1420774474a63c6da37d66e70351e80273a7f6a538d8c05d21d727571dded")
	if err != nil {
		return err
	}
	var evTopicPiece [2]frontend.Variable
	evTopicPiece[0] = evTopicBytes[0:16]
	evTopicPiece[1] = evTopicBytes[16:32]
	topicHash := espcore.Recompose32ByteToNibbles(api, evTopicPiece)
	topicHashEqual := rlp.ArrayEqual(api, topicHash[:], data3[0][:], 64, 64)
	api.AssertIsEqual(topicHashEqual, 1)

	api.AssertIsEqual(c.SmtRoot, 1)

	return nil
}
