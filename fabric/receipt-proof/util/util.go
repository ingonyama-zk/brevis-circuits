package util

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"github.com/celer-network/brevis-circuits/common/proof"
	"github.com/ethereum/go-ethereum/crypto"
	"math/big"
	"strconv"
	"strings"

	bccommon "github.com/celer-network/brevis-circuits/common"
	"github.com/celer-network/brevis-circuits/fabric/receipt-proof/core"
	"github.com/celer-network/brevis-circuits/gadgets/keccak"
	"github.com/celer-network/brevis-circuits/gadgets/mpt"
	"github.com/celer-network/goutils/log"
	"github.com/consensys/gnark/frontend"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/iden3/go-iden3-crypto/keccak256"
)

type ReceiptProofData struct {
	TransactionHash string
	BlockHash       string
	BlockNumber     uint64
	BlockTime       uint64
	MPTKey          string
	MPTProofs       []string
	BlockRlp        string
	BlockFieldsNum  int
}

func GenerateReceiptMPTProof(rpcUrl, transactionHash string) (*ReceiptProofData, error) {
	ec, err := ethclient.Dial(rpcUrl)
	if err != nil {
		log.Errorf("Failed to dial eth client: %s, %s\n", rpcUrl, err.Error())
		return nil, err
	}

	receipt, err := ec.TransactionReceipt(context.Background(), common.HexToHash(transactionHash))
	if err != nil {
		log.Errorf("Failed to retrieve transaction receipt: %+v\n", err.Error())
		return nil, err
	}

	header, err := ec.HeaderByNumber(context.Background(), receipt.BlockNumber)
	if err != nil {
		log.Errorf("Failed to retrieve block header: %+v\n", err.Error())
		return nil, err
	}

	blockRlp, err := rlp.EncodeToBytes(header)
	if err != nil {
		log.Errorf("Failed to encode block header info: %+v\n", err.Error())
		return nil, err
	}

	var decodedRlpBytes [][]byte
	err = rlp.Decode(bytes.NewReader(blockRlp), &decodedRlpBytes)
	if err != nil {
		log.Errorf("Failed to decode block header: %+v\n", err.Error())
		return nil, err
	}
	headerRlpFieldNumber := len(decodedRlpBytes)

	bk, err := ec.BlockByNumber(context.Background(), receipt.BlockNumber) // 21 transactions, with ext nodes
	if err != nil {
		log.Errorf("Failed to retrieve transaction receipt: %s\n", err.Error())
		return nil, err
	}

	var receipts types.Receipts
	for _, tx := range bk.Transactions() {
		rec, err := ec.TransactionReceipt(context.Background(), tx.Hash())
		if err != nil {
			log.Errorf("Failed to retrieve transaction %s receipt: %s\n", hexutil.Encode(tx.Hash().Bytes()), err.Error())
			return nil, err
		}
		receipts = append(receipts, rec)
	}

	receiptMPTProof, keyIndex, _, err := bccommon.GetReceiptProof(bk, receipts, int(receipt.TransactionIndex))

	if err != nil {
		log.Errorf("Cannot get transaction mpt proof: %+v\n", err.Error())
		return nil, err
	}

	var receiptMPTProofInHex []string
	for i := range receiptMPTProof {
		receiptMPTProofInHex = append(receiptMPTProofInHex, hexutil.Encode(receiptMPTProof[i]))
	}

	return &ReceiptProofData{
		TransactionHash: transactionHash,
		BlockHash:       bk.Hash().String(),
		BlockNumber:     bk.NumberU64(),
		BlockTime:       bk.Time(),
		MPTKey:          hex.EncodeToString(keyIndex),
		MPTProofs:       receiptMPTProofInHex,
		BlockRlp:        hexutil.Encode(blockRlp),
		BlockFieldsNum:  headerRlpFieldNumber,
	}, nil
}

type PublicInputs struct {
	LeafHash    []byte
	BlockHash   []byte
	BlockNumber uint64
	BlockTime   uint64
}

func GenerateReceiptCircuitProofWitness(rpcUrl, transactionHash string) (*core.ReceiptProofCircuit, *PublicInputs, error) {

	receiptProofData, err := GenerateReceiptMPTProof(rpcUrl, transactionHash)

	if err != nil {
		log.Errorf("Failed to generate receipt circuit witness %s: %s\n", transactionHash, err.Error())
		return nil, nil, err
	}

	depth := len(receiptProofData.MPTProofs)

	if depth < 2 {
		log.Errorf("Failed to generate receipt circuit witness %s (Wrong mpt proofs) : %v\n", transactionHash, receiptProofData.MPTProofs)
		return nil, nil, err
	}

	mptProof0Bytes, err := hexutil.Decode(receiptProofData.MPTProofs[0])

	if err != nil {
		log.Errorf("Failed to decode mpt proof0 %s: %s", transactionHash, err.Error())
		return nil, nil, err
	}

	rootHashHexString := strings.ReplaceAll(hexutil.Encode(keccak256.Hash(mptProof0Bytes)), "0x", "")

	var rootHash [64]frontend.Variable
	for i := 0; i < 64; i++ {
		intValue, _ := strconv.ParseInt(string(rootHashHexString[i]), 16, 64)
		rootHash[i] = intValue
	}
	var keyFragmentStarts [core.ReceiptMPTProofMaxDepth]frontend.Variable
	for i := 0; i < core.ReceiptMPTProofMaxDepth; i++ {
		keyFragmentStarts[i] = i
		if i > depth-1 {
			keyFragmentStarts[i] = 6
		}
	}

	mptKey := receiptProofData.MPTKey

	/// Special case for index 0 transaction. 8 is the only used nibble
	if mptKey == "80" {
		mptKey = "8"
	}

	keyHexLen := len(mptKey)

	var keyRlpHex [core.ReceiptMPTProofKeyMaxLength]frontend.Variable
	for i := 0; i < core.ReceiptMPTProofKeyMaxLength; i++ {
		if i < keyHexLen {
			intValue, _ := strconv.ParseInt(string(receiptProofData.MPTKey[i]), 16, 64)
			keyRlpHex[i] = intValue
		} else {
			keyRlpHex[i] = 0
		}
	}

	leafBytes, err := hexutil.Decode(receiptProofData.MPTProofs[len(receiptProofData.MPTProofs)-1])

	if err != nil {
		log.Errorf("Failed to decode mpt leaf %s: %s", transactionHash, err.Error())
		return nil, nil, err
	}

	var leafDecodedValue [][]byte
	err = rlp.Decode(bytes.NewReader(leafBytes), &leafDecodedValue)

	if err != nil {
		log.Errorf("Failed to rlp-decode mpt leaf %s: %s", transactionHash, err.Error())
		return nil, nil, err
	}

	var publicInputs PublicInputs

	leafHashHexString := hexutil.Encode(keccak256.Hash(leafBytes))
	leafHashBytes := hexutil.MustDecode(leafHashHexString)
	var leafHashFV [2]frontend.Variable
	leafHashFV[0] = leafHashBytes[0:16]
	leafHashFV[1] = leafHashBytes[16:32]

	var nodeRlp [core.ReceiptMPTProofMaxDepth - 1][mpt.BranchNodeMaxBlockSize]frontend.Variable
	var nodeRlpRoundIndexes [core.ReceiptMPTProofMaxDepth - 1]frontend.Variable
	var nodePathPrefixLength [core.ReceiptMPTProofMaxDepth - 1]frontend.Variable
	var nodeTypes [core.ReceiptMPTProofMaxDepth - 1]frontend.Variable

	for i := 0; i < core.ReceiptMPTProofMaxDepth-1; i++ {
		if i < depth-1 {
			// Feed actual data
			rlpHexString := receiptProofData.MPTProofs[i]
			bytes, _ := hexutil.Decode(rlpHexString)
			paddedBytes := keccak.Pad101Bytes(bytes)
			var rlp [mpt.BranchNodeMaxBlockSize]frontend.Variable
			for i, b := range paddedBytes {
				n1 := b >> 4
				n2 := b & 0x0F
				rlp[i*2] = n1
				rlp[i*2+1] = n2
			}

			for j := len(paddedBytes) * 2; j < 272*4; j++ {
				rlp[j] = 0
			}

			nodeRlp[i] = rlp

			nodeRlpRoundIndexes[i] = keccak.GetKeccakRoundIndex(len(rlpHexString) - 2)

			nodeType, pathPrefixLength := GetRlpPathPrefixLength(rlpHexString)
			nodePathPrefixLength[i] = pathPrefixLength
			nodeTypes[i] = nodeType
		} else {
			// Add placeholder data
			var empty [1088]frontend.Variable
			for j := 0; j < 1088; j++ {
				empty[j] = 0
			}
			nodeRlp[i] = empty
			nodeRlpRoundIndexes[i] = 0
			nodePathPrefixLength[i] = 0
			nodeTypes[i] = 0
		}
	}

	blockHashBytes, _ := hexutil.Decode(receiptProofData.BlockHash)
	var blockHashFV [2]frontend.Variable
	blockHashFV[0] = blockHashBytes[0:16]
	blockHashFV[1] = blockHashBytes[16:32]

	blockRlpHex := receiptProofData.BlockRlp
	rlpBytes, _ := hexutil.Decode(blockRlpHex)
	blockRoundIndex := keccak.GetRoundIndex(len(rlpBytes) * 8)
	paddedRlpBytes := keccak.Pad101Bytes(rlpBytes)

	var blockHashRlpFV [mpt.EthBlockHeadMaxBlockHexSize]frontend.Variable
	for i, b := range paddedRlpBytes {
		blockHashRlpFV[i*2] = b >> 4
		blockHashRlpFV[i*2+1] = b & 0x0F
	}

	for i := len(paddedRlpBytes) * 2; i < mpt.EthBlockHeadMaxBlockHexSize; i++ {
		blockHashRlpFV[i] = 0
	}

	publicInputs.LeafHash = leafHashBytes
	publicInputs.BlockHash = blockHashBytes
	publicInputs.BlockNumber = receiptProofData.BlockNumber
	publicInputs.BlockTime = receiptProofData.BlockTime

	return &core.ReceiptProofCircuit{
		LeafHash:             leafHashFV,
		BlockHash:            blockHashFV,
		BlockNumber:          receiptProofData.BlockNumber,
		BlockTime:            receiptProofData.BlockTime,
		Key:                  keyRlpHex,
		KeyLength:            keyHexLen,
		RootHash:             rootHash,
		KeyFragmentStarts:    keyFragmentStarts,
		NodeRlp:              nodeRlp,
		NodePathPrefixLength: nodePathPrefixLength,
		NodeTypes:            nodeTypes,
		NodeRlpRoundIndexes:  nodeRlpRoundIndexes,
		Depth:                depth,

		BlockHashRlp:    blockHashRlpFV,
		BlockFieldsNum:  receiptProofData.BlockFieldsNum,
		BlockRoundIndex: blockRoundIndex,
	}, &publicInputs, nil
}

func GetRlpPathPrefixLength(nodeRlp string) (nodeType int, pathPrefixLength int) {
	input, err := hexutil.Decode(nodeRlp)

	if err != nil {
		log.Error("Failed to decode node rlp", nodeRlp, err.Error())
	}

	var decodeValue [][]byte
	err = rlp.Decode(bytes.NewReader(input), &decodeValue)

	if err != nil {
		log.Error("Failed to decode", err)
	}

	if len(decodeValue) == 17 {
		nodeType = 0
		pathPrefixLength = 0
		return
	} else if len(decodeValue) == 2 {
		nodeType = 1
		if decodeValue[0][0] == 0 {
			pathPrefixLength = 2
		} else {
			pathPrefixLength = 1
		}
		return
	}

	log.Error("Failed to decide node type", nodeRlp, decodeValue)

	nodeType = 0
	pathPrefixLength = 0
	return
}

type ReceiptSingleNumSumCircuitPublicInputs struct {
	SmtRoot uint64
	Volume  uint64
	From    string
}

func GenerateReceiptSingleNumSumCircuitProofWitness(rpcUrl, smtRoot, txHash, contractAddr, fromAddr, topic string, vol uint64) (*core.SingleNumSumCircuit, *ReceiptSingleNumSumCircuitPublicInputs, error) {
	ec, err := ethclient.Dial(rpcUrl)
	if err != nil {
		log.Fatalln(err)
	}

	receipt, err := ec.TransactionReceipt(context.Background(), bccommon.Hex2Hash(txHash))
	if err != nil {
		log.Fatalln(err)
	}

	raw, err := proof.GetReceiptRaw(receipt)
	if err != nil {
		log.Fatalln(err)
	}

	// only process new type
	if raw[0] != 2 {
		log.Fatalln()
	}

	bk, err := ec.BlockByNumber(context.Background(), receipt.BlockNumber) // 21 transactions, with ext nodes
	if err != nil {
		log.Fatalln(err)
	}

	var receipts types.Receipts
	for _, tx := range bk.Transactions() {
		rec, err := ec.TransactionReceipt(context.Background(), tx.Hash())
		if err != nil {
			log.Fatalln(err)
		}
		receipts = append(receipts, rec)
	}
	receiptMPTProof, _, _, err := proof.GetReceiptProof(bk, receipts, int(receipt.TransactionIndex))

	var receiptRlpHexLen frontend.Variable
	var receiptRlp [784]frontend.Variable
	var receiptLeafValueRlp [800]frontend.Variable

	copy(receiptRlp[:], GetHexArray(fmt.Sprintf("%x", raw[1:]), 784))
	copy(receiptLeafValueRlp[:], GetHexArray(fmt.Sprintf("%x", receiptMPTProof[len(receiptMPTProof)-1]), 800))
	receiptRlpHexLen = 784

	smtRootBytes, _ := hexutil.Decode(smtRoot)

	leafValue := receiptMPTProof[len(receiptMPTProof)-1]
	leafHash := crypto.Keccak256(receiptMPTProof[len(receiptMPTProof)-1])

	log.Infof("leafValue: %x", leafValue)
	log.Infof("leafHash: %x", leafHash)

	var leafHashPiece [2]frontend.Variable
	leafHashPiece[0] = leafHash[0:16]
	leafHashPiece[1] = leafHash[16:32]

	var leafValueHex [800]frontend.Variable
	copy(leafValueHex[:], GetHexArray(fmt.Sprintf("%x", leafValue), 800))

	paddedBytes := keccak.Pad101Bytes(leafValue)

	var paddedLeafRlpHex [272 * 3]frontend.Variable
	for i, b := range paddedBytes {
		n1 := b >> 4
		n2 := b & 0x0F

		paddedLeafRlpHex[i*2] = n1
		paddedLeafRlpHex[i*2+1] = n2
	}

	for i := len(paddedBytes) * 2; i < 272*3; i++ {
		paddedLeafRlpHex[i] = 0
	}

	// mpt data
	oldWitness, _, err := GenerateReceiptCircuitProofWitness(rpcUrl, txHash)

	newPublicInputs := &ReceiptSingleNumSumCircuitPublicInputs{
		Volume:  vol,
		SmtRoot: 1,
		From:    fromAddr,
	}

	witness := &core.SingleNumSumCircuit{
		SmtRoot: smtRootBytes,
		//
		LeafHash: leafHashPiece,

		Key:                  oldWitness.Key,
		KeyLength:            oldWitness.KeyLength,
		RootHash:             oldWitness.RootHash,
		KeyFragmentStarts:    oldWitness.KeyFragmentStarts,
		NodeRlp:              oldWitness.NodeRlp,
		NodePathPrefixLength: oldWitness.NodePathPrefixLength,
		NodeTypes:            oldWitness.NodeTypes,
		NodeRlpRoundIndexes:  oldWitness.NodeRlpRoundIndexes,
		Depth:                oldWitness.Depth,

		BlockHashRlp:    oldWitness.BlockHashRlp,
		BlockFieldsNum:  oldWitness.BlockFieldsNum,
		BlockRoundIndex: oldWitness.BlockRoundIndex,

		LeafValue:       leafValueHex,
		LeafValuePadded: paddedLeafRlpHex,

		Volume:           vol,
		From:             new(big.Int).SetBytes(bccommon.Hex2Bytes(fromAddr)),
		ReceiptRlpHexLen: receiptRlpHexLen,
		ReceiptRlp:       receiptRlp,

		LogIndex: 0,
	}

	return witness, newPublicInputs, nil
}

func GetHexArray(hexStr string, maxLen int) (res []frontend.Variable) {
	for i := 0; i < maxLen; i++ {
		if i < len(hexStr) {
			intValue, _ := strconv.ParseInt(string(hexStr[i]), 16, 64)
			res = append(res, intValue)
		} else {
			res = append(res, 0)
		}
	}
	return
}
