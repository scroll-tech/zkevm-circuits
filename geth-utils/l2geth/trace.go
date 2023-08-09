package main

import (
	"fmt"
	"math/big"

	"github.com/imdario/mergo"
	"github.com/scroll-tech/go-ethereum/common"
	"github.com/scroll-tech/go-ethereum/common/hexutil"
	"github.com/scroll-tech/go-ethereum/core"
	"github.com/scroll-tech/go-ethereum/core/rawdb"
	"github.com/scroll-tech/go-ethereum/core/state"
	"github.com/scroll-tech/go-ethereum/core/types"
	"github.com/scroll-tech/go-ethereum/core/vm"
	"github.com/scroll-tech/go-ethereum/params"
)

type Block struct {
	Coinbase   common.Address `json:"coinbase"`
	Timestamp  *hexutil.Big   `json:"timestamp"`
	Number     *hexutil.Big   `json:"number"`
	Difficulty *hexutil.Big   `json:"difficulty"`
	GasLimit   *hexutil.Big   `json:"gas_limit"`
	BaseFee    *hexutil.Big   `json:"base_fee"`
}

type Account struct {
	Nonce   hexutil.Uint64              `json:"nonce"`
	Balance *hexutil.Big                `json:"balance"`
	Code    hexutil.Bytes               `json:"code"`
	Storage map[common.Hash]common.Hash `json:"storage"`
}

type Transaction struct {
	From       common.Address  `json:"from"`
	To         *common.Address `json:"to"`
	Nonce      hexutil.Uint64  `json:"nonce"`
	Value      *hexutil.Big    `json:"value"`
	GasLimit   hexutil.Uint64  `json:"gas_limit"`
	GasPrice   *hexutil.Big    `json:"gas_price"`
	GasFeeCap  *hexutil.Big    `json:"gas_fee_cap"`
	GasTipCap  *hexutil.Big    `json:"gas_tip_cap"`
	CallData   hexutil.Bytes   `json:"call_data"`
	AccessList []struct {
		Address     common.Address `json:"address"`
		StorageKeys []common.Hash  `json:"storage_keys"`
	} `json:"access_list"`
}

type TraceConfig struct {
	ChainID uint64 `json:"chain_id"`
	// HistoryHashes contains most recent 256 block hashes in history,
	// where the lastest one is at HistoryHashes[len(HistoryHashes)-1].
	HistoryHashes []*hexutil.Big             `json:"history_hashes"`
	Block         Block                      `json:"block_constants"`
	Accounts      map[common.Address]Account `json:"accounts"`
	Transactions  []Transaction              `json:"transactions"`
	LoggerConfig  *vm.LogConfig              `json:"logger_config"`
	ChainConfig   *params.ChainConfig        `json:"chain_config"`
}

func newUint64(val uint64) *uint64 { return &val }

func transferTxs(txs []Transaction) types.Transactions {
	// current we can only transfer
	t_txs := make([]*types.Transaction, 0, len(txs))
	for _, tx := range txs {
		// If gas price is specified directly, the tx is treated as legacy type.
		// if tx.GasPrice != nil {
		// 	tx.GasFeeCap = tx.GasPrice
		// 	tx.GasTipCap = tx.GasPrice
		// }

		// txAccessList := make(types.AccessList, len(tx.AccessList))
		// for i, accessList := range tx.AccessList {
		// 	txAccessList[i].Address = accessList.Address
		// 	txAccessList[i].StorageKeys = accessList.StorageKeys
		// }

		// currently we can only use l1msg tx (since we have no signature yet)
		l1msgTx := &types.L1MessageTx{
			Gas:        uint64(tx.GasLimit),
			QueueIndex: uint64(tx.Nonce),
			To:         tx.To,
			Value:      toBigInt(tx.Value),
			Data:       tx.CallData,
			Sender:     tx.From,
		}
		t_txs = append(t_txs, types.NewTx(l1msgTx))
	}

	return types.Transactions(t_txs)
}

func L2Trace(config TraceConfig) (*types.BlockTrace, error) {

	chainConfig := params.ChainConfig{
		ChainID:             new(big.Int).SetUint64(config.ChainID),
		HomesteadBlock:      big.NewInt(0),
		DAOForkBlock:        big.NewInt(0),
		DAOForkSupport:      true,
		EIP150Block:         big.NewInt(0),
		EIP150Hash:          common.Hash{},
		EIP155Block:         big.NewInt(0),
		EIP158Block:         big.NewInt(0),
		ByzantiumBlock:      big.NewInt(0),
		ConstantinopleBlock: big.NewInt(0),
		PetersburgBlock:     big.NewInt(0),
		IstanbulBlock:       big.NewInt(0),
		MuirGlacierBlock:    big.NewInt(0),
		BerlinBlock:         big.NewInt(0),
		LondonBlock:         big.NewInt(0),
	}

	if config.ChainConfig != nil {
		mergo.Merge(&chainConfig, config.ChainConfig, mergo.WithOverride)
	}

	// Debug for Shanghai
	// fmt.Printf("geth-utils: ShanghaiTime = %d\n", *chainConfig.ShanghaiTime)

	txs := transferTxs(config.Transactions)

	var txsGasLimit uint64
	blockGasLimit := toBigInt(config.Block.GasLimit).Uint64()
	for _, tx := range txs {
		txsGasLimit += tx.Gas()
	}
	if txsGasLimit > blockGasLimit {
		return nil, fmt.Errorf("txs total gas: %d Exceeds block gas limit: %d", txsGasLimit, blockGasLimit)
	}

	// For opcode PREVRANDAO
	randao := common.BigToHash(toBigInt(config.Block.Difficulty)) // TODO: fix

	blockCtx := vm.BlockContext{
		CanTransfer: core.CanTransfer,
		Transfer:    core.Transfer,
		GetHash: func(n uint64) common.Hash {
			number := config.Block.Number.ToInt().Uint64()
			if number > n && number-n <= 256 {
				index := uint64(len(config.HistoryHashes)) - number + n
				return common.BigToHash(toBigInt(config.HistoryHashes[index]))
			}
			return common.Hash{}
		},
		Coinbase:    config.Block.Coinbase,
		BlockNumber: toBigInt(config.Block.Number),
		Time:        toBigInt(config.Block.Timestamp),
		Difficulty:  toBigInt(config.Block.Difficulty),
		//		Random:      &randao,
		BaseFee:  toBigInt(config.Block.BaseFee),
		GasLimit: blockGasLimit,
	}

	//FIXME: if no history, use random hash instead?
	parent := randao
	if len(config.HistoryHashes) > 0 {
		parentI := len(config.HistoryHashes) - 1
		parent = common.BigToHash(toBigInt(config.HistoryHashes[parentI]))
	}

	header := &types.Header{
		ParentHash: parent,
		Number:     toBigInt(config.Block.Number),
		GasLimit:   toBigInt(config.Block.GasLimit).Uint64(),
		Extra:      []byte{},
		Time:       toBigInt(config.Block.Timestamp).Uint64(),
	}
	block := types.NewBlockWithHeader(header).WithBody(txs, nil)

	// Setup state db with accounts from argument
	stateDB, _ := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	for address, account := range config.Accounts {
		stateDB.SetNonce(address, uint64(account.Nonce))
		stateDB.SetCode(address, account.Code)
		if account.Balance != nil {
			stateDB.SetBalance(address, toBigInt(account.Balance))
		}
		for key, value := range account.Storage {
			stateDB.SetState(address, key, value)
		}
	}
	stateDB.Finalise(true)

	traceEnv := core.CreateTraceEnvDirect(
		&chainConfig,
		&vm.LogConfig{
			EnableMemory:     true,
			EnableReturnData: true,
		},
		blockCtx,
		blockCtx.Coinbase,
		stateDB,
		parent,
		block,
		true,
	)

	return traceEnv.GetBlockTrace(block)
}

func Trace(config TraceConfig) ([]*types.ExecutionResult, error) {
	l2trace, err := L2Trace(config)
	if err != nil {
		return nil, err
	}

	return l2trace.ExecutionResults, nil
}
