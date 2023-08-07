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

// Copied from github.com/ethereum/go-ethereum/internal/ethapi.ExecutionResult
// ExecutionResult groups all structured logs emitted by the EVM
// while replaying a transaction in debug mode as well as transaction
// execution status, the amount of gas used and the return value
type ExecutionResult struct {
	Gas         uint64                `json:"gas"`
	Failed      bool                  `json:"failed"`
	ReturnValue string                `json:"returnValue"`
	StructLogs  []*types.StructLogRes `json:"structLogs"`
}

// Copied from github.com/ethereum/go-ethereum/internal/ethapi.FormatLogs
// FormatLogs formats EVM returned structured logs for json output
func FormatLogs(logs []*vm.StructLog) []*types.StructLogRes {
	formatted := make([]*types.StructLogRes, len(logs))
	for _, trace := range logs {
		logRes := types.NewStructLogResBasic(trace.Pc, trace.Op.String(), trace.Gas, trace.GasCost, trace.Depth, trace.RefundCounter, trace.Err)
		for _, stackValue := range trace.Stack {
			logRes.Stack = append(logRes.Stack, stackValue.Hex())
		}
		for i := 0; i+32 <= trace.Memory.Len(); i += 32 {
			logRes.Memory = append(logRes.Memory, common.Bytes2Hex(trace.Memory.Bytes()[i:i+32]))
		}
		if len(trace.Storage) != 0 {
			storage := make(map[string]string)
			for i, storageValue := range trace.Storage {
				storage[i.Hex()] = storageValue.Hex()
			}
			logRes.Storage = storage
		}
		logRes.ExtraData = trace.ExtraData

		formatted = append(formatted, logRes)
	}
	return formatted
}

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

func Trace(config TraceConfig) ([]*ExecutionResult, error) {
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

	var txsGasLimit uint64
	blockGasLimit := toBigInt(config.Block.GasLimit).Uint64()
	messages := make([]core.Message, len(config.Transactions))
	for i, tx := range config.Transactions {
		// If gas price is specified directly, the tx is treated as legacy type.
		if tx.GasPrice != nil {
			tx.GasFeeCap = tx.GasPrice
			tx.GasTipCap = tx.GasPrice
		}

		txAccessList := make(types.AccessList, len(tx.AccessList))
		for i, accessList := range tx.AccessList {
			txAccessList[i].Address = accessList.Address
			txAccessList[i].StorageKeys = accessList.StorageKeys
		}
		messages[i] = types.NewMessage(
			tx.From,
			tx.To,
			uint64(tx.Nonce),
			toBigInt(tx.Value),
			uint64(tx.GasLimit),
			toBigInt(tx.GasPrice),
			toBigInt(tx.GasFeeCap),
			toBigInt(tx.GasTipCap),
			tx.CallData,
			txAccessList,
			false,
		)

		txsGasLimit += uint64(tx.GasLimit)
	}
	if txsGasLimit > blockGasLimit {
		return nil, fmt.Errorf("txs total gas: %d Exceeds block gas limit: %d", txsGasLimit, blockGasLimit)
	}

	// For opcode PREVRANDAO
	//	randao := common.BigToHash(toBigInt(config.Block.Difficulty)) // TODO: fix

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

	// Run the transactions with tracing enabled.
	executionResults := make([]*ExecutionResult, len(config.Transactions))
	for i, message := range messages {
		tracer := vm.NewStructLogger(config.LoggerConfig)
		evm := vm.NewEVM(blockCtx, core.NewEVMTxContext(message), stateDB, &chainConfig, vm.Config{Debug: true, Tracer: tracer, NoBaseFee: true})

		result, err := core.ApplyMessage(evm, message, new(core.GasPool).AddGas(message.Gas()), big.NewInt(0))
		if err != nil {
			return nil, fmt.Errorf("Failed to apply config.Transactions[%d]: %w", i, err)
		}
		stateDB.Finalise(true)

		executionResults[i] = &ExecutionResult{
			Gas:         result.UsedGas,
			Failed:      result.Failed(),
			ReturnValue: fmt.Sprintf("%x", result.ReturnData),
			StructLogs:  FormatLogs(tracer.StructLogs()),
		}
	}

	return executionResults, nil
}
