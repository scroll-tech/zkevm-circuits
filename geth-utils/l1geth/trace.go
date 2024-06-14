package main

import (
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/eth/tracers"
	"github.com/ethereum/go-ethereum/eth/tracers/logger"
	_ "github.com/ethereum/go-ethereum/eth/tracers/native"
	"github.com/ethereum/go-ethereum/params"
	"github.com/holiman/uint256"
	"github.com/imdario/mergo"
)

func init() {
	tracers.DefaultDirectory.Register("structLogTracer", newStructLogTracer, false)
}

// Copied from github.com/ethereum/go-ethereum/internal/ethapi.ExecutionResult
// ExecutionResult groups all structured logs emitted by the EVM
// while replaying a transaction in debug mode as well as transaction
// execution status, the amount of gas used and the return value
type ExecutionResult struct {
	Gas         uint64          `json:"gas"`
	Failed      bool            `json:"failed"`
	ReturnValue string          `json:"returnValue"`
	StructLogs  []StructLogRes  `json:"structLogs"`
	Prestate    json.RawMessage `json:"prestate"`
	CallTrace   json.RawMessage `json:"callTrace"`
}

// StructLogRes stores a structured log emitted by the EVM while replaying a
// transaction in debug mode
// Copied from github.com/ethereum/go-ethereum/internal/ethapi.StructLogRes
type StructLogRes struct {
	Pc            uint64             `json:"pc"`
	Op            string             `json:"op"`
	Gas           uint64             `json:"gas"`
	GasCost       uint64             `json:"gasCost"`
	Depth         int                `json:"depth"`
	Error         string             `json:"error,omitempty"`
	Stack         *[]string          `json:"stack,omitempty"`
	Memory        *[]string          `json:"memory,omitempty"`
	Storage       *map[string]string `json:"storage,omitempty"`
	RefundCounter uint64             `json:"refund,omitempty"`
}

// Copied from github.com/ethereum/go-ethereum/internal/ethapi.FormatLogs
// FormatLogs formats EVM returned structured logs for json output
func FormatLogs(logs []logger.StructLog) []StructLogRes {
	formatted := make([]StructLogRes, len(logs))
	for index, trace := range logs {
		formatted[index] = StructLogRes{
			Pc:            trace.Pc,
			Op:            trace.Op.String(),
			Gas:           trace.Gas,
			GasCost:       trace.GasCost,
			Depth:         trace.Depth,
			Error:         trace.ErrorString(),
			RefundCounter: trace.RefundCounter,
		}
		if trace.Stack != nil {
			stack := make([]string, len(trace.Stack))
			for i, stackValue := range trace.Stack {
				stack[i] = stackValue.Hex()
			}
			formatted[index].Stack = &stack
		}
		if trace.Memory != nil {
			memory := make([]string, 0, (len(trace.Memory)+31)/32)
			for i := 0; i+32 <= len(trace.Memory); i += 32 {
				memory = append(memory, fmt.Sprintf("%x", trace.Memory[i:i+32]))
			}
			formatted[index].Memory = &memory
		}
		if trace.Storage != nil {
			storage := make(map[string]string)
			for i, storageValue := range trace.Storage {
				storage[fmt.Sprintf("%x", i)] = fmt.Sprintf("%x", storageValue)
			}
			formatted[index].Storage = &storage
		}
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
		Address common.Address `json:"address"`
		// Must be `storageKeys`, since `camelCase` is specified in ethers-rs.
		// <https://github.com/gakonst/ethers-rs/blob/88095ba47eb6a3507f0db1767353b387b27a6e98/ethers-core/src/types/transaction/eip2930.rs#L75>
		StorageKeys []common.Hash `json:"storageKeys"`
	} `json:"access_list"`
}

type TraceConfig struct {
	ChainID uint64 `json:"chain_id"`
	// HistoryHashes contains most recent 256 block hashes in history,
	// where the latest one is at HistoryHashes[len(HistoryHashes)-1].
	HistoryHashes []*hexutil.Big             `json:"history_hashes"`
	Block         Block                      `json:"block_constants"`
	Accounts      map[common.Address]Account `json:"accounts"`
	Transactions  []Transaction              `json:"transactions"`
	LoggerConfig  *logger.Config             `json:"logger_config"`
	ChainConfig   *params.ChainConfig        `json:"chain_config"`
}

func newUint64(val uint64) *uint64 { return &val }

func toBigInt(value *hexutil.Big) *big.Int {
	if value != nil {
		return value.ToInt()
	}
	return big.NewInt(0)
}

func Trace(config TraceConfig) ([]*ExecutionResult, error) {
	chainConfig := params.ChainConfig{
		ChainID:                       new(big.Int).SetUint64(config.ChainID),
		HomesteadBlock:                big.NewInt(0),
		DAOForkBlock:                  big.NewInt(0),
		DAOForkSupport:                true,
		EIP150Block:                   big.NewInt(0),
		EIP155Block:                   big.NewInt(0),
		EIP158Block:                   big.NewInt(0),
		ByzantiumBlock:                big.NewInt(0),
		ConstantinopleBlock:           big.NewInt(0),
		PetersburgBlock:               big.NewInt(0),
		IstanbulBlock:                 big.NewInt(0),
		MuirGlacierBlock:              big.NewInt(0),
		BerlinBlock:                   big.NewInt(0),
		LondonBlock:                   big.NewInt(0),
		ShanghaiTime:                  newUint64(0),
		CancunTime:                    newUint64(0),
		TerminalTotalDifficulty:       big.NewInt(0),
		TerminalTotalDifficultyPassed: true,
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
		if tx.GasPrice != nil {
			// Set GasFeeCap and GasTipCap to GasPrice if not exist.
			if tx.GasFeeCap == nil {
				tx.GasFeeCap = tx.GasPrice
			}
			if tx.GasTipCap == nil {
				tx.GasTipCap = tx.GasPrice
			}
		}

		txAccessList := make(types.AccessList, len(tx.AccessList))
		for i, accessList := range tx.AccessList {
			txAccessList[i].Address = accessList.Address
			txAccessList[i].StorageKeys = accessList.StorageKeys
		}
		messages[i] = core.Message{
			From:              tx.From,
			To:                tx.To,
			Nonce:             uint64(tx.Nonce),
			Value:             toBigInt(tx.Value),
			GasLimit:          uint64(tx.GasLimit),
			GasPrice:          toBigInt(tx.GasPrice),
			GasFeeCap:         toBigInt(tx.GasFeeCap),
			GasTipCap:         toBigInt(tx.GasTipCap),
			Data:              tx.CallData,
			AccessList:        txAccessList,
			SkipAccountChecks: false,
		}

		txsGasLimit += uint64(tx.GasLimit)
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
		Time:        toBigInt(config.Block.Timestamp).Uint64(),
		Difficulty:  toBigInt(config.Block.Difficulty),
		Random:      &randao,
		BaseFee:     toBigInt(config.Block.BaseFee),
		GasLimit:    blockGasLimit,
	}

	// Setup state db with accounts from argument
	stateDB, _ := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	for address, account := range config.Accounts {
		stateDB.SetNonce(address, uint64(account.Nonce))
		stateDB.SetCode(address, account.Code)
		if account.Balance != nil {
			stateDB.SetBalance(address, uint256.MustFromBig(toBigInt(account.Balance)), tracing.BalanceChangeUnspecified)
		}
		for key, value := range account.Storage {
			stateDB.SetState(address, key, value)
		}
	}
	stateDB.Finalise(true)

	var (
		usedGas         uint64
		resultMap       map[string]json.RawMessage
		executionResult ExecutionResult
	)

	loggerConfig, err := json.Marshal(config.LoggerConfig)
	if err != nil {
		return nil, fmt.Errorf("Failed to marshal configLoggerConfig, %w", err)
	}

	// Run the transactions with tracing enabled.
	executionResults := make([]*ExecutionResult, len(config.Transactions))
	for i, message := range messages {
		txContext := core.NewEVMTxContext(&message)
		muxTracerConfig := []byte(fmt.Sprintf(`
		{
			"structLogTracer": %s,
			"callTracer": null,
			"prestateTracer": null
		}
		`, loggerConfig))
		muxTracer, err := tracers.DefaultDirectory.New("muxTracer", new(tracers.Context), muxTracerConfig)
		if err != nil {
			return nil, err
		}
		evm := vm.NewEVM(blockCtx, txContext, stateDB, &chainConfig, vm.Config{Tracer: muxTracer.Hooks, NoBaseFee: true})

		tx := types.NewTx(toTxData(message, chainConfig.ChainID))
		_, err = core.ApplyTransactionWithEVM(&message, &chainConfig,
			new(core.GasPool).AddGas(message.GasLimit), stateDB,
			blockCtx.BlockNumber,
			common.Hash{}, tx, &usedGas, evm)
		if err != nil {
			return nil, fmt.Errorf("Failed to apply config.Transactions[%d]: %w", i, err)
		}
		stateDB.Finalise(true)

		muxResult, err := muxTracer.GetResult()
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(muxResult, &resultMap); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(resultMap["structLogTracer"], &executionResult); err != nil {
			return nil, err
		}
		executionResult.Prestate = resultMap["prestateTracer"]
		executionResult.CallTrace = resultMap["callTracer"]

		executionResults[i] = &executionResult
	}

	return executionResults, nil
}

func toTxData(message core.Message, ChainID *big.Int) types.TxData {
	var data types.TxData
	switch {
	case message.BlobHashes != nil:
		al := types.AccessList{}
		if message.AccessList != nil {
			al = message.AccessList
		}
		data = &types.BlobTx{
			To:         *message.To,
			ChainID:    uint256.MustFromBig((*big.Int)(ChainID)),
			Nonce:      message.Nonce,
			Gas:        message.GasLimit,
			GasFeeCap:  uint256.MustFromBig((*big.Int)(message.GasFeeCap)),
			GasTipCap:  uint256.MustFromBig((*big.Int)(message.GasTipCap)),
			Value:      uint256.MustFromBig((*big.Int)(message.Value)),
			Data:       message.Data,
			AccessList: al,
			BlobHashes: message.BlobHashes,
			BlobFeeCap: uint256.MustFromBig((*big.Int)(message.BlobGasFeeCap)),
		}
		// if message.Blobs != nil {
		// 	data.(*types.BlobTx).Sidecar = &types.BlobTxSidecar{
		// 		Blobs:       message.Blobs,
		// 		Commitments: message.Commitments,
		// 		Proofs:      message.Proofs,
		// 	}
		// }

	case message.GasFeeCap != nil:
		al := types.AccessList{}
		if message.AccessList != nil {
			al = message.AccessList
		}
		data = &types.DynamicFeeTx{
			To:         message.To,
			ChainID:    (*big.Int)(ChainID),
			Nonce:      message.Nonce,
			Gas:        message.GasLimit,
			GasFeeCap:  message.GasFeeCap,
			GasTipCap:  message.GasTipCap,
			Value:      message.Value,
			Data:       message.Data,
			AccessList: al,
		}

	case message.AccessList != nil:
		data = &types.AccessListTx{
			To:         message.To,
			ChainID:    ChainID,
			Nonce:      message.Nonce,
			Gas:        message.GasLimit,
			GasPrice:   message.GasPrice,
			Value:      message.Value,
			Data:       message.Data,
			AccessList: message.AccessList,
		}

	default:
		data = &types.LegacyTx{
			To:       message.To,
			Nonce:    message.Nonce,
			Gas:      message.GasLimit,
			GasPrice: message.GasPrice,
			Value:    message.Value,
			Data:     message.Data,
		}
	}
	return data
}

func newStructLogTracer(ctx *tracers.Context, cfg json.RawMessage) (*tracers.Tracer, error) {
	var config logger.Config
	if cfg != nil {
		if err := json.Unmarshal(cfg, &config); err != nil {
			return nil, err
		}
	}
	structLogger := logger.NewStructLogger(&config)
	return &tracers.Tracer{
		Hooks:     structLogger.Hooks(),
		GetResult: structLogger.GetResult,
		Stop:      structLogger.Stop,
	}, nil
}
