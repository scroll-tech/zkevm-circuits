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
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/eth/tracers"
	"github.com/ethereum/go-ethereum/eth/tracers/logger"
	_ "github.com/ethereum/go-ethereum/eth/tracers/native"
	"github.com/ethereum/go-ethereum/params"
	"github.com/imdario/mergo"
)

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
	// where the lastest one is at HistoryHashes[len(HistoryHashes)-1].
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
		ChainID:             new(big.Int).SetUint64(config.ChainID),
		HomesteadBlock:      big.NewInt(0),
		DAOForkBlock:        big.NewInt(0),
		DAOForkSupport:      true,
		EIP150Block:         big.NewInt(0),
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
		txContext := core.NewEVMTxContext(&message)
		prestateTracer, err := tracers.DefaultDirectory.New("prestateTracer", new(tracers.Context), nil)
		if err != nil {
			return nil, fmt.Errorf("Failed to create prestateTracer: %w", err)
		}
		callTracer, err := tracers.DefaultDirectory.New("callTracer", new(tracers.Context), nil)
		if err != nil {
			return nil, fmt.Errorf("Failed to create callTracer: %w", err)
		}
		structLogger := logger.NewStructLogger(config.LoggerConfig)
		tracer := NewMuxTracer(
			structLogger,
			prestateTracer,
			callTracer,
		)
		evm := vm.NewEVM(blockCtx, txContext, stateDB, &chainConfig, vm.Config{Tracer: tracer, NoBaseFee: true})

		result, err := core.ApplyMessage(evm, &message, new(core.GasPool).AddGas(message.GasLimit))
		if err != nil {
			return nil, fmt.Errorf("Failed to apply config.Transactions[%d]: %w", i, err)
		}
		stateDB.Finalise(true)

		prestate, err := prestateTracer.GetResult()
		if err != nil {
			return nil, fmt.Errorf("Failed to get prestateTracer result: %w", err)
		}

		callTrace, err := callTracer.GetResult()
		if err != nil {
			return nil, fmt.Errorf("Failed to get callTracer result: %w", err)
		}

		executionResults[i] = &ExecutionResult{
			Gas:         result.UsedGas,
			Failed:      result.Failed(),
			ReturnValue: fmt.Sprintf("%x", result.ReturnData),
			StructLogs:  FormatLogs(structLogger.StructLogs()),
			Prestate:    prestate,
			CallTrace:   callTrace,
		}
	}

	return executionResults, nil
}

type MuxTracer struct {
	tracers []vm.EVMLogger
}

func NewMuxTracer(tracers ...vm.EVMLogger) *MuxTracer {
	return &MuxTracer{tracers}
}

func (t *MuxTracer) CaptureTxStart(gasLimit uint64) {
	for _, tracer := range t.tracers {
		tracer.CaptureTxStart(gasLimit)
	}
}

func (t *MuxTracer) CaptureTxEnd(restGas uint64) {
	for _, tracer := range t.tracers {
		tracer.CaptureTxEnd(restGas)
	}
}

func (t *MuxTracer) CaptureStart(env *vm.EVM, from common.Address, to common.Address, create bool, input []byte, gas uint64, value *big.Int) {
	for _, tracer := range t.tracers {
		tracer.CaptureStart(env, from, to, create, input, gas, value)
	}
}

func (t *MuxTracer) CaptureEnd(output []byte, gasUsed uint64, err error) {
	for _, tracer := range t.tracers {
		tracer.CaptureEnd(output, gasUsed, err)
	}
}

func (t *MuxTracer) CaptureEnter(typ vm.OpCode, from common.Address, to common.Address, input []byte, gas uint64, value *big.Int) {
	for _, tracer := range t.tracers {
		tracer.CaptureEnter(typ, from, to, input, gas, value)
	}
}

func (t *MuxTracer) CaptureExit(output []byte, gasUsed uint64, err error) {
	for _, tracer := range t.tracers {
		tracer.CaptureExit(output, gasUsed, err)
	}
}

func (t *MuxTracer) CaptureState(pc uint64, op vm.OpCode, gas, cost uint64, scope *vm.ScopeContext, rData []byte, depth int, err error) {
	for _, tracer := range t.tracers {
		tracer.CaptureState(pc, op, gas, cost, scope, rData, depth, err)
	}
}

func (t *MuxTracer) CaptureFault(pc uint64, op vm.OpCode, gas, cost uint64, scope *vm.ScopeContext, depth int, err error) {
	for _, tracer := range t.tracers {
		tracer.CaptureFault(pc, op, gas, cost, scope, depth, err)
	}
}
