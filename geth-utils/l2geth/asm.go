package main

import (
	"fmt"
	"io"
	"math/big"
	"strings"

	"github.com/scroll-tech/go-ethereum/core/vm"
)

type Asm struct {
	bytecode         []byte
	labelMap         map[string]int
	pendingLabelsMap map[string][]int
}

func NewAssembly() *Asm {
	return &Asm{
		labelMap:         make(map[string]int),
		pendingLabelsMap: make(map[string][]int),
	}
}

func (a *Asm) Bytecode() []byte {
	if len(a.pendingLabelsMap) > 0 {
		pendingLabels := make([]string, 0, len(a.pendingLabelsMap))
		for pendingLabel := range a.pendingLabelsMap {
			pendingLabels = append(pendingLabels, pendingLabel)
		}
		panic(fmt.Sprintf("pending labels are not defined yet: %v", strings.Join(pendingLabels, ", ")))
	}
	return a.bytecode
}

func (a *Asm) PrintMnemonics(out io.Writer) {
	for idx := 0; idx < len(a.bytecode); {
		code := vm.OpCode(a.bytecode[idx])
		// code >= PUSH1 and code <= PUSH32
		// <https://github.com/ethereum/go-ethereum/blob/944e1a0f906e021f9e513730af87144d61b1fcce/core/vm/opcodes.go#LL28C27-L28C27>
		// <https://github.com/ethereum/go-ethereum/pull/24039>
		if code.IsPush() {
			n := int(code) - int(vm.PUSH0)
			fmt.Fprintf(out, "%02d\t%s\t0x%x\n", idx, code.String(), a.bytecode[idx+1:idx+1+n])
			idx += n + 1
		} else {
			fmt.Fprintf(out, "%02d\t%s\n", idx, code.String())
			idx++
		}
	}
}

// 0x0 range
func (a *Asm) Stop() *Asm                       { return a.appendByte(vm.STOP) }
func (a *Asm) Add(v ...interface{}) *Asm        { return a.opWithPush(vm.ADD, v...) }
func (a *Asm) Mul(v ...interface{}) *Asm        { return a.opWithPush(vm.MUL, v...) }
func (a *Asm) Sub(v ...interface{}) *Asm        { return a.opWithPush(vm.SUB, v...) }
func (a *Asm) Div(v ...interface{}) *Asm        { return a.opWithPush(vm.DIV, v...) }
func (a *Asm) SDiv(v ...interface{}) *Asm       { return a.opWithPush(vm.SDIV, v...) }
func (a *Asm) Mod(v ...interface{}) *Asm        { return a.opWithPush(vm.MOD, v...) }
func (a *Asm) SMod(v ...interface{}) *Asm       { return a.opWithPush(vm.SMOD, v...) }
func (a *Asm) AddMod(v ...interface{}) *Asm     { return a.opWithPush(vm.ADDMOD, v...) }
func (a *Asm) MulMod(v ...interface{}) *Asm     { return a.opWithPush(vm.MULMOD, v...) }
func (a *Asm) Exp(v ...interface{}) *Asm        { return a.opWithPush(vm.EXP, v...) }
func (a *Asm) SignExtend(v ...interface{}) *Asm { return a.opWithPush(vm.SIGNEXTEND, v...) }

// 0x10 range
func (a *Asm) Lt(v ...interface{}) *Asm     { return a.opWithPush(vm.LT, v...) }
func (a *Asm) Gt(v ...interface{}) *Asm     { return a.opWithPush(vm.GT, v...) }
func (a *Asm) SLt(v ...interface{}) *Asm    { return a.opWithPush(vm.SLT, v...) }
func (a *Asm) SGt(v ...interface{}) *Asm    { return a.opWithPush(vm.SGT, v...) }
func (a *Asm) Eq(v ...interface{}) *Asm     { return a.opWithPush(vm.EQ, v...) }
func (a *Asm) IsZero(v ...interface{}) *Asm { return a.opWithPush(vm.ISZERO, v...) }
func (a *Asm) And(v ...interface{}) *Asm    { return a.opWithPush(vm.AND, v...) }
func (a *Asm) Or(v ...interface{}) *Asm     { return a.opWithPush(vm.OR, v...) }
func (a *Asm) Xor(v ...interface{}) *Asm    { return a.opWithPush(vm.XOR, v...) }
func (a *Asm) Not(v ...interface{}) *Asm    { return a.opWithPush(vm.NOT, v...) }
func (a *Asm) Byte(v ...interface{}) *Asm   { return a.opWithPush(vm.BYTE, v...) }
func (a *Asm) Shl(v ...interface{}) *Asm    { return a.opWithPush(vm.SHL, v...) }
func (a *Asm) Shr(v ...interface{}) *Asm    { return a.opWithPush(vm.SHR, v...) }
func (a *Asm) Sar(v ...interface{}) *Asm    { return a.opWithPush(vm.SAR, v...) }
func (a *Asm) Sha3(v ...interface{}) *Asm   { return a.opWithPush(vm.SHA3, v...) }

// 0x30 range
func (a *Asm) Address() *Asm                        { return a.appendByte(vm.ADDRESS) }
func (a *Asm) Balance(v ...interface{}) *Asm        { return a.opWithPush(vm.BALANCE, v...) }
func (a *Asm) Origin() *Asm                         { return a.appendByte(vm.ORIGIN) }
func (a *Asm) Caller() *Asm                         { return a.appendByte(vm.CALLER) }
func (a *Asm) CallValue() *Asm                      { return a.appendByte(vm.CALLVALUE) }
func (a *Asm) CallDataLoad(v ...interface{}) *Asm   { return a.opWithPush(vm.CALLDATALOAD, v...) }
func (a *Asm) CallDataSize() *Asm                   { return a.appendByte(vm.CALLDATASIZE) }
func (a *Asm) CallDataCopy(v ...interface{}) *Asm   { return a.opWithPush(vm.CALLDATACOPY, v...) }
func (a *Asm) CodeSize() *Asm                       { return a.appendByte(vm.CODESIZE) }
func (a *Asm) CodeCopy(v ...interface{}) *Asm       { return a.opWithPush(vm.CODECOPY, v...) }
func (a *Asm) GasPrice() *Asm                       { return a.appendByte(vm.GASPRICE) }
func (a *Asm) ExtCodeSize(v ...interface{}) *Asm    { return a.opWithPush(vm.EXTCODESIZE, v...) }
func (a *Asm) ExtCodeCopy(v ...interface{}) *Asm    { return a.opWithPush(vm.EXTCODECOPY, v...) }
func (a *Asm) ReturnDataSize() *Asm                 { return a.appendByte(vm.RETURNDATASIZE) }
func (a *Asm) ReturnDataCopy(v ...interface{}) *Asm { return a.opWithPush(vm.RETURNDATACOPY, v...) }
func (a *Asm) ExtCodeHash(v ...interface{}) *Asm    { return a.opWithPush(vm.EXTCODEHASH, v...) }

// 0x40 range
func (a *Asm) BlockHash(v ...interface{}) *Asm { return a.opWithPush(vm.BLOCKHASH, v...) }
func (a *Asm) Coinbase() *Asm                  { return a.appendByte(vm.COINBASE) }
func (a *Asm) Timestamp() *Asm                 { return a.appendByte(vm.TIMESTAMP) }
func (a *Asm) Number() *Asm                    { return a.appendByte(vm.NUMBER) }
func (a *Asm) Difficulty() *Asm                { return a.appendByte(vm.DIFFICULTY) }
func (a *Asm) GasLimit() *Asm                  { return a.appendByte(vm.GASLIMIT) }
func (a *Asm) ChainID() *Asm                   { return a.appendByte(vm.CHAINID) }
func (a *Asm) SelfBalance() *Asm               { return a.appendByte(vm.SELFBALANCE) }
func (a *Asm) BaseFee() *Asm                   { return a.appendByte(vm.BASEFEE) }

// 0x50 range
func (a *Asm) Pop() *Asm                     { return a.appendByte(vm.POP) }
func (a *Asm) MLoad(v ...interface{}) *Asm   { return a.opWithPush(vm.MLOAD, v...) }
func (a *Asm) MStore(v ...interface{}) *Asm  { return a.opWithPush(vm.MSTORE, v...) }
func (a *Asm) MStore8(v ...interface{}) *Asm { return a.opWithPush(vm.MSTORE8, v...) }
func (a *Asm) SLoad(v ...interface{}) *Asm   { return a.opWithPush(vm.SLOAD, v...) }
func (a *Asm) SStore(v ...interface{}) *Asm  { return a.opWithPush(vm.SSTORE, v...) }
func (a *Asm) Jump(label ...string) *Asm     { return a.jump(vm.JUMP, label...) }
func (a *Asm) JumpI(label ...string) *Asm    { return a.jump(vm.JUMPI, label...) }
func (a *Asm) PC() *Asm                      { return a.appendByte(vm.PC) }
func (a *Asm) MSize() *Asm                   { return a.appendByte(vm.MSIZE) }
func (a *Asm) Gas() *Asm                     { return a.appendByte(vm.GAS) }
func (a *Asm) JumpDest(label ...string) *Asm { return a.jumpDest(label...) }
func (a *Asm) Push0() *Asm                   { return a.appendByte(vm.PUSH0) }

// 0x60 range
func (a *Asm) PushX(val interface{}) *Asm { return a.push(val) }
func (a *Asm) DupX(x int) *Asm {
	rangeCheck(x, 1, 16, "X")
	return a.appendByte(int(vm.DUP1) + x - 1)
}
func (a *Asm) SwapX(x int) *Asm {
	rangeCheck(x, 1, 16, "X")
	return a.appendByte(int(vm.SWAP1) + x - 1)
}

// 0xa0 range
func (a *Asm) LogX(x int) *Asm {
	rangeCheck(x, 0, 5, "X")
	return a.appendByte(int(vm.LOG0) + x)
}

// 0xf0 range
func (a *Asm) Create(v ...interface{}) *Asm       { return a.opWithPush(vm.CREATE, v...) }
func (a *Asm) Call(v ...interface{}) *Asm         { return a.opWithPush(vm.CALL, v...) }
func (a *Asm) CallCode(v ...interface{}) *Asm     { return a.opWithPush(vm.CALLCODE, v...) }
func (a *Asm) Return(v ...interface{}) *Asm       { return a.opWithPush(vm.RETURN, v...) }
func (a *Asm) DelegateCall(v ...interface{}) *Asm { return a.opWithPush(vm.DELEGATECALL, v...) }
func (a *Asm) Create2(v ...interface{}) *Asm      { return a.opWithPush(vm.CREATE2, v...) }
func (a *Asm) StaticCall(v ...interface{}) *Asm   { return a.opWithPush(vm.STATICCALL, v...) }
func (a *Asm) Revert(v ...interface{}) *Asm       { return a.opWithPush(vm.REVERT, v...) }
func (a *Asm) SelfDestruct() *Asm                 { return a.appendByte(vm.SELFDESTRUCT) }

func (a *Asm) jump(op vm.OpCode, label ...string) *Asm {
	if len(label) > 0 {
		rangeCheck(len(label), 1, 1, "len(label)")

		if pos, ok := a.labelMap[label[0]]; ok {
			a.PushX(pos)
		} else {
			a.pendingLabelsMap[label[0]] = append(a.pendingLabelsMap[label[0]], len(a.bytecode))
			a.PushX([]byte{0, 0, 0})
		}
	}

	return a.appendByte(op)
}

func (a *Asm) jumpDest(label ...string) *Asm {
	a.appendByte(vm.JUMPDEST)

	if len(label) > 0 {
		rangeCheck(len(label), 1, 1, "len(label)")

		if _, ok := a.labelMap[label[0]]; ok {
			panic("label already defined")
		}

		a.labelMap[label[0]] = len(a.bytecode)

		pos := big.NewInt(int64(len(a.bytecode) - 1)).Bytes()
		if len(pos) < 3 {
			pos = append(make([]byte, 3-len(pos)), pos...)
		}
		for _, pendingLabel := range a.pendingLabelsMap[label[0]] {
			copy(a.bytecode[pendingLabel+1:pendingLabel+4], pos)
		}

		delete(a.pendingLabelsMap, label[0])
	}

	return a
}

func (a *Asm) opWithPush(op vm.OpCode, v ...interface{}) *Asm {
	opPushRangeCheck(op, len(v))
	return a.pushRev(v...).appendByte(op)
}

func (a *Asm) push(v ...interface{}) *Asm {
	for _, v := range v {
		bytes := toBytes(v)

		rangeCheck(len(bytes), 1, 32, "len(bytes)")
		a.appendByte(int(vm.PUSH0) + len(bytes))

		for _, b := range bytes {
			a.appendByte(b)
		}
	}

	return a
}

func (a *Asm) pushRev(v ...interface{}) *Asm {
	reverse(v)
	return a.push(v...)
}

func (a *Asm) appendByte(v interface{}) *Asm {
	switch v := v.(type) {
	case vm.OpCode:
		a.bytecode = append(a.bytecode, byte(v))
	case byte:
		a.bytecode = append(a.bytecode, v)
	case int:
		a.bytecode = append(a.bytecode, byte(v))
	default:
		panic(fmt.Sprintf("unexpected appendByte type %T", v))
	}

	return a
}
