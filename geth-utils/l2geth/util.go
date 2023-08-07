package main

import (
	"fmt"
	"math/big"
	"unsafe"

	"github.com/holiman/uint256"
	"github.com/scroll-tech/go-ethereum/common"
	"github.com/scroll-tech/go-ethereum/common/hexutil"
	"github.com/scroll-tech/go-ethereum/core/vm"
)

var (
	minStackPtrOffset    = 3 * unsafe.Sizeof(int(0))
	longonInstructionSet = newLondonInstructionSet()
)

//go:linkname newLondonInstructionSet github.com/scroll-tech/go-ethereum/core/vm.newLondonInstructionSet
func newLondonInstructionSet() vm.JumpTable

func opPushRangeCheck(op vm.OpCode, n int) {
	opPtr := unsafe.Pointer(longonInstructionSet[op])
	minStack := *(*int)(unsafe.Pointer(uintptr(opPtr) + minStackPtrOffset))
	rangeCheck(n, 0, minStack, fmt.Sprintf("len(vals) of %s", op.String()))
}

func rangeCheck(n, l, h int, name string) {
	if n < l || n > h {
		if l == h {
			panic(fmt.Sprintf("%s should be %d, but got %d", name, h, n))
		} else {
			panic(fmt.Sprintf("%s should be in range [%d, %d], but got %d", name, l, h, n))
		}
	}
}

func reverse(vals []interface{}) {
	for i, j := 0, len(vals)-1; i < j; i, j = i+1, j-1 {
		vals[i], vals[j] = vals[j], vals[i]
	}
}

func toBytes(value interface{}) []byte {
	var bytes []byte

	switch value := value.(type) {
	case string:
		u256, err := uint256.FromHex(value)
		if err != nil {
			panic(err)
		}
		bytes = u256.Bytes()
	case int:
		for value > 0 {
			bytes = append([]byte{byte(value & 0xff)}, bytes...)
			value >>= 8
		}
	case []byte:
		bytes = value
	case common.Address:
		bytes = value.Bytes()
	case common.Hash:
		bytes = value.Bytes()
	case *uint256.Int:
		bytes = value.Bytes()
	case *big.Int:
		bytes = value.Bytes()
	default:
		panic(fmt.Errorf("Unsupported type %T", value))
	}

	if len(bytes) == 0 {
		bytes = []byte{0}
	}

	return bytes
}

func toBigInt(value *hexutil.Big) *big.Int {
	if value != nil {
		return value.ToInt()
	}
	return big.NewInt(0)
}
