package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/ethereum/go-ethereum/common"

	"main/gethutil"
)

func main() {
	address := common.BytesToAddress([]byte{0xff})
	assembly := gethutil.NewAssembly().SStore(0, 0xcafeb0ba).SLoad(0).SStore(0, 0xdeabbeef).SLoad(0)

	accounts := map[common.Address]gethutil.Account{address: {Code: assembly.Bytecode()}}
	tx := gethutil.Transaction{To: &address, GasLimit: 46000}

	result, err := gethutil.Trace(gethutil.TraceConfig{Accounts: accounts, Transactions: []gethutil.Transaction{tx}})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to trace tx, err: %v\n", err)
	}

	bytes, err := json.MarshalIndent(result[0].StructLogs, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to marshal logs, err: %v\n", err)
	}

	fmt.Fprintln(os.Stdout, string(bytes))
}
