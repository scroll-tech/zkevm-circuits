package main

/*
   #include <stdlib.h>
*/
import "C"
import (
	"encoding/json"
	"fmt"
	"unsafe"
)

// TODO: Add proper error handling.  For example, return an int, where 0 means
// ok, and !=0 means error.
//
//export CreateTrace
func CreateTrace(configStr *C.char) *C.char {
	//fmt.Printf("%s", C.GoString(configStr))
	var config TraceConfig
	err := json.Unmarshal([]byte(C.GoString(configStr)), &config)
	if err != nil {
		return C.CString(fmt.Sprintf("Failed to unmarshal config, err: %v", err))
	}

	executionResults, err := Trace(config)
	if err != nil {
		return C.CString(fmt.Sprintf("Failed to run Trace, err: %v", err))
	}

	bytes, err := json.MarshalIndent(executionResults, "", "  ")
	if err != nil {
		return C.CString(fmt.Sprintf("Failed to marshal []ExecutionResult, err: %v", err))
	}

	return C.CString(string(bytes))
}

//export FreeString
func FreeString(str *C.char) {
	C.free(unsafe.Pointer(str))
}

func main() {}
