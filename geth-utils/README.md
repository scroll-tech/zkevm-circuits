# Go Ethereum Utility

The module `gethutil` tried to provide identical output from APIs `debug_trace*` of latest `geth` as test vectors for [`zkevm-circuits`](https://github.com/privacy-scaling-explorations/zkevm-circuits).

### Debugging

The execution traces returned by geth omit some information like execution
errors in some situations.  Moreover you may want to inspect some intermediate
values of the EVM execution for debugging purposes.

Print debugging can be easily achieved by replacing the dependency of `go-ethereum` by a local copy of the repository.  Just clone `go-ethereum` into a folder next to the `zkevm-circuits` repository, and uncomment the following line in `go.mod`:
```
replace github.com/ethereum/go-ethereum => ../../go-ethereum
```

Now you can add print logs in your `go-ethereum` copy as necessary. 
