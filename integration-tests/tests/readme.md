# Integration Test #

## Mainnet

Testings in `mainnet.rs` enable accessing a RPC node with debug API, and test any block or single transaction from the node. Trace and block witness would be rebuilt from the input data (block or tx) and then being mocking proven by a specified circuit.

The running parameters are specified by enviroment variables:

* CIRCUIT: the circuit used to launch mocking proven, can be `super` (by default), `evm`, `copy`, `rlp`, `tx`, `state`, and we can use `none` to make a dry-run (no provding but only building of witness)
* GETH0_URL: the url of RPC node, like "https://eth-goerli.g.alchemy.com/v2/"

For testing block, we specify blocks inside a range by `START_BLOCK` and `END_BLOCK`:

* if we wish to test block 11001 from RPC node at `http://localhost:30303`
```bash
GETH0_URL=http://localhost:30303 START_BLOCK=11001 END_BLOCK=11001 cargo test --features=scroll --release test_circuit_all_block
```

For testing single transaction, we specify id of tx by `TXID`:
```bash
TX_ID=0xc820f41c097fb21e7d3dcbf450d2e20f28989eea4e36ee2ebd076b6952cf6693 GETH0_URL=http://localhost:30303 cargo test --features=scroll --release test_mock_prove_tx
```

### About testing mainnet block
To support most txs in mainnet some features are still missed:

- [ ] EIP1559 in bus-mapping tx circuit (tx type = 2)
- [ ] BASEFEE opcode

And for support most blocks in mainnet require more features:
- [ ] Support >128 max txs for rlp / sig circuit
- [ ] large copy data (> 500,000 which is hardcoded currently, 1.5M is adviced)
