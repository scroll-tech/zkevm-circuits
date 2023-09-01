---
tags: scroll documentation
---

# Public Input Circuit

code: https://github.com/scroll-tech/zkevm-circuits/blob/develop/zkevm-circuits/src/pi_circuit.rs `develop` branch


## Public Data

`PublicData` contains the block header information (block contexts) as well as transactions information. It is structured as follows:

```markmap
# PublicData
## ChainID (u64Word)
## transactions
- Transaction
    - block_number
    - id
    - hash
    - nonce
    - gas
    - gas_price
    - caller_address
    - callee_address
    - is_create
    - value
    - call_data
    - call_data_length
    - call_data_gas_cost
    - chain_id
    - rlp_unsigned
    - rlp_signed
    - v
    - r
    - s
    - calls
    - steps
- Transaction
- ...
## block_ctxs (BTreeMap: BlockNumber(u64)->BlockContext)
- Block Context
    - coinbase
    - gas_limit
    - number
    - timestamp
    - difficulty
    - base_fee
    - history_hashes
    - chain_id
    - eth_block
- Block Context
- ...
## prev_state_root (256bit hash)
## withdraw_trie_root (256bit hash)
```

The above `PublicData` will be transformed byte by byte into `pi_bytes` as the actual pi data:

- `pi_bytes`
    - `chain_id` (u64 Word in big-endian bytes)
    - `prev_state_root` (256-bit hash in bytes)
    - `after_state_root` (256-bit hash in bytes, obtained from the last `block_ctx`'s state root in the list of `block_ctxs`)
    - `withdraw_trie_root` (256-bit hash in bytes)
    - `data_hash` (keccak256 of `data_bytes`)

where `data_bytes` rolls over all `block_ctxs` and `transactions` to produce an array with the following components
- `data_bytes`
    - roll over each `block_ctx`:
        - `number` (u64 in big-endian bytes)
        - `timestamp` (u64 in big-endian bytes)
        - `base_fee` (in big-endian bytes)
        - `gas_limit` (in big-endian bytes)
        - `num_txs` (in big-endian bytes) which is the number of `transactions` that are included in this block
    - roll over each `transaction`:
        - tx hash (in bytes): Each `tx_hash` is of the form `keccak(rlp(tx_sign))`. 

Finally `pi_hash` is the Keccak256 hash of `pi_bytes`.


## The Purpose of Public Input Circuit

The above `pi_bytes` is assigned to the PI Circuit byte-by-byte. The PI Circuit aims to check the correctness of `pi_bytes` by looking up to the Keccak table for `pi_hash` and compare the `pi_hash` with a given instance of the `pi_hash`. 

Since the [Keccak table](https://github.com/scroll-tech/zkevm-circuits/blob/925f6fc423af6b733a36b544289b4514fc9faecb/zkevm-circuits/src/table.rs#L1289) only records input RLC and output RLC, to perform the lookup, PI Circuit must record the RLC accumulation of input bytes and (hash) output bytes. This induces further checks about the correctness of these RLC accumulations. These accumulation columns are also re-used to store Keccak input rlc and output rlcs, so they induce many copy constraints. Furthermore, some of the public input data fields such as block context, tx hashes, chain_id, coinbase, difficulty are having connection with the block table and tx table, so copy constraints with them are also established.


## Circuit Layout and Design

PI Circuit is assigned in a byte-by-byte manner that corresponds to each field of the public data information. For each field, the value is decomposed into bytes and assigned in a way that each byte occupies one circuit row. At the boundaries between data fields some selectors/fixed column are turned on/off (true/false). 

Also, the columns that are used to store the raw public input bytes, or RLC results, or length can be re-used to store RLC of data bytes, pi bytes, data hash, pi hash etc. This leads to copy constraints that enforce some of the specific cells in the pi circuits that must be equal. The PI circuit is written in a fashion that specific cells in a column may be extracted and then used elsewhere for copy constraint purposes.

The columns of PI circuit are explained as follows:

- `constant`: Fixed Column. It is dedicated to store coinbase, difficulty in bytes.
- `rpi`: Advice Column, also called `raw_public_inputs`. It stores the RLC (using `evm_word` randomness) or LC (using `BYTE_POW_BASE=256`) of the current field of public input data represented in bytes. The choice of RLC or LC depends on the bit-length of this data field's rpi value under consideration: if this value's bit-length can be hold by a field element's capacity, we use RLC with `evm_word` randomness; otherwise, we use LC with `BYTE_POW_BASE`(=256) as the LC multiplication factor. This column is also used to store some data bytes, pi bytes and Keccak input RLC result as follows:
    - After all `data_bytes` fields are assigned, turn `q_keccak=1` and record rlc of data bytes via `keccak_input` randomness
    - After all `pi_bytes` fields are assigned, turn `q_keccak=1` and record rlc of pi bytes via `keccak_input` randomness 
    - After all data fields are assigned, this column is used to store RLC of the high 16-byte (`Keccak_hi`) and RLC of the low 16-byte (`Keccak_lo`) of the `pi_hash=Keccak(pi_bytes)` using `evm_word` randomness.
- `rpi_bytes`: Advice Column, also called `rpi_field_bytes`. It fills `pi_bytes` in a byte-by-byte manner. After all rpi data field are filled, this column is used to record the high 16 byte and the low 16 byte of `pi_hash`. So a typical assignment has the following order:
    - `data_bytes`: 
        - for each `block_ctx`: byte by byte of `block_number`, `time_stamp`, `base_fee`, `gas_limit`, `num_txs`. This will be padded by `BlockContext::Padding(chain_id)` until number of `block_ctx` reaches `max_inner_blocks`;
        - for each `transaction`: byte by byte of `tx_hash`. This will be padded by `dummy_tx_hash` (which corresponds to tx private key = 1.) until number of `tx_hash` reaches `max_txs`;
    - `pi_bytes`
        - `chain_id`: in big-endian form
        - `previous_state_root`
        - `after_state_root`
        - `withdraw_trie_root`
        - `data_hash`
    - `pi_hash`
        - high 16 bytes 
        - low 16 bytes
    - `coinbase`: `N_BYTES_ACCOUNT_ADDRESS` number of bytes
    - `difficulty`: `N_BYTES_WORD` number of bytes 
- `rpi_bytes_acc`: Advice Column, also called `rpi_field_bytes_acc`. It records the accumulation of RLC/LC of `rpi_bytes`. The choice of RLC or LC depends on the bit-length of the current pi data field's value being assigned: if this value's bit-length can be hold by a field element's capacity, we use RLC with `evm_word` randomness, and at this time `is_field_rlc` is true; otherwise, we use LC with `BYTE_POW_BASE`(=256) to do the LC and at this time `is_field_rlc` is false. 
- `rpi_rlc_acc`: Advice Column, cumulative RLC of `rpi_bytes` using `keccak_input` randomness (because of the need to lookup into Keccak table). This column is also used to store the RLC of data hash and pi hash as follows:
    - After all `data_bytes` fields are assigned, turn `q_keccak=1` and record rlc of data hash via `evm_word` randomness
    - After all `pi_bytes` fields are assigned, turn `q_keccak=1` and record rlc of pi hash via `evm_word` randomness 
    - After all data fields are assigned, this column is used to store cumulative RLC of the high 16-byte (`Keccak_hi`) and cumulative RLC of the low 16-byte (`Keccak_lo`) of the `pi_hash=Keccak(pi_bytes)` using `evm_word` randomness.
- `rpi_length_acc`: Advice column. It is used to record the accumulated length in bytes of `rpi_bytes`. This column is also used to store the length of data bytes and pi bytes as follows:
    - After all `data_bytes` fields are assigned, turn `q_keccak=1` and record the length of data bytes
    - After all `pi_bytes` fields are assigned, turn `q_keccak=1` and record the length of pi bytes
    - After all data fields are assigned, this column is used to store accumulation of `pi_hash` in bytes with length from 1 to 32.
- `is_rpi_padding`: Advice Column. It is true when the currently assigned field is not included in the data bytes. For example, this happens at the padding rows for `block_ctxs` or `transactions` inside `rpi_bytes`.
- `real_rpi`: Advice column. If `is_rpi_padding` then assign 0, otherwise it is the same as `rpi` column. This column is used for recording valid block context fields that are copied to block table.
- `pi`: Instance Column. It is used to record `keccak_hi` and `keccak_lo`
- `q_field_step`: Selector Column. This selector is enabled except when the currently assigned field is running at its last byte. 
- `is_field_rlc`: Fixed Column. This is true if the bit-length of the value of currently assigned field can be hold by a field element's capacity.
- `q_block_context`: Fixed Column. This is true when the currently assigned field is in `data_bytes` and is related to `block_ctx` information. 
- `q_tx_hashes`: Fixed Column. This is true when the currently assigned field is in `data_bytes` and is related to `transactions` information.
- `q_not_end`: Selector Column. It is enabled during (1) `data_bytes` rows; (2) `pi_bytes` rows; `pi_hash_bytes` rows;
- `is_rlc_keccak`: Fixed Column. This is true when the row is not for storing keccak hi/lo byte cells. This is because on these rows we accumulate Keccak input.
- `q_keccak`: Selector Column. This selector is enabled at the row for computing keccak hash. This happens when the `rpi_bytes` column is at the row (1) after all `data_bytes` fields are assigned; (2) after all `pi_bytes` fields are assigned.
- `q_block_tag`: Fixed Column. This is to connect with the Block Table and is used to indicate that the current row is not the last row of the block table.
- `cum_num_txs`: Advice Column. This is used to record the cumulative number of transations;
- `is_block_num_txs`: Fixed Column. This is true when the current row corresponds to the block table tag is `NumTxs`.


## Constraints

- correct accumulation of `rpi_bytes_acc` when `q_field_step==1`
    - when `is_field_rlc==true`: `rpi_bytes_acc` accumulates `rpi_bytes` in RLC manner using evm word randomness 
    - when `is_field_rlc==false`: `rpi_bytes_acc` accumulates `rpi_bytes` in LC manner using coefficient `BYTE_POW_BASE=256` 

- correct accumulation of `rpi_rlc_acc` when `q_not_end` is enabled:
    - when `is_rpi_padding` is false: `rpi_rlc_acc` accumulates `rpi_bytes` in an RLC manner using `keccak_input` randomness
    - when `is_rpi_padding` is true: `rpi_rlc_acc` keeps the same

- correct accumulation of `rpi_length` when `q_not_end` is enabled
    - when `is_rpi_padding` is false: `rpi_length` increase by 1
    - when `is_rpi_padding` is true: `rpi_length` keeps the same

- constraints for padding 
    - in block context: `q_block_context` is true:
        - `is_rpi_padding` is Boolean
        - when `q_block_context` is true at the next row and `is_rpi_padding` is true at the current row, then `is_rpi_padding` is true at the next row
        - `real_rpi == not(is_rpi_padding) * rpi`
    - in tx_hash: `q_tx_hashes` is true
        - `is_rpi_padding` is Boolean
        - when `q_tx_hashes` is true at the next row and `is_rpi_padding` is true at the current row, then `is_rpi_padding` is true at the next row
        - `rpi` is RLC of dummy_tx_hash in bytes using `evm_word` randomness when `is_rpi_padding` is true.

- lookup to keccak table for `keccak(rpi)` when `q_keccak==1`
    - lookup item `q_keccak * (1, rpi, rpi_length_acc, rpi_rlc_acc)` into keccak table for `(is_final, input_rlc, input_length, output_rlc)`

- constraints for the block table: when `q_block_tag` is enabled 
    - for the first row, `cum_num_txs` is 0
    - when `is_block_num_txs` is true, increase `cum_num_txs` at the next row by `num_txs` in the block, which is fetched from block table; else do not increase

- copy constraints: 
    - inside PI circuit: this is mainly to constrain certain cells are equal due to the design of PI circuit columns. This includes
        - copy RLC of `data_bytes`/`pi_bytes` from `rpi_rlc_acc` column to `rpi` column when the latter has `q_keccak==1`
        - copy RLC of `data_hash` from `rpi_rlc_acc` column to `rpi` column when the latter has `q_keccak==1`
        - copy RLC of `pi_hash` from `rpi_rlc_acc` column to itself
        - within a data field
            - rpi_cells are equal
            - rpi_cell equals to the last `rpi_bytes_acc`
            - the first `rpi_bytes_acc` equals to the first byte_cell
    - copy block context fields, chain_id, coinbase, difficulty to block table
    - copy tx_hashes, chain_id, coinbase, difficulty to tx table