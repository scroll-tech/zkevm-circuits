---
tags: scroll documentation
---

# Tx Circuit

code: https://github.com/scroll-tech/zkevm-circuits/blob/develop/zkevm-circuits/src/tx_circuit.rs `develop` branch

[ETHTransactions]: https://ethereum.org/en/developers/docs/transactions/

[EIP2718]: https://eips.ethereum.org/EIPS/eip-2718

[EIP155]: https://eips.ethereum.org/EIPS/eip-155

[EIP1559]: https://eips.ethereum.org/EIPS/eip-1559

[EIP2930]: https://eips.ethereum.org/EIPS/eip-2930

[EllipticCurveDigitalSignatureAlgorithm]: https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm

[`TxFieldTag`]: https://github.com/scroll-tech/zkevm-circuits/blob/60d7a4bde24ce5e9d1260a3d27b5c1b4e153c0bf/zkevm-circuits/src/table.rs#L125

## Transactions

### Data in an Ethereum transaction

According to this document of [ETHTransactions], a submitted (legacy, [EIP2718] type `0x00`) transaction got recorded by the ethereum network will include the following data fields as information:
- `raw`: RLP encoded form of the tx `RLP([nonce, gasPrice, gasLimit, to, value, data, v, r, s])`;
- `nonce`: sequence number of tx;
- `gasPrice`: tx gas price per gas unit;
- `gasLimit`:  the maximum amount of gas units that can be consumed by the tx;
- `to`: callee address;
- `value`: amount of eth value (U256) to be transferred by the tx;
- `data`: CallData, this is used when tx creates a contract bytecode, in form of bytes and one row per byte;
- `v`, `r`, `s`: signature of the tx sender, `v` (U64) is the recovery id, `(r,s)` (U256, U256) is the ECDSA signature computed from [EllipticCurveDigitalSignatureAlgorithm] with specified message and key;
- `hash`: U256, Keccak-256 hash of the signed tx's data = `[Nonce, Gas, GasPrice, To, Value, CallData, v, r, s]`.

A transaction can be contract creation or message call. For contract creation, `to=0`. 

### Types of Transactions

Besides legacy transation, there are also other types of transactions such as [EIP155], [EIP2930] ([EIP2718] type `0x01`) and [EIP1559] ([EIP2718] type `0x02`). They differ by their details in tx information and their signing process. 

For example, in the above legacy transaction the ECDSA signature `(r,s)` is obtained by signing with message `RLP([nonce, gasprice, startgas, to, value, data])` and the private key of the EOA account that initiates this tx. In this case `v` is 27 or 28; instead, in EIP155 the sign message becomes `RLP([nonce, gasprice, startgas, to, value, data, chainid, 0, 0])` and `v` is `ChainID*2+35` or `ChainID*2+36`. 

In the tx circuit, we currently support the following 3 types of txs:
- `PreEip155`: legacy tx
- `Eip155`: as above EIP-155
- `L1Msg`: L1 message tx. This is not a tx type in the original Etherem protocol, but a tx type in which bridge contract users initiate deposit tx or invoke L2 contract txs. We follow [EIP2718] and use `0x7e` to stand for this tx type.

### Transactions data provided to the Tx Circuit

Besides the above transaction data, some metadata are also available for the tx circuit, which include:

- CallerAddress: this is recovered from the tx and its signature using `ecrecover`;
- IsCreate: bool, this is recovered by tx_tag being CalleeAddress and value at this row is none. This also relies upon the fact that IsCreate is next to CalleeAddress in the list of tx_tag ([`TxFieldTag`]);
- CallDataLength: provided by the smart contract;
- CallDataGasCost: U64, the gas cost of calldata;
- TxSignHash: U256, Keccak-256 hash of RLP tx's transaction data that needs to be signed =`[Nonce, Gas, GasPrice, To, Value, ChainID, CallData]`;

[Transaction](https://github.com/scroll-tech/zkevm-circuits/blob/60d7a4bde24ce5e9d1260a3d27b5c1b4e153c0bf/zkevm-circuits/src/witness/tx.rs#L39) is a data structure provided to zkevm-circuits that carries all necessary transaction information needed by the circuits as witnesses. [`TxFieldTag`] is the list of tx data fields that will be feed to the Tx Circuit.

### Use of Keccak256 hash and the tx signature process

In the Tx Circuit, there are two pieces of tx related data that will be applied the Keccak256 hash. They both correspond to some tx_tag fields ([`TxFieldTag`]):
- (`TxHashLength`, `TxHashRLC`, `TxHash`): signed tx's data = `[Nonce, Gas, GasPrice, To, Value, CallData, v, r, s]`. `TxHashLength` stands for the length in bytes of `RLP([signed tx's data])`; `TxHashRLC` stands for the RLC in bytes of signed tx's data and `TxHash=Keccak256(RLP(signed tx's data))`. `TxHash` becomes the `hash` data field in tx data; 
- (`TxSignLength`, `TxSignRLC`, `TxSignHash`): tx's data that needs to be signed = `[Nonce, Gas, GasPrice, To, Value, ChainID, CallData]`. `TxSignLenth` stands for the length in bytes of `RLP(tx's data that needs to be signed)`; `TxSignRLC` stands for the RLC in bytes of `RLP(tx's data that needs to be signed)` and  `TxSignHash=Keccak256(RLP(tx's data that needs to be signed))`. `TxSignHash` is the same as the `msg_hash` data field that will be used to obtain the tx sender's signature `(v,r,s)`.

According to the [EllipticCurveDigitalSignatureAlgorithm] (ECDSA), the signatures `(r,s)` are calculated via ECDSA from `msg_hash` and a `public_key`. In the case of an ethereum tx, the scheme looks as follows

`msg_hash=keccak(RLP(tx's data that needs to be signed))`

`(r,s)=ecdsa(msg_hash, public_key)`

The recovery id `v` is then computed from the parity of the `y` component of the EC point corresponding to `x` compnent being `r`. The `public_key` can be recovered from `(v,r,s)` and `msg_hash` using `ecrecover`, which further determines the caller address as `caller_address=keccak(public_key)[-20:]` (because this is the way account address is created, which is derived from its public key). Notice that only EOA address can initiate a tx and contract address cannot, because contract address is not calculated from public key but from nonce and EOA address. Also notice that EOA account's private key are elliptic-curve pre-images of public key and are thus hidden, while the public key can be calculated from the private key.

In the Tx Circuit, validation of correct signature is made through lookup to the sig table; validation of correct RLP is made through lookup to the RLP table; and validation of correct has is made through lookup to the Keccak table.


## The Purpose of Tx Circuit

Tx Circuit provides constraints that validates the correctness of a transaction. It mainly checks the following aspects of tx:
- correctness of `CallDataLength` and the accumulated `CallDataGasCost`: custom gates and lookup into tx table on the last row of tx's call data bytes;
- correctness of TxSign and TxHash related data: lookup into RLP table and Keccak table;
- correctness of `msg_hash` if `tx_type` is `L1Msg`: lookup to RLP table;
- tx signature via ECDSA done correctly and caller address recovered from ECDSA signature correctly: lookup to sig table;
- correct transition behavior of tx id, cum_num_txs and call_data_length etc. .
- some basic constraints such as boolean for some indicator variables etc. .


## Circuit Layout and Design

Each transaction's data fields except calldata are listed row-by-row according to tx_tag ([`TxFieldTag`]), then followed by padding txs. After that, each tx's variable-length calldata are listed byte-by-byte (one row per byte). This design of order is mainly because of variable length feature of tx's calldata.

Based on the corresponding tx_tag, lookup to different tables maybe triggered. Tx Circuit uses columns `LookupCondition::xx` to determine the kind of lookup if the current row needs to. 

Some boolean columns are used to reduce the degree of constraint system, such as `is_tag_block_num`, `is_calldata`, `is_caller_address`, `is_chain_id`, `is_l1_msg`.

### Columns

- `tx_type`: Advice Column. The type of tx, currently supports `PreEip155`, `Eip155`, `L1Msg`;
- `rlp_tag`: Advice Column. The associated rlp tag to lookup in the RLP table;
- `is_none`: Advice Column. This represents whether the tx_tag for the current row corresponds to value 0;
- `is_tag_block_num`: Advice Column. If tx_tag is `BlockNumber`;
- `is_calldata`: Advice Column. If tx_tag is `CallData`;
- `is_caller_address`: Advice Column. If tx_tag is `CallerAddress`;
- `is_l1_msg`: Advice Column. If `tx_type` is `L1Msg`;
- `is_chain_id`: Advice Column. If tx_tag is `ChainID`;
- `LookupCondition`
    - `TxCallData`: condition that enables lookup to tx table for CallDataLength and CallDataGasCost. This is enabled when tx_tag is `CallDataLength` and the latter has non-zero value;
    - `L1MsgHash`: condition that enables lookup to RLP table for message hashing of `tx_type = L1Msg`. This is enabled when `is_l1_msg==1` and tx_tag chosen among `Nonce, Gas, CalleeAddress, Value, CallDataRLC, CallerAddress, TxHashLength, TxHashRLC`;
    - `RlpSignTag`: condition that enables lookup to RLP table for signing in case `tx_type != L1Msg`;
    - `RlpHashTag`: condition that enables lookup to RLP table for message hashing of `tx_type != L1Msg`. This is enabled when `is_l1_msg==0` and tx_tag chosen among `Nonce, GasPrice, Gas, CalleeAddress, Value, CallDataRLC, TxDataGasCost, SigV, SigR, SigS, TxHashLength, TxHashRLC`;
    - `Keccak`: condition that enables lookup to Keccak table. This is enabled when tx_tag is `TxSignLength` (and `is_l1_msg==0`) or `TxHashLength`;
- `is_final`: Advice Column. Final part of assigning tx data is the CallData part;
- `call_data_gas_cost_acc`: Advice Column. Accumulated CallDataGasCost, starting to accumulate from the first CallDataByte. Otherwise None;
- `is_padding_tx`: Advice Column. If this row is for padding tx;
- `cum_num_txs`: Advice Column. The cumulative number of txs;
- `sv_address`: Advice Column. The sign-verified caller address recovered using `ecrecover`.

### Sub-Configurations

#### BinaryNumberChip
This chip helps to check the correct decomposition of a binary number into an array of bits. The number of advice columns used in this chip is set to be the desired number of bits. In Tx Circuit, this chip is applied to the following sub-configurations as `BinaryNumberConfig`:

- `tx_tag_bits`: number of bits is hard-coded as 5. This is to correspond to tx_tag ([`TxFieldTag`]);
- `tx_type_bits`: number of bits is hard-coded as 3. This is to correspond to tx_type.

#### IsZeroChip

This chip helps to check if a value is zero. It uses one advice column to store this value and another advice column for its inverse. In Tx Circuit, this chip is applied to the following sub-configurations as `IsZeroConfig`:
- `tx_id_is_zero`: this is used to check if `tx_id` is zero;
- `value_is_zero`: this is used to check if the `value` field for the current tx_tag is zero. This is applied when tx_tag is CallerAddress (if CallerAddress is zero, then skip sign verify); or is CallDataLenngth (if CallDataLength is zero, then skip lookup to tx table for call data); or is CallData (if CallData byte is zero, then gas cost is 4 otherwise 16).

#### IsEqualChip
This chip helps to check the equality of two values by storing their difference into `IsZeroChip`. In Tx Circuit, this chip is applied to the following sub-configurations as `IsEqualConfig`:
- `tx_id_unchanged`: to check if the current `tx_id` and next `tx_id` are the same.

#### ComparatorChip
This chip helps to compare two values and see if they are equal or one is less then the other. In Tx Circuit, this chip is applied to the following sub-configuration as `ComparatorConfig`:
- `tx_id_cmp_cum_num_txs`: compare `tx_id` and `cum_num_txs`.

### Lookup Tables

Tx Circuit connects various tables in zkevm-circuits due to the central role played by ethereum txs. These tables include [tx table](https://github.com/scroll-tech/zkevm-circuits/blob/60d7a4bde24ce5e9d1260a3d27b5c1b4e153c0bf/zkevm-circuits/src/table.rs#L193), [sig table](https://github.com/scroll-tech/zkevm-circuits/blob/60d7a4bde24ce5e9d1260a3d27b5c1b4e153c0bf/zkevm-circuits/src/table.rs#L2184), [block table](https://github.com/scroll-tech/zkevm-circuits/blob/60d7a4bde24ce5e9d1260a3d27b5c1b4e153c0bf/zkevm-circuits/src/table.rs#L1199), [RLP table](https://github.com/scroll-tech/zkevm-circuits/blob/60d7a4bde24ce5e9d1260a3d27b5c1b4e153c0bf/zkevm-circuits/src/table.rs#L2057) and [Keccak table](https://github.com/scroll-tech/zkevm-circuits/blob/60d7a4bde24ce5e9d1260a3d27b5c1b4e153c0bf/zkevm-circuits/src/table.rs#L1289).


### Circuit Layout

Assign an empty row first, then followed by each tx's data fields except calldata, one row per tx_tag. This is then followed by padding txs. After that, assign each tx's (not padding tx) variable length calldata in bytes with one row per byte and in the order of increasing tx_id. 

## Constraints

- basic constraints
    - `is_none` is boolean;
    - `tx_type` among `PreEip155`, `Eip155` and `L1Msg`;
    - `rlp_tag` is corresponding to tx_tag in a correct way (for some tx_tag the corresponding `rlp_tag` is none, for some other tx_tag this correspondence is just identical with possible name changes);
    - If CalleeAddress has value none, then IsCreate (next row) will be also none;
    - if `is_none` is true at current row, then value ==0;
    - if CallData is none, then both CallDataLength and CallDataGasCost must be none value; otherwise, CallDataLength must have non-zero value;
    - for L1Msg type tx, tx gas cost is 0.

- constraints for columns that are boolean indicators:
    - `is_call_data`, `is_caller_address`, `is_chain_id`, `is_tag_block_num`, `is_l1_msg` are boolean;
    - Conditions for each type of `LookupCondition::xx` imposed correctly in accordance with the way they are assigned.

- lookup to tx_table for CallData (LookupCondition::TxCallData)
    - triggered when tag is CallDataLength and CallDataLength is not 0;
    - Lookup tx table to validate call_data_gas_cost_acc;
    - Lookup tx table to validate last call data byte in tx has index = call_data_length-1 when the call data length is larger than 0.

- lookup to RLP table for tx_type when the latter is `L1Msg`, to check that the corrsponding hash format in RLP table is `L1MsgHash`.

- lookup to RLP table for signing (LookupCondition::RlpSignTag)
    - triggered when tx_tag is one of the following: Nonce, GasPrice, Gas, CalleeAddress, Value, CallDataRLC, TxSignLength, TxSignRLC;
    - Lookup RLP table to validate the value correspond to any of these tags with the corresponding sign format `TxSignPreEip155` (for `tx_type==PreEip155`) or `TxSignEip155` (for `tx_type==Eip155`).

- lookup to RLP table for hasing (LookupCondition::RlpHashTag and LookupCondition::L1MsgHash)
    - LookupCondition::RlpHashTag triggerd when tx_tag is one of the following: Nonce, GasPrice, Gas, CalleeAddress, Value, CallDataRLC, TxDataGasCost, SigV, SigR, SigS, TxHashLength, TxHashRLC;
    - LookupCondition::L1MsgHash triggerd when tx_tag is one of the following: Nonce, Gas, CalleeAddress, Value, CallDataRLC, CallerAddress, TxHashLength, TxHashRLC;
    - Lookup RLP table to validate the value correspond to any of these tags with the corresponding hash format `L1MsgHash`(for `tx_type==L1Msg`) or `TxHashPreEip155` (for `tx_type==PreEip155`) or `TxHashEip155` (for `tx_type==Eip155`).

- lookup to sig table for signature information `(msg_hash_rlc, v, r, s, sv_address)`
    - triggerd with tx_tag is ChainID and `is_l1_msg==false`;
    - lookup `(msg_hash_rlc=TxSignHash, v, r, s, sv_address)` to sig_table. `v` is determined based on `chain_id` and `ty_type` being `Eip155` or `PreEip155`.

- lookup to Keccak table for TxSign and TxHash data length and hash result (LookupCondition::Keccak)
    - triggered when tx_tag is TxSignLength (and `is_l1_msg==false`) or TxHashLength
    - Lookup Keccak table to validate the value correspond to TxSign or TxHash data input_rlc, input_length and output_rlc

- lookup to Block table for cum_num_txs
    - triggered when tx_tag is BlockNumber and the row is not padding row
    - Lookup Block table to validate the cum_num_txs is for the current block_num

- constraints for tx_id
    - `tx_id` transition, on rows where `is_calldata` is false: `tx_id` increase by 1 when the next tx_tag is Nonce, otherwise `tx_id` and `tx_type` remain unchanged
    - tx_id <= cum_num_txs
    - tx_id_next - tx_id in u16
    - tx_id changes on the final call data byte

- constraints for padding tx
    - when CallerAddress=0

- constraints for tx calldata bytes
    - is_final is bool
    - for any row that is not a final row (is_final = false)
        - index::next == index::cur + 1
        - tx_id::next == tx_id::cur
        - calldata_length::cur == calldata_length::next
        - calldata_gas_cost_acc::next == calldata_gas_cost::cur + gas_cost_next
    - for the final row (is_final = true)
        - calldata_length == index::cur + 1
        - tx_id changes

- constraints for ECDSA signature and CallerAddress
    - Lookup sig table for `(msg_hash_rlc, v, sig_r, sig_s, sv_address, 1)`. Recall that `msg_hash=Keccak256(RLP(TxSign))`, which is `TxSignHash` in tx_tag. This checks
        - ECDSA signature verified by the sign_verify chip
        - `sv_address` recovered from signed tx data using `ecrecover` for secp256k1 (`CallerAddress=keccak(recover_pk(v,r,s,msg_hash))[-20:]`). 
    - if `tx_type!=L1Msg`, then CallerAddress is the same as `sv_address`
    - constrain `v` based on `tx_type`: for `tx_type==Eip155`, `v=ChainID+35 or 36`, for `tx_type==PreEip155`, `v=27 or 28`, for `tx_type==L1Msg`, `v==0`

 