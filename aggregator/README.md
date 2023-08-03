Proof Aggregation
-----

![Architecture](./figures/architecture.jpg)
<!-- 
This repo does proof aggregations for zkEVM proofs.

## zkEVM circuit
A zkEVM circuits generates a ZK proof for a chunk of blocks. It takes 64 field elements as its public input, consist of 
- chunk's data hash digest: each byte is encoded in an Fr element
- chunk's public input hash digest: each byte is encoded in an Fr element
The total size for a public input is 64 bytes, encoded in 64 Fr element

For the ease of testing, this repo implements a `MockCircuit` which hash same public input APIs as a zkEVM circuit. 

## First compression circuit
The first compression circuit takes in a fresh snark proof and generates a new (potentially small) snark proof. 
The public inputs to the new snark proof consists of 
- 12 elements from the accumulators
    - an accumulator consists of 2 G1 elements, which are the left and right inputs to the pairing
    - this is treated as 4 Fq elements, each decomposed into 3 limbs and encoded in Fr  
- 64 elements from previous snark
    - re-expose the same public inputs as the original snark

The first compression circuit is configured [wide config file](./configs/compression_wide.config).

## Second compression circuit

The second compression circuit takes in a compressed snark proof and generates a new (potentially small) snark proof. 
The public inputs to the new snark proof consists of 
- 12 elements from the accumulators
    - an accumulator consists of 2 G1 elements, which are the left and right inputs to the pairing
    - this is treated as 4 Fq elements, each decomposed into 3 limbs and encoded in Fr  
    - accumulator from the previous snark is accumulated into the current accumulator
- 64 elements from previous snark
    - skipping the first 12 elements which are previous accumulator, as they are already accumulated
    - re-expose the rest 64 field elements as the public inputs 

The second compression circuit is configured [thin config file](./configs/compression_thin.config).

## Aggregation circuit
An aggregation circuit takes in a batch of `k` proofs, each for a chunk of blocks. 
It generates a single proof asserting the validity of all the proofs. 

It also performs public input aggregation, i.e., reducing the `64k` public elements  into a fixed number of `144` elements:
- 12 elements from accumulators, which accumulates all the previous `k` accumulators from each snark
- 132 elements from the hashes
    - first_chunk_prev_state_root: 32 Field elements
    - last_chunk_post_state_root: 32 Field elements
    - last_chunk_withdraw_root: 32 Field elements
    - batch_public_input_hash: 32 Field elements
    - chain_id: 8 Field elements

In addition, it attests that, for chunks indexed from `0` to `k-1`,
- batch_data_hash := keccak(chunk_0.data_hash || ... || chunk_k-1.data_hash) where chunk_i.data_hash is a public input to the i-th batch snark circuit
- chunk_pi_hash := keccak(chain_id || prev_state_root || post_state_root || withdraw_root || chunk_data_hash) where chunk_data_hash is a public input to the i-th batch snark circuit
- and the related field matches public input

See [public input aggregation](./src/proof_aggregation/public_input_aggregation.rs) for the details of public input aggregation. -->

<!-- # Spec for Dynamic aggregator -->

# Params
|param|meaning |
|:---:|:---|
|k | number of valid chunks|
|n | max number of chunks per batch|
|t | number of rounds for the final hash $\lceil32\times n/136\rceil$ |

Currently `n` is hard coded to `10`.
# Structs

## Chunk

A __chunk__ is a list of continuous blocks. It consists of 4 hashes:
- state root before this chunk
- state root after this chunk
- the withdraw root of this chunk
- the data hash of this chunk

Those 4 hashes are obtained from the caller.

The chunk's public input hash is 
```
chunk_pi_hash := keccak(chain_id || prev_state_root || post_state_root || withdraw_root ||  chunk_data_hash)
```

## Continuous chunks

A list of continuous chunks $c_1, \dots, c_k$ satisfy
```
c_i.post_state_root == c_{i+1}.prev_state_root
```
for $i \in [1, k-1]$.

## Empty chunk
An __empty chunk__ is a chunk that does not contain any transactions. It is used for padding. 
If $k< n$, $(n-k)$ empty chunks are padded to the list. An empty chunk has the same data fields as a real chunk, and the parameters are set as
- state root before this chunk: `c_k.post_state_root`
- state root after this chunk: `c_k.post_state_root`
- the withdraw root of this chunk: `c_k.withdraw_root`
- the data hash of this chunk: `keccak("")`

## Batch

A __batch__ consists of continuous chunks of size `n`. If the input chunks' size `k` is less than `n`, we pad the input with `(n-k)` empty chunks using the above logic.

# Circuits

## Chunk circuit

Circuit proving the relationship for a chunk is indeed the zkEVM circuit. It will go through 2 layers of compression circuit, and becomes a __snark__ struct. We do not list its details here. Abstractly, a snark circuit has the following properties:
- it takes 44 elements as public inputs 
    - 12 from accumulators
    - 32 from public input hash

## Empty chunk circuit
An empty chunk circuit also takes 44 elements as public inputs. 
In our design it is curial that __a same circuit__ is used for both real chunk circuit and empty chunk circuit. In other words, an empty chunk circuit will also  go through the same compressions before it is aggregated. 


![Architecture](./figures/hashes.jpg)

## Aggregation Circuit

We want to aggregate `k` snarks, each from a valid chunk. We generate `(n-k)` empty chunks, and obtain a total of `n` snarks. 

In the above example, we have `k = 2` valid chunks, and `2` empty chunks.

> Interlude: we just need to generate 1 empty snark, and the rest `n-k-1` will be identical for the same batch. We cannot pre-compute it though, as the witness `c_k.post_state_root` and `c_k.withdraw_root` are batch dependent.

### Configuration

There will be three configurations for Aggregation circuit.
- FpConfig; used for snark aggregation
- KeccakConfig: used to build keccak table
- RlcConfig: used to compute RLC of hash inputs

### Public Input
The public input of the aggregation circuit consists of
- 12 elements from accumulator
- 32 elements of `batch_pi_hash`
- 1 element of `k`

### Statements
For snarks $s_1,\dots,s_k,\dots, s_n$ the aggregation circuit argues the following statements.

1. batch_data_hash digest is reused for public input hash. __Static__.

2. batch_pi_hash used same roots as chunk_pi_hash. __Static__.
```
batch_pi_hash   := keccak(chain_id || chunk_1.prev_state_root || chunk_n.post_state_root || chunk_n.withdraw_root || batch_data_hash)
```
and `batch_pi_hash` matches public input.

3. batch_data_hash and chunk[i].pi_hash use a same chunk[i].data_hash when chunk[i] is not padded

```
for i in 1 ... __n__
    chunk_pi_hash   := keccak(chain_id || prev_state_root || post_state_root || withdraw_root || chunk_data_hash)
```

This is done by compute the RLCs of chunk[i]'s data_hash for `i=0..k`, and then check the RLC matches the one from the keccak table.

4. chunks are continuous: they are linked via the state roots. __Static__.

for i in 1 ... __n-1__
```
c_i.post_state_root == c_{i+1}.prev_state_root
```

5. All the chunks use a same chain id. __Static__.
```
for i in 1 ... __n__
    batch.chain_id == chunk[i].chain_id
```

6. The last `(n-k)` chunk[i]'s prev_state_root == post_state_root when chunk[i] is padded
```
for i in 1 ... n:
    is_padding = (i > k) // k is a public input
    if is_padding:
        chunk_i.prev_state_root == chunk_i.post_state_root 
        chunk_i.withdraw_root == chunk_{i-1}.withdraw_root
        chunk_i.data_hash == [0u8; 32]
```
7. chunk[i]'s data_hash len is `0` when chunk[i] is padded


### Handling dynamic inputs


![Dynamic_inputs](./figures/hash_table.jpg)


Our keccak table uses `2^19` rows. Each keccak round takes `300` rows. When the number of round is is less than $2^19/300$, the cell manager will fill in the rest of the rows with dummy hashes. 

The only hash that uses dynamic number of rounds is the last hash. 
Suppose we target for `MAX_AGG_SNARK = 10`. Then, the last hash function will take no more than `32 * 10 /136 = 3` rounds. 

We also know in the circuit if a chunk is an empty one or not. This is given by a flag `is_padding`. 

For the input of the final data hash
- we extract `32 * MAX_AGG_SNARK` number of cells (__static__ here) from the last hash. We then compute the RLC of those `32 * MAX_AGG_SNARK` when the corresponding `is_padding` is not set. We constraint this RLC matches the `data_rlc` from the keccak table.


For the output of the final data hash
- we extract all three hash digest cells from last 3 rounds. We then constraint that the actual data hash matches one of the three hash digest cells with proper flags defined as follows.

|#valid snarks | offset of data hash | flags|
|---| ---| ---|
|1,2,3,4       | 0                   | 1, 0, 0|
|5,6,7,8       | 32                  | 0, 1, 0   |
|9,10          | 64                  | 0, 0, 1|

Additional checks for dummy chunk
- if `is_padding` for `i`-th chunk, we constrain `chunk[i].prev_state_root = chunk[i].post_state_root`
- if `is_padding` for `i`-th chunk, we constrain `chunk[i-1].withdraw_root = chunk[i].withdraw_root`
- if `is_padding` for `i`-th chunk, we constrain `chunk[i-1].data_hash.len() == 0`

<!-- 
1. Extact the final `data_rlc` cell from each round. There are maximum $t$ of this, denoted by $r_1,\dots r_t$
    - __caveat__: will need to make sure the circuit is padded as if there are $t$ rounds, if the actual number of rounds is less than $t$. This is done by keccak table already: 
    all columns of keccak table are padded to `1<<LOG_DEGREE` by construction (__need to double check this is circuit dependent__)
2. Extract a challenge and then compute `rlc:= RLC(chunk_1.data_hash || ... || chunk_k.data_hash)` using a __phase 2__ column
3. assert `rlc` is valid via a lookup argument
    - constrain `rlc` cell is within the "data_rlc" column of keccak table via standard lookup API
    - potential optimization: avoid using lookup API. There is only $t$ elements as $rlc \in \{r_1,\dots r_t\}$ and we may check equality one by one.
 -->

<!-- 
Circuit witnesses:
- a list of k __real__ CHUNKs, each with 44 elements of public inputs (12 from accumulators and
32 from public input hash)
    - 
    - Those 4 hashes are obtained from the caller.
    - It's public input hash is 
        - chunk_pi_hash   := keccak(chain_id || prev_state_root || post_state_root || withdraw_root ||
            chunk_data_hash)
Circuit public inputs:
- an accumulator of 12 elements
- a batch public input hash of 32 elements
- the value k, 1 element

The aggregation circuit aggregates MAX_AGG_NUM snarks.
If k < MAX_AGG_NUM, dummy snarks will be padded -->
