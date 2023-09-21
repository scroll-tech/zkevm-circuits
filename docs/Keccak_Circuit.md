---
tags: scroll documentation
---

# Keccak Circuit

code: https://github.com/scroll-tech/zkevm-circuits/blob/develop/zkevm-circuits/src/keccak_circuit.rs `develop` branch

link to the original HackMD file: https://hackmd.io/@dieGzUCgSGmRZFQ7SDxXCA/H1vMF0_u2

[NIST Keccak Spec]: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf

[Keccak Team Keccak Spec]: https://keccak.team/files/Keccak-implementation-3.2.pdf

[Keccak256 Implementation]:
https://github.com/scroll-tech/zkevm-circuits/tree/scroll-stable/keccak256

[Keccak Circuit Original Spec]: https://hackmd.io/NaTuIvmaQCybaOYgd-DG1Q?view#Bit-implementation

[Keccak Circuit Implementation]: 
https://github.com/Brechtpd/zkevm-circuits/tree/keccak-playground/zkevm-circuits/src/keccak_circuit

[Additional Reference from Polygon]: https://polygon.technology/blog/zk-white-paper-efficient-zk-proofs-for-keccak


## The Keccak hash function

We shall first explain the Keccak hash function to be proved by our Keccak Circuit. This follows [NIST Keccak Spec], [Keccak Team Keccak Spec] and the [Keccak256 Implementation] in our codebase.

### Keccak-f permutation function

Any instance of the Keccak sponge function family makes use of one of the seven Keccak-f permutations, denoted Keccak-f[b], where $b \in \{25, 50, 100, 200, 400, 800, 1600\}$ is the width of the permutation. These Keccak-f permutations are iterated constructions consisting of a sequence of almost identical rounds. The number of rounds $n_r$ depends on the permutation width, and is given by $n_r = 12 + 2 \ell$, where $2^\ell = \dfrac{b}{25}$. 

We focus on Keccak-f[1600] which has $n_r=24$ rounds. At each round $1\leq k\leq n_r$, input are $5\times 5$ lanes of 64 bit words $A[x,y]$, where $[x,y]\in \{0,...,4\}\times \{0,...,4\}$ indicate the lane and the length of each lane is $64$-bit word. We then perform the following operations on $A[x,y]$:

- $\theta$-step:  
```math
\begin{array}{rl}
C[x]& =A[x,0]\oplus A[x,1]\oplus A[x,2] \oplus A[x,3]\oplus A[x,4] \ , \ x=0,...,4 \ ,
\\
D[x,z]& =C[x-1]\oplus \text{ROT}(C[x+1], 1) \ , \ x=0,...,4, \ , 
\\
A[x,y] & = A[x,y]\oplus D[x] \ , \ x=0,...,4, y=0,...,4, \ .
\end{array}
```

- $\rho$ and $\pi$-steps:  
$$B[y,2x+3y]=\text{ROT}(A[x,y], r[x,y]) \ , \ x=0,...,4, y=0,...,4 \ ,$$

- $\chi$-step:  
$$A[x,y]=B[x,y]\oplus ((\text{NOT} \ B[x+1,y]) \  \text{AND} \  B[x+2,y]) \ , \ x=0,...,4, y=0,...,4 \ ,$$

- $\iota$-step:
$$A[0,0]=A[0,0]\oplus RC[k] \ .$$

In the above all the operations on the indices are done modulo $5$. $A$ denotes the complete permutation state array and $A[x, y]$ denotes a particular lane in that state. $B[x, y]$, $C[x]$ and $D[x]$ are intermediate variables. The symbol $\oplus$ denotes the bitwise exclusive $\text{OR}$, $\text{NOT}$ the bitwise complement and $\text{AND}$ the bitwise AND operation. Finally, $\text{ROT}(W,r)$ denotes the bitwise cyclic (right) shift operation, moving bit at position $i$ into position $i + r$ (modulo the lane size).

Cyclic shift offset constants $r[x,y]$ are picked according to the following table

|$r(x,y)$| $x=3$ | $x=4$ | $x=0$ | $x=1$ | $x=2$|
|-|-|-|-|-|-|
| $y=2$ | 25 | 39 | 3  | 10 | 43 |
| $y=1$ | 55 | 20 | 36 | 44 | 6  |
| $y=0$ | 28 | 27 | 0  | 1  | 62 |
| $y=4$ | 56 | 14 | 18 | 2  | 61 |
| $y=3$ | 21 | 8  | 41 | 45 | 15 |

Round constants $RC[k]$ are also given, in hexiadecimal notion it looks like:

$$\begin{array}{ll}
RC[ 0] & \verb"0x0000000000000001" 
\\
RC[ 1] & \verb"0x0000000000008082" 
\\
RC[ 2] & \verb"0x800000000000808A" 
\\
RC[ 3] & \verb"0x8000000080008000" 
\\
RC[ 4] & \verb"0x000000000000808B" 
\\
RC[ 5] & \verb"0x0000000080000001" 
\\
RC[ 6] & \verb"0x8000000080008081" 
\\
RC[ 7] & \verb"0x8000000000008009" 
\\
RC[ 8] & \verb"0x000000000000008A" 
\\
RC[ 9] & \verb"0x0000000000000088" 
\\
RC[10] & \verb"0x0000000080008009" 
\\
RC[11] & \verb"0x000000008000000A" 
\\
RC[12] & 
\verb"0x000000008000808B"
\\
RC[13] & 
\verb"0x800000000000008B"
\\
RC[14] & 
\verb"0x8000000000008089"
\\
RC[15] & 
\verb"0x8000000000008003"
\\
RC[16] & 
\verb"0x8000000000008002"
\\
RC[17] & 
\verb"0x8000000000000080"
\\
RC[18] & 
\verb"0x000000000000800A"
\\
RC[19] & 
\verb"0x800000008000000A"
\\
RC[20] & 
\verb"0x8000000080008081"
\\
RC[21] & 
\verb"0x8000000000008080"
\\
RC[22] & 
\verb"0x0000000080000001"
\\
RC[23] & 
\verb"0x8000000080008008"
\end{array}$$

### Keccak sponge function

The final Keccak hash makes use of the sponge function, with arbitrary bit-length input and 256-bit output. Implemented using Padding, Absorb and Squeeze as below:

#### Padding
`NUM_WORDS_TO_ABSORB` = 17, `NUM_BYTES_PER_WORD` = 8, then `RATE` =  17 $\times$ 8 = 136. Since `NUM_BITS_PER_BYTE` = 8 , then `RATE_IN_BITS` = 17 $\times$ 8 $\times$ 8 = 1088. 

Given an input with length counted in bytes, compute `padding_total=RATE-input.len()%RATE`, this gives total number of padding bytes. Note that if input length in bytes is a multiple of `RATE`, the number of padding bytes is `RATE` but not 0. This means we always do padding. 

If the above `padding_total` is 1, then we pad a byte for $\verb"0x81"$; else pad a list of bytes $\verb"0x01", \verb"0x00", ..., \verb"0x00", \verb"0x80"$ with length in bytes equal to `padding_total`.

In terms of bits, if `padding_total` is 1, we pad $\overline{10000001}$ (which is 129 no matter what endian form we take); else we pad $\overline{00000001, 00000000, ..., 00000000, 10000000}$ with length in bytes equal to `padding_total`. Here the bit representations are understood in big-endian form, so $\overline{00000001}$ = 1, $\overline{10000000}$ = 128. In the Keccak Circuit codebase (see [here](https://github.com/scroll-tech/zkevm-circuits/blob/ba4f7fe610e920c173e2acf3c276e8d048b97854/zkevm-circuits/src/keccak_circuit/keccak_packed_multi.rs#L515)) we actually use little-endian bit representations, so instead we pad $\overline{10000000, 00000000, ..., 00000000, 00000001}$ with length in bytes equal to `padding_total`. Here $\overline{10000000}$ = 1, $\overline{00000001}$ = 128.

After padding, the input is extended to be with length in bytes a multiple of `RATE`, so in bits a multiple of `RATE_IN_BITS`. This result represented in bits is divided into chunks of size `RATE_IN_BITS`. 

#### Absorb

Following the result of padding represented in bits, in each chunk further divide this chunk into 17 sections with length 64 for each section. At the first chunk, initialize from all $A[i][j]=0$, then we perform the following absorb operation: for each of the first 17 words $A[i][j], i+5j<17$, we let $\verb"idx"=i+5j$ and we update
$$A[i][j] \leftarrow A[i][j]\oplus \verb"chunk[idx * 64..(idx + 1) * 64]"$$ to obtain output $A[i][j]$. We perform this absorb operation before the 24 rounds of Keccak-f permutation. Then the 24-rounds of Keccak-f permutation is followed to operate on all $A[i][j]$'s where $0\leq i, j\leq 4$. After that we move to next chunk and repeat this process starting from the output $A[i][j]$ from last iteration (absorb + permutation). Such iteration is continued until the final chunk (which may contain padding data).

#### Squeeze

At the end of the above absorb process, take $A[0][0], A[1][0], A[2][0], A[3][0]$ to form $4$ words, each word is $64$-bit. The Keccak hash output would then be the $256$-bit word
$$A[3][0] || A[2][0] || A[1][0] || A[0][0]$$


### Keccak Hash function Input and Output RLCs

#### input_rlc (data_rlc)
We are given the Keccak original input in bytes but without the padding bytes in the following order 
```math
\verb"bytes"_0, ..., \verb"bytes"_{n-1}
```
Then RLC using Keccak input $\verb"challenge"$ (which is after `FirstPhase`) to obtain

```math
\verb"input_rlc"=\verb"bytes"_{n-1}+\verb"bytes"_{n-2}*\verb"challenge"+...+\verb"bytes"_0 * \verb"challenge"^{n-1} \ .
```

In the Keccak Circuit, it corresponds to the column $\verb"data_rlc"$.


#### output_rlc (hash_rlc)
We are given the Keccak hash output being the $256$-bit word
$$A[3][0] || A[2][0] || A[1][0] || A[0][0] \ .$$
We divide each of above $4$ words into byte representation as $A[i][0]=\overline{A[i][0][7], ..., A[i][0][0]}$. This gives $32$ bytes $A[0][0][0..7]$, $A[1][0][0..7]$, $A[2][0][0..7]$, $A[3][0][0..7]$ for $i=0,1,2,3$. Then RLC using Keccak output $\verb"challenge"$ (= the challenge for evm word, i.e., after `FirstPhase`) to obtain $$\verb"ouput_rlc"=A[0][0][0]+A[0][0][1]*\verb"challenge"+...+A[3][0][7] * \verb"challenge"^{31} \ .$$
which is the output of Keccak hash's RLC that we use in our zkevm-circuits' Keccak table. In the Keccak Circuit, it corresponds to the column $\verb"hash_rlc"$.

## The Keccak table

The whole of zkevm-circuits at the level of super circuit uses the following structure of the Keccak table which contains the following 4 advice columns

- `is_final`: when true, it means that this row is the final part of a variable-length input extended with padding, so all Keccak rounds including absorb and permutation and squeeze are done, and the row's corresponding output is the hash result;
- `input_rlc`: each row takes one byte of the input, and add it to the previous row's `input_rlc` multiplied by the challenge for Keccak input. At the row for the last byte of the input (without padding, so `is_final` may not be true), this row is the `input_rlc` for the whole input. After that row, if there are padding rows until `is_final` becomes true, this `input_rlc` keeps the same;
- `input_len`: similarly to `input_rlc`, it adds up $8$ bits for each row until the last byte (without padding) which gives the actual input length in bytes;
- `output_rlc`: it is zero for all rows except the row corresponding to the last byte of input (with padding, so that `is_final` is true), where result is the `output_rlc` as we defined in the previous section. 


## Arithmetic for Packed Implementation

The multi-packed implementation for the Keccak Circuit uses special arithmetic called (Keccak) sparse-word-representation, this splits a 64-bit word into parts. 

Each bit in the sparse-word-representation holds `BIT_COUNT` (=3) number of 0/1 bits, so equivalent to `BIT_SIZE` (=8) as the base of bit in the sparse-word-representation.

A 64-bit word in sparse-word-representation can thus be expressed as a single field element since 64 x 3=192<254.

A `pack_table` indicates the relation between the standard bit-representation and the Keccak-sparse-word-representation, e.g. map 3 = $\overline{1100}$ (little-endian-form) to 9. This is done by `pack`. The reverse operation is `unpack`. So 
```math
\begin{array}{rl}
\verb"pack": & \overline{a_0a_1...a_{63}} \text{ (little endian)} \rightarrow a_0+a_1\cdot 8 +...+a_{63}\cdot 8^{63} \ ,
\\
\verb"unpack": & a_0+a_1\cdot 8+...+a_{63}\cdot 8^{63} \rightarrow \overline{a_0a_1...a_{63}} \text{ (little endian)} \ .
\end{array}
```
These operations have to go back-and-forth between input (to Keccak internal) and output (from Keccak internal).

It must be noticed that the packing related functions/modules `pack`, `unpack`, `into_bits`, `to_bytes` etc used inside Keccak Circuit are all in terms of little-endian order (in bits).

The underlying reason why we use these packing and unpacking operations is because of the simple fact that for two bit variables $x, y$ we have $x\oplus y=x+y\mod 2$. This means we can use simple addition then parity to build the Keccak Circuit arithmetic that constraints XOR operation. The pack-implementation helps to avoid carry to higher digits in the addition. The `BIT_SIZE` is chosen to be 8 because in the $\theta$-step we need 5 XOR operations so with the least number of bits >5 we must take 8 = $2^3$.

### `decode`

Each `part` has `num_bits` indicating how many bits it contains in a sparse-word-representation. Each bit holds a base of `BIT_SIZE` (=8). So if 
$$\verb#parts#=[\verb#part#[0],...,\verb#part#[n-1]]$$ in little-endian form then it decodes into a field element with decoded
$$\verb#value#=\sum\limits_{k=0}^{n-1}\left(\verb#part#[k].\verb#value#\right) \times \verb#BIT_SIZE#^{ \sum\limits_{i=0}^k \verb#part#[i].\verb#num_bits#} \ .$$

### `WordParts`

This is a util struict that returns a description of how a 64-bit word will be split into parts. If 
- `uniform` is true, then `target_sizes` consists of dividing 64 bit positions into even `part_size` plus a possible remainder; 
- `uniform` is false, then `target_sizes` consists of dividing both the `rot` (rotation) and (64-`rot`)-bit words into even `part_size` but named `part_a` and `part_b` plus a possible remainder for each. 

The parts splitted from the word is then determined bit-by-bit from `target_size`, so that each part will consist of a collection of bit positions that it represents, starting from 0-th bit position. The way bit positions are determined ensures that if

- `uniform` is true, then the remaining `rot`-sized bits [63-`rot`+1,...,63] are divided by `part_size` plus a remainder, and first 64-`rot` bits are determined by a section compensating previous remainder, plus divide by `part_size`, and plus the remainder from `target_size` division; 
- `uniform` is false, then the remaining `rot`-sized bits [63-`rot`+1,...,63] are divided by `part_size` plus remainder, and first 64-`rot` bits determined by `part_size` plus a remainder.

The way we do the above split when `uniform` is true enables an optimization shown below, where after rotation the front and tail remainders combined together becomes an inverval of length `part_size`:

![split_normalize_true](https://hackmd.io/_uploads/S1V-8qoKn.png)

Such a property is useful in `split_uniform`, because in that case it can use this specific partition to split an input word to parts and then rotation transform it to an input that will have the same partition layout as the output after rotation operation in Keccak permutations. This enables same input-output shape so that we can do lookup uniformly on input-output pairs without re-partition (`uniform_lookup = true`), i.e, splitting up the words into parts, then recombining and then splitting up again. This saves a significant amount of columns. 


### `split`

The module splits a $64$-bit word in sparse-word-representation into `parts` according to a given `part_size` using `Word_Parts` with `uniform=false`. Each `part` consists of a collection of connected bit positions (`bit_pos` from 0-63) that it represents, so it corresponds to a field element (done via `pack_part`).

$$\verb#part#.\verb#value#=\sum\limits_{i=0}^{\verb#part#.\verb#num_bits#} \verb#input#[i] \times \verb#BIT_SIZE#^{i} \ ,$$
where $\verb#input#[i]$ is the (sparse-word-representation) bit value of `input` at the $i$-th bit position given by `part`.


### `split_uniform`

The module splits a $64$-bit word in sparse-word-representation into `parts` according to a given `part_size` using `Word_Parts` with `uniform=true`. 

When this module is called, it will use `CellManager` to allocate a region to store the `input_parts`, which are to be the partition returned by `WordParts`. It then merges the splitted `part_size` interval that contains 0 into one part with size `part_size` in the `output_parts`, while stores the original splitted `input_parts` that are divided by 0 as two separate parts.

The returned parts from this module are the `output_parts`, which are used for inputs in uniform lookup to check relations constrained by Keccak-permutation operations that involve rotations, such as $\rho/\pi/\chi$ steps.

### `transform`

It calls `transform_to` module to bitwise transform values to cells using a function and constrain the input-output relation using a lookup table.


### `transform_to`

It bitwise transforms `input` expressed in `parts` to `output_parts` that are in cells using a function `f: fn(&u8) -> u8`. It constrains the input-output part relation using `transform_table`, i.e., the `(input_part, output_part)` must be found in `(transform_table[0], transform_table[1])`.


## Circuit Layout and Design

### Keccak specific CellManager

Circuit uses Keccak specific `CellManager`, which layouts advice columns in `SecondPhase`. They form a rectangular region of `Cell`'s. 

`CellManager.rows` records the current length of used cells at each row. New cells are queried and inserted at the row with shortest length of used cells. The `start_region()` method pads all rows to the same length according to the longest row, making sure all rows start at the same column. This is used when a new region is started to fill in witnesses.

It is worth to notice here that the Keccak specific `CellManager` behaves very differently from EVM Circuit's `CellManager` (see [here](https://github.com/scroll-tech/zkevm-circuits/blob/4686a078c64ca1f5482d7b43f3a94f4f7c9bd99f/zkevm-circuits/src/evm_circuit/util.rs#L342)), since the latter aligns new cells in a horizontal way instead of vertical. 

### Circuit Layout

Following this [link](https://docs.google.com/spreadsheets/d/1Pe5kkcWsD6Go3oDTey3GT0vpscxpCxzj4DglzWXF5zc/edit?usp=sharing) is a figure showing the Keccak Circuit layout.  This figure only shows a $24$ round of Keccak permutation. The actual Keccak circuit iteratively rolls this configuration for arbitrary-length input to do the hash. The most right region is the corresponding Keccak table.

Each row in the table is a `KeccakRow`, with the following items 

- `KeccakRow`:
    - `q_enable`: Fixed Column, bool; 
    - `q_first`: Fixed Column, bool, the first row;
    - `q_round`: Fixed Column, bool;
    - `q_absorb`: Fixed Column, bool, absorb row;
    - `q_round_last`: Fixed Column, bool, last round;
    - `q_padding`: Fixed Column, bool, selector of padding row;
    - `q_padding_last`: Fixed Column, bool, last padding row;
    - `round_cst`: Fixed Column, the round constant $RC[k]$;
    - `is_final`: bool, previous hash is done;
    - `Cell_Values`: values in cells which are used in Keccak Circuit's configuration, such as `absorb_fat`, `absorb_res`, `input_bytes`, etc.;
    - `length`: the actual input length in each round throwing away padding;
    - `data_rlc`: RLC of input data, after absorb;
    - `hash_rlc`: RLC of hash output, after squeeze;

The first round of rows must be initialized with dummy values, in particular, set `is_final` = false. 

In the current set-up, the number of rows that each round will occupy is `DEFAULT_KECCAK_ROWS = 12`. This means `CellManager` at each region aligns cells vertically to reach a height of 12 before it starts to align cells at the next consecutive column.

The number of columns consumed by each region (with different color in the figure) shown in the figure is just schematic. In reality this is determined by the size of data to be processed and the `part_size`, so that `CellManager` will insert each part into a cell and (vertically) align them.

### Spread input, absorb data and squeeze data along with the rounds of Keccak permutation in the circuit layout

Unlike the standard Keccak function, circuit spreads 17 absorb data and 4 squeeze data along with the 24 rounds of Keccak permutation. It uses selectors `q_absorb` and `q_round_last` to control absorb and squeeze data related constraints. In the figure the 4 squeeze data are attached at the end of diagram, but in reality this only happens at the last block of the input hash (with padding) so that squeeze will be applied (i.e. `is_final` is true), and then the final hash result will be obtained. However, each 24-round will record `squeeze_from_prev`, though they are only needed when the final hash result is obtained.

### Use of negative rotations in the circuit configuration

The Keccak circuit has to process variable length input which is divided into chunks, and for each chunk there will be allocated 24-rounds of Keccak permutation. So the Keccak Circuit configuration frequently uses negative rotations to fetch results from previous rounds (such as `squeeze_from_prev`). This of course cannot be done at the initial round, so in the witness generation function `multi_keccak` we will assign dummy first rows for 1 round (12 Keccak rows).

### Lookup tables used in Keccak internal and the number of lookup bits as part_size

The internal lookup tables in Keccak Circuit are used mainly in `transform` related modules. These tables include 
- `normalize_3`: [TableColumn; 2], parity normalize table with each bit in range $[0,2)$; 
- `normalize_4`: [TableColumn; 2],
parity normalize table with each bit in range $[0,4)$; 
- `normalize_6`: [TableColumn; 2],
parity normalize table with each bit in range $[0,6)$;
- `chi_base_table`:  [TableColumn; 2], for $\chi$-step lookup, $[0,1,1,0,0]$;
- `pack_table`: [TableColumn; 2], indicates the pack relation, i.e. 0..256 encoded as Keccak-sparse-word representation;

Since these tables can be used in multiple bits where each bit will do lookup according to the table, e.g. with number of bits equals `part_size`, Keccak Circuit needs to determine the optimal `part_size` for each table. This is done in the function `get_num_bits_per_lookup_impl`, which determines the maximum number of bits by the condition $$\verb"range"^{\verb"num_bits"+1}+\verb"num_unusable_rows"<=2^{\verb"KECCAK_DEGREE"}$$ Currently `KECCAK_DEGREE`=19.

### Number of KeccakRows needed for one hash

In some other circuits such as the [aggregation and compression circuits](https://github.com/scroll-tech/zkevm-circuits/tree/develop/aggregator), there is a need to exactly compute the number of rows consumed by one hash. This can be done by first compute the number of bytes in the input plus padding, and then divide into chunks of size `RATE`=136 bytes. The number of Keccak rows that each chunk will consume is equal to
$$\verb"DEFAULT_KECCAK_ROWS" * (1+\verb"NUM_ROUNDS")$$ 
and with the current setting `DEFAULT_KECCAK_ROWS=12`, `NUM_ROUNDS=24` this number will be 300. The number of chunks is determined by the input length plus padding and is equal to 
$$\verb"input.len()"/\verb"RATE" + 1$$
So total number of Keccak rows consumed by one hash is equal to the product of the two above.

## Constraints

### The normalize tables

`normalize_3`, `normalize_4`, `normalize_6` are normalization tables that are used to record the parity transformation of a sequence of bits with length `part_size` with each bit in `[0u64,...,range)` (`range`=3,4,6). Parity is taken as 0 for even and 1 for odd.

### State data

State data (used to be denoted as $A[x,y]$ in our section on Keccak-f permutation) before and after the Keccak-f permutation are stored in $s[i][j]$ and $s_{\text{next}}[i][j]$ for $0\leq i,j\leq 4$. Each $s[i][j]$ stands for a $64$-bit Keccak-sparse-word-representation (with bits stand for `[0,...,7]`).

### theta-step

Witnesses filled in a newly started region by `CellManager.start_region()`.

#### Constraints

First bitwise add 
$$c[i] = s[i][0] + s[i][1] + s[i][2] + s[i][3] + s[i][4] \ ,$$
to obtain $c=(c[0],...,c[4])$, so each $c[i]$ is 64-bit with each bit in `[0,5]` partitioned into parts with Keccak's `split` module with `rot`=1, then use `normalize_6` table to reduce it part by part to $\{0,1\}$ parity, denoted by $bc[i]$.  

After that, calculate
$$os[i][j]=s[i][j]+bc[(i+4)\mod 5]+\text{rot}(bc[(i+1)\mod 5], 1) $$ and set it to be the new state $s[i][j]$.

#### Rationale 
- <i>Soundness</i>: Use the symbols in the previous section on Keccak-f permutation function, it can be checked that $C[x]$ is the same as the parity of $A[x,0]+A[x,1]+...+A[x,4]$. So this is what $bc[i]$ checks at the `normalize_6` table lookup step. 
In a same rationale, $os[i][j]$ after normalization stands for the parity of $A[x,y]\oplus D[x]$. This normalization is postponed to $\rho/\pi$-step using `normalize_4` table lookup. 
- <i>Completeness</i>: Since $C[x]$ is the same as the parity of $A[x,0]+A[x,1]+...+A[x,4]$, any selection of witnesses that satisfy original $\theta$-step in the Section on Keccak-f permutation function will pass the constraints.

### rho/pi-step

Witnesses filled in a newly started region by `CellManager.start_region()`.

There are 3 consecutive regions for     `rho_pi_chi_cells`:
- `rho_pi_chi_cells[0]`: position $[j][2i+3j]$ is rotation of $s[i][j]$ by $r[i][j]$ (as in the $\rho/\pi$-step) saved as parts using `split_uniform` with `rot=r[i][j]`. Each 5-cells row counted as 1-column;
- `rho_pi_chi_cells[1]`: transform `rho_pi_chi_cells[0]` using normalize table `normalize_4`;
- `rho_pi_chi_cells[2]`: record the transform $3-2a+b-c$ used for $\chi$-step, will explain in that step.

#### Constraints 

Lookup in `normalize_4` table already gives a constraint. This is for the $os[i][j]$ step left in the $\theta$-step. Further, since `split_uniform` will combine small parts that are seperated by $0$, lookup to `normalize_4` of these small parts in a uniform way. 

#### Rationale

- <i>Soundness</i>: The `normalize_4` table lookup is used for the $os[i][j]$-parity check that is responsible for the $A[x,y]\oplus D[x]$ substep in the $\theta$-step. The other parts of this step are mostly to record values and do lookup range check. 
- <i>Completeness</i>: Same as $\theta$-step, using equivalence of $A[x,y]\oplus D[x]$ with parity of $A[x,y]+D[x]$.
 
### chi-step

Witnesses filled in a newly started region by `CellManager.start_region()`.

#### Constraints
Do $s[i][j]\oplus (\text{NOT } s[i+1 \mod 5][j] \text{ AND } s[i+2 \mod 5][j])$ by lookup table generated from $3a+2b-c\mapsto [0,1,1,0,0]$. The lookup result will be set to be the new $s[i][j]$.


#### Rationale 
- <i>Soundness</i>: We have

|$a$| $b$ | $c$ | $a\oplus (\text{NOT } b \text{ AND } c)$ | $3a+2b-c$| 
|-|-|-|-|-|
|1|1|1|1|1| 
|1|1|0|1|2|
|1|0|1|0|0| 
|1|0|0|1|1|
|0|1|1|0|3|
|0|1|0|0|4| 
|0|0|1|1|2| 
|0|0|0|0|0| 

So we lookup to table generated from mapping $[0,1,2,3,4]\mapsto [0,1,1,0,0]$. 

- <i>Completeness</i>: From the above table we see that any array of 0/1 bits $(a,b,c,d)$ that satisfy $a\oplus (\text{NOT } b \text{ AND } c)=d$ must satisfy the $3a+2b-c$ lookup table constraint. 

### iota-step

Witnesses filled in a newly started region by `CellManager.start_region()`.

#### Constraints

Do, for round $k$, the computation $s[0][0]+\verb"round_cst"[k] \ (RC[k])$ and lookup to `normalize_3` table.

#### Rationale
- <i>Soundness</i>: This is simply because the parity of $s[0][0]+\verb"round_cst"[k]$ gives the xor result $s[0][0]\oplus \verb"round_cst"[k]$.
- <i>Completeness</i>: Same as $\theta$-step, using equivalence of $s[0,0]\oplus \verb"round_cst"[k]$ with parity of $s[0,0]+\verb"round_cst"[k]$.

### Absorb

#### Constraints 
Verify the absorb data in parallel with each round of permutation, so in the first $17$ rounds each round absorb one word $A[i][j]$ indexed by $i+5j<17$, using $\verb"result"=\verb"state"+\verb"data"$ and then normalize to $\{0,1\}$ via `normalize_3` table.

#### Rationale
- <i>Soundness</i>: Clear from fact that $a\oplus b$ has the same parity as $a+b$ (i.e. normalize to $\{0,1\}$).
- <i>Completeness</i>: Same rationale.

### Squeeze and hash_rlc

#### Constraints 
When the previous hash is done: 
(1) Verify that the hash RLC result from `squeeze_from_prev` is the same as `hash_rlc`. 
(2) Verify that `squeeze_from_prev` are indeed filled in with the same values as state words $A[0][0], A[1][0], A[2][0], A[3][0]$ to squeeze.

The <b>Rationale</b> of above constraints are pretty straightforward 


### Padding

Use `length` to record the actual length of input bytes, and pad until total length is an integer multiple of `RATE_IN_BITS`. On padding rows set a padding selector `is_padding` to be $1$. 

#### Constraints 
(1) `is_padding` is boolean; 
(2) `is_padding` is zero on absorb row; 
(3) `is_padding` changes from 0 to 1 only once; 
(4) padding input byte starts with $1$ then followed by $0$ if this is not last padding input byte; 
(5) for last padding input byte, input bytes is $128$ (if not first padding, equals $\overline{00000001}$ in standard bits, little-endian-form) or $129$ (if is also first padding, equals $\overline{10000001}$ in standard bits, this means the only padding is $\overline{10000001}$). 

The <b>Rationale</b> of the above constraints are also straightforward following the definition of padding. Only one thing that needs to pay attention: Keccack internal uses byte representation together with Keccack-sparse-word-representation. 


### data_rlc

RLC uses keccak input $\verb"challenge"$ (same as evm_words challenge). 

Update `data_rlcs` on each of the $17$ rounds where we absorb data based on input bytes. At each round, produce a sequence of 
$$\verb"data_rlcs[0..NUM_BYTES_PER_WORD]",$$
with RLC iteration at each step
```math
\begin{array}{l} 
\verb"data_rlcs[NUM_BYTES_PER_WORD - (idx + 1)] " 
\\
\verb" = data_rlcs[NUM_BYTES_PER_WORD - idx] * challenge + byte_value"
\end{array}
```
and
$$\verb"data_rlcs[NUM_BYTES_PER_WORD]"=\verb"data_rlcs[0]"$$ which is previous round RLC result, initialized from $0$. This means after each round $\verb"data_rlcs[0]"$ contains the final RLC of input bytes up to this round. This is set to be the `data_rlc` of the current round, and it is passed to the next round so that after all 17 absorb rounds, we get the final `data_rlc` for the current chunk data. This is then passed to the next chunk until the last byte of input data, where `data_rlc` must exclude padding data. So in the final part of the input byte `data_rlc` will be equal to the corresponding `input_rlc` in the Keccak table.  
