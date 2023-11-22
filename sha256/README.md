# SHA256 Circuit with lookup table

This circuit use a forking of `table16` in `halo2-gadget`, with some patches:

+ Make all code generic for `Field` trait so it also work with `bn254` curve
+ Fix the digest exporting part, output correct digest (the final state ⊕ init state) with correct constraint (rows for 512-bit block increased from **2102** -> **2114**)

The witness in table16 is then exported to an extra region so the rlc of input and digest can be calculated and form the lookup table for SHA256 precompile in zkevm-circuit. To achieve this, we have induced several cols and assigned them with two region: `input` and `digest`. As following table shows:


input region:

|          | inherit_s_finaal |           |inherit_counter|iitnher_rlc|        |             |         |inherit_padding  |padding_size|
|----------|------------------|-----------|-----------|-----------|------------|-------------|---------|-----------------|------------|
|s_begin   | s_final (0 or 1) |           |0/inherit_cnt|0/inherit_rlc|        |             | s_output|0/inherit_padding|            |
|s_enable  | s_final (cont.)  | s_u16 (1) | counter   | bytes_rlc | trans_byte | copied_data | 0       |padding          |            |
|s_enable  | s_final (cont.)  | s_u16 (0) |           | bytes_rlc | trans_byte |             | 0       |padding          |            |
|....      |
|s_last    | s_final (cont.)  | s_u16 (0) | counter   | bytes_rlc |            |             |         |padding          |bit_size    |


digest region:

|          | input s_final    | bytes     |    0      |           |            |             | s_output|   1       |
|----------|------------------|-----------|-----------|-----------|------------|-------------|---------|-----------|
|s_enable  | s_final (cont.)  | s_u16 (1) | counter   | bytes_rlc | trans_byte | copied_data | init_iv |padding (fixed 1)|
|s_enable  | s_final (cont.)  | s_u16 (0) |           | bytes_rlc | trans_byte | export_state| 0       |
|....      |
|          | s_final (cont.)  | s_u16 (0) |           | hash_rlc  |            | inher_input_rlc| 1 ... | 



Each input region catch a 512-bit block, in the form of 16x 32bit integers assigned in cells inside the `message schedule` region of table16. The cells in last row (enabled by `s_last` selector) would be connected by equality constraint to the first row of next input region for the next 512-bit block. cells in the `s_final` col is identify to be 0 or 1 in the same input region.

The last row of `input region` is constrainted equal to the first row in digest region