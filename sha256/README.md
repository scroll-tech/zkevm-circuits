

input region:

|          | inher_s_finaal   |           |inher_counter|inher_rlc|            |             |         |inher_padding   |
|----------|------------------|-----------|-----------|-----------|------------|-------------|---------|----------------|
|s_begin   | s_final (0 or 1) |           |0/inher_cnt|0/inher_rlc|            |             | s_output|0/inher_padding |
|s_enable  | s_final (cont.)  | s_u16 (1) | counter   | bytes_rlc | trans_byte | copied_data | 0       |padding         |
|s_enable  | s_final (cont.)  | s_u16 (0) |           | bytes_rlc | trans_byte |             | 0       |padding         |





digest region:

|          | input s_final    | bytes     |    0      |           |            |             | s_output|   1       |
|----------|------------------|-----------|-----------|-----------|------------|-------------|---------|-----------|
|s_enable  | s_final (cont.)  | s_u16 (1) | counter   | bytes_rlc | trans_byte | copied_data | init_iv |padding (fixed 1)|
|s_enable  | s_final (cont.)  | s_u16 (0) |           | bytes_rlc | trans_byte | export_state| 0       |
|....      |
|          | s_final (cont.)  | s_u16 (0) |           | hash_rlc  |            | inher_input_rlc| 1 ... | 