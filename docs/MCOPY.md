---
tags: scroll documentation
---

# MCOPY
mcopy opcode introduces in EIP5656(https://eips.ethereum.org/EIPS/eip-5656), which provides an efficient EVM instruction for copying memory areas. especially in the same call context. it pops three parameter `dst_offset`, `src_offset`, `length` from evm stack, copying memory slice [`src_offset`, `src_offset` + `length`] to destination memory slice [`dst_offset`, `dst_offset` + `length`].

below describle three parts that implementation involves.
## buss mapping
  - generates stack read operations to get above mentioned parameters. `dst_offset`, `src_offset`, `length`.
  - generates copy event in helper `gen_copy_steps_for_memory_to_memory` because it is a dynamic copy case. the copy steps generating follows all read steps + all wrtie steps pattern while normal existing copy steps follows read step + write step + read step + write step... pattern. this is to avoid copy range overlaps issue(destination copy range overlaps source copy range in the same memory context). copy event's `src_type` and `dst_type` are the same `CopyDataType::Memory`, copy event's `src_id` and `dst_id` are also the same since source and destination copy happens in one call context.
  -  for the error cases, like OOG. if OOG happens, hit error type: `OogError::MemoryCopy`.

## EVM circuit
  - `MCopyGadget` is responsible for mcopy gadget constraints in evm circuit side. concrete constraints list as below
    - stack read lookups for `dst_offset`, `src_offset`, `length`
    - constrain memory source and destination address expansion correctly, this is by `MemoryExpansionGadget` sub gadget constructed with `memory_src_address` plus `memory_dest_address`.
    - constrain `memory_copier_gas` and total gas cost transition, for mcopy, there are both constant gas cost and dynamic gas cost.
    - lookup copy table when actual copy length > 0,copy circuit is responsible for validating copy table is set correctly. special case for  length == 0, the copy event resulting in rw counter increasing number (`copy_rwc_inc`) should be zero.
    - `memory_word_size` transition: memory expansion gadget calculates the greater `memory_word_size` (max(src_addr_expansion, dest_addr_expansion)) expansion and transition to it. 
    - other trivial constraint & state transition, refer to code  `MCopyGadget` gadget code details.


  - error case:
    mcopy may encouter the following two error cases:
    - stack underflow:
    - OOG memory copy:
    - todo


## Copy Circuit
  to support mcopy, copy circuit make some changes. here don't intend to describle how entire copy circuit works but only focus on changes regarding mcopy.
  - add new column `is_memory_copy`indicating if current event is mcopy(memory --> memory copy) case. constrain it is boolean type.
  - add new gadget `is_id_unchange` indicating if current row and next row have same id, in other words, checking src_id == dst_id. it is used for `is_memory_copy` constraint.
  - `rw_counter`
    - for non memory copy cases, remain the same. 
    - for memory copy cases, constrain rw_counter increasing or remain same every two steps( two consecutive read steps or write steps). the `rwc_inc_left[2] == rwc_inc_left[0] - rwc_diff`, rwc_diff can be 0 (not reach memory word end, rw_counter remain the same) or 1 (reach memory word end, rw_counter increase by 1).
  - constraint `is_memory_copy` value, `is_memory_copy` is always bool.  it is true only when src_id == dst_id and copy src_type == dst_type == `CopyDataType::Memory` 
  - TODO: 

