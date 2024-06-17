---
tags: scroll documentation
---

# MCOPY
mcopy opcode introduces in EIP5656(https://eips.ethereum.org/EIPS/eip-5656), which provides an efficient EVM instruction for copying memory areas. 
it is in the same call context. it pops three parameters `dst_offset`, `src_offset`, `length` from evm stack, copying memory slice [`src_offset`, `src_offset` + `length`] to destination memory slice [`dst_offset`, `dst_offset` + `length`].
certainly it can also encounter some errors when execution like other opcodes.
the most complex copy case is destination copy range overlapping with source copy range. for example, `src_offset` = 0, `dst_offset` = 0x20, `length` = 0x40, 
source copy range is [0, 0x40], destination copy range is [0x20, 0x60], the overlapping range is [0x20, 0x40].
 
below describle three parts that implementation involves.
## buss mapping
  - generates stack read operations to get above mentioned parameters. `dst_offset`, `src_offset`, `length`.

  - generates copy event in helper `gen_copy_steps_for_memory_to_memory` because it is a dynamic copy case. the copy steps generating follows all read steps + all write steps pattern while normal existing copy steps follows read step + write step + read step + write step... pattern. this is to avoid copy range overlaps issue(destination copy range overlaps source copy range in the same memory context). copy event's `src_type` and `dst_type` are the same `CopyDataType::Memory`, copy event's `src_id` and `dst_id` are also the same since source and destination copy happens in one call context.

  - rw_counter of write steps start from half of total memory word count.

  - for the error cases, like OOG. if OOG happens, hit error type: `OogError::MemoryCopy`, evm circuit gadget will handle it. 


## EVM circuit
  - `MCopyGadget` is responsible for mcopy gadget constraints in evm circuit side. concrete constraints list as below
    - stack read lookups for `dst_offset`, `src_offset`, `length`
    - constrain memory source and destination address expansion correctly, this is by `MemoryExpansionGadget` sub gadget constructed with `memory_src_address` plus `memory_dest_address`.

    - constrain `memory_copier_gas` and total gas cost transition, for mcopy, there are both constant gas cost and dynamic gas cost.
    - lookup copy table when actual copy length > 0,copy circuit is responsible for validating copy table is set correctly. special case for  length == 0, the copy event resulting in rw counter increasing number (`copy_rwc_inc`) should be zero.

    - `memory_word_size` transition: memory expansion gadget calculates the greater `memory_word_size` (max(src_addr_expansion, dest_addr_expansion)) expansion and transition to it. 

    - other trivial constraint & state transition, refer to code  `MCopyGadget` gadget code details.


  - error cases:
    mcopy may encounter the following two error cases:
    - stack underflow:
      - if stack has less than three element will encounter this error. existing `ErrorStackGadget` gadget handles it. have set correct stack info for mcopy in helper `valid_stack_ptr_range`, which `ErrorStackGadget` takes use of it to do the constraint.

    - OOG memory copy:
      - there are two cases which result in this error: 1) remain gas left is indeed not sufficient. 2) source address(`src_add`) or destination address (`dst_address`) is u64 overflow.

      - `ErrorOOGMemoryCopyGadget` gadget is responsible for memory copy OOG cases, make OOG mcopy also take adantage of this gadget. 

      - specially for mcopy, besdies existing constraints in `ErrorOOGMemoryCopyGadget` gadget. added source address(`src_add`) overflow case for mcopy in OOG condition constraint.

      - added mcopy opcode in `ErrorOOGMemoryCopyGadget` gadget opcode list as well.


## Copy Circuit
  to support mcopy, copy circuit make some changes. here don't intend to describle how entire copy circuit works but only focus on changes regarding mcopy.
  - add new column `is_memory_copy`indicating if current event is mcopy(memory --> memory copy) case. constrain it is boolean type.

  - add new gadget `is_id_unchange` indicating if current row and next row have same id, in other words, checking src_id == dst_id. it is used for `is_memory_copy` constraint.
  - `rw_counter`
    - for non memory copy cases, remain the same: every consecutive two rows (read step + write step) increase rw_counter by 1 or 0.  

    - for memory copy cases, constrain rw_counter increasing or remain same every two steps( two consecutive read steps or write steps). the `rwc_inc_left[2] == rwc_inc_left[0] - rwc_diff`, rwc_diff can be 0 (not reach memory word end, rw_counter remain the same) or 1 (reach memory word end, rw_counter increase by 1).

    - rw_counter for write steps updated from half of total memory word count, since first half of all bytes are for reading ops.
    
    - rwc_inc_left has the similar updates as rw_counter.

  - constraint `is_memory_copy` value, `is_memory_copy` is always bool.  it is true only when src_id == dst_id and copy src_type == dst_type == `CopyDataType::Memory`

