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
    - constrain memory source and destination address expansion correctly
    - 

## Copy Circuit
  - TODO
  - TODO



