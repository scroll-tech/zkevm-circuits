---
tags: scroll documentation
---

# MCOPY
mcopy opcode introduces in EIP5656(https://eips.ethereum.org/EIPS/eip-5656), which provides an efficient EVM instruction for copying memory areas. especially in the same call context. it pops three parameter `dst_offset`, `src_offset`, `length` from evm stack, copying memory slice [`src_offset`, `src_offset` + `length`] to destination memory slice [`dst_offset`, `dst_offset` + `length`].

below describle three parts that implemtation involves.
## buss mapping
  - TODO
  - 

## EVM circuit
  - TODO
  - TODO
  - 

## Copy Circuit
  - TODO
  - TODO



