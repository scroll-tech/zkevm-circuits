---
tags: scroll documentation
---

# Sig Circuit

[Elliptic Curve Digital Signature Algorithm]: https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm

code: https://github.com/scroll-tech/zkevm-circuits/blob/develop/zkevm-circuits/src/sig_circuit.rs `develop` branch

## Ethereum's tx signature process

According to the [Elliptic Curve Digital Signature Algorithm] (ECDSA), the signatures `(r,s)` are calculated via ECDSA from `msg_hash` and a `public_key` using the formula

`(r,s)=ecdsa(msg_hash, public_key)`
 
The `public_key` is obtained from `private_key` by mapping the latter to an elliptic curve (EC) point. The `r` is the x-component of an EC point, and the same EC point's y-component will be used to determine the recovery id `v = y%2` (the parity of y). Given the signature `(v,r,s)`, the `public_key` can be recovered from `(v,r,s)` and `msg_hash` using `ecrecover`.

The above scheme is applied to the Ethereum protocol. Each EOA address has its own private key and the corresponding public key is obtained via EC mapping (Note: only EOA address can initiate a tx and contract address cannot, because contract address is not calculated from public key but from nonce and EOA address). For a tx, we have `msg_hash=keccak(RLP(tx's data that needs to be signed))`.  Since EOA account's address is created from from its public key via the formula `caller_address=keccak(public_key)[-20:]`, we can recover the caller address once we recover the public key. 

## SigTable and the Purpose of Sig Circuit

[SigTable](https://github.com/scroll-tech/zkevm-circuits/blob/cd6f44fee7873238f65fc402430a72956fae63b8/zkevm-circuits/src/table.rs#L2191) built inside zkevm-circuits is used to verify signatures. It has the following columns:
- `msg_hash_rlc`: Advice Column, Random-linear combination of the Keccak256 hash of the message that's signed;
- `sig_v`: Advice Column, the recovery id, it should be the parity of y;
- `sig_r_rlc`: Advice Column, RLC of the signature's `r` component;
- `sig_s_rlc`: Advice Column, RLC of the signature's `s` component;
- `recovered_addr`: Advice Column, the recovered address, i.e. the 20-bytes address that must have signed the message;
- `is_valid`: Advice Column, indicates whether or not the signature is valid or not upon signature verification.

The Sig Circuit aims at proving the correctness of SigTable. This mainly includes the following types of constraints:

- checking that the signature is obtained correctly. This is done by the ECDSA chip, and the correctness of `v` is checked separately;
- checking that `msg_hash` is obtained correctly from Keccak hash function. This is done by lookup to Keccak table from `rlc_column` with `q_keccak=1`;
- checking that all RLCs are obtained correctly. The RLC values (such as `msg_hash_rlc` etc.) will be stored in an advice column `rlc_column`. The correctness of RLCs will be checked by an RLC chip;
- checking that the overflowing CRT integer is decomposed correctly with 3 limbs, of sizes 88, 88, and 80 (in bits). This is applied to `msg_hash` and public key's EC coordinates.

## Architecture, Design and Constraints

`assign_ecdsa` method takes the signature data and uses ECDSA chip to verify its correctness. The verification result `sig_is_valid` will be returned. The recovery id `v` value will be computed and verified.

`sign_data_decomposition` method takes the signature data and the return values of `assign_ecdsa`, and returns the cells for byte decomposition of the keys and messages in the form of `SignDataDecomposed`. The latter consists of the following contents:
- `SignDataDecomposed`
    - `pk_hash_cells`: byte cells for keccak256 hash of public key;
    - `msg_hash_cells`: byte cells for `msg_hash`;
    - `pk_cells`: byte cells for the EC coordinates of public key;
    - `address`: RLC of `pk_hash` last 20 bytes;
    - `is_address_zero`: check if address is zero;
    - `r_cells`, `s_cells`: byte cells for signatures `r` and `s`.

During the process of sign data decomposition, checks of CRT integer decomposition into limbs of size `[88,88,80]` are done for `msg_hash` and public key's EC coordinates. 

The decomposed sign data are sent to `assign_sign_verify` method to compute and verify their RLC values and perform Keccak lookup checks. 
