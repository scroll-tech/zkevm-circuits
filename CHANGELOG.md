# Changelog
Unreleased

## [0.9.0] - 2023-09-xx
### Added
- Add `end_tx` flag to `StepState` to fix `EndTx` soundness.
- Add common proving functions from scroll-prover.
- Add prestate tracer to bus-mapping.
- Add inner-prove and chunk-prove features to testool.

### Changed
- Fix to add an empty string to default `CodeDB`.
- Fix to less than or equal to (`<=`) `NORMALIZED_ROW_LIMIT` (from `<`) in ccc.
- Fix ecdsa circuit binary selection bug.
- Fix ecrecover "address not recovered" case to be supported by `SigCircuit`.
- Fix keccak circuit's ccc need to consider first dummy chunk.
- Upgrade ethers from `0.17.0` to `2.0.7`.
- Upgrade mpt-circuits from `0.6.2` to `0.6.3`.

### Removed
no

\[Unreleased\]: https://github.com/scroll-tech/zkevm-circuits/releases/tag/v0.9.0...HEAD

\[0.9.0\]: https://github.com/scroll-tech/zkevm-circuits/releases/tag/v0.9.0
