# zkEVM contribution guidelines

Thank you for investing your time in contributing to our project! 

Before starting, we encourage you to take a look to the following documentation as it might help you in your first contribution adventure:
- https://github.com/privacy-scaling-explorations/zkevm-docs
- https://github.com/privacy-scaling-explorations/zkevm-specs

## General considerations
- Make atomic PRs. Focused on a single feature or topic. Don't mix different topics or issues in the same PR if it can be avoided.
- For PRs that change significantly the codebase or the way on which some procedure is done (test-suite, cross-crate structures, module refactors) please file an issue and wait until this feature/proposal gets approved by the repo maintainers.
- Don't set PRs as ready for review until they're not completed from the dev perspective and also are up-to-date with `main`/`master`. Also, if any changes are requested, bring back the PR to `Draft` until it's ready again with the aforementioned requirements.
- When a PR implements a behaviour that follows a different pattern than the current design, or introduces a new design, please make sure to explain the reasoning and logic behind it. In such cases it's always better if there's an issue where that pattern / new design has been discussed and an agreement has been reached about it.
- We require at least 2 review approvals for each PR, except for the cases where the PR is considered trivial, where 1 review approval is enough.
It's up to the maintainers to decide whether more than one review is required.
- Avoid requesting reviews of a PR in `zkevm-circuits` when the implementation follows a spec that is not yet in `master` at `zkevm-specs`.  In such case, set the `zkevm-circuits` PR as draft to signal you're working on it but it's not yet ready for review.
- Provide clear title and description of any PR and/or Issue you raise. That helps a lot to the reviewers/maintainers and other contributors to understand its scope and purpose.
- The author of the PR should be the one to merge their own PR after the required approvals.  Only when the author has no merge permission will a reviewer perform the merge.

## Opcodes

- When working on an opcode implementation, please make sure to follow this order
    1. If the spec is not written, write it and submit a PR in `zkevm-specs`
    2. After the spec is merged, implement the opcode and submit a PR in `zkevm-circuits`
        - It's OK to work on the circuit and spec at the same time and have the implementation PR submitted before the spec is merged, but in such case, please set the implementation PR as draft until the spec is merged.

- Try to include `bus-mapping` + `zkevm-circuits` opcode implementations in the same PR, but never mixing more than one Opcode at a time.
