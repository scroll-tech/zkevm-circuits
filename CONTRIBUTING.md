# zkEVM contribution guidelines

Thank you for investing your time in contributing to our project!

# How you can Contribute

First take a look at our [specs](https://github.com/privacy-scaling-explorations/zkevm-specs), [auditing videos](https://www.youtube.com/watch?v=HhHTho2QZa4), and [zkevm docs](https://github.com/privacy-scaling-explorations/zkevm-docs). It’s very important that you understand at a high-level how the ZK-EVM architecture and all of its components work.

## Best Coding Practices

### Creating PRs

1. Fork the zkevm or specs repos.
2. Write a simple markdown spec doc about the PR and send to the `zkevm-specs` repo.
    - ******************NOTE:****************** If the PR changes the circuit behavior, it is encouraged to reflect the changes in high level python ([here](https://github.com/privacy-scaling-explorations/zkevm-specs/tree/master/src/zkevm_specs)) and submit them along the same PR with the markdown spec to `zkevm-specs` repo.
3. We encourage everyone to [open an issue](https://github.com/privacy-scaling-explorations/zkevm-circuits/issues/new/choose) and wait until this feature/proposal gets approved by the repo maintainers before getting to work on a PR. However, this is a must for PRs that change significantly the codebase or the way on which some procedure is done (test-suite, cross-crate structures, module refactors).
4. Create a separate branch that will host all commits. Give branch names succinct title describing the change.
5. Start to make your changes. Please also make sure that the following commands pass if you have changed the code:
    
    ```
    make test
    make clippy
    ```
    
6. Once you made the changes, give the commit message a sufficient description of the change. The message content can be brief, including only enough details to summarize the purpose of the commit. In other instances, more in-depth explanations about how the commit accomplishes its goals are better suited as comments in the code.
    - ******************NOTE:****************** The commits in a pull request should be organized in a manner where each commit represents a small, coherent step towards the pull request's overall objective. The structure of the pull request should facilitate the reviewer in easily tracking and understanding each change made.
7. Send the circuit PR to the `zkevm-circuits` repo. Make sure you give a clear title and succinct description of the PR and the area you are changing. 
    - ******************NOTE:****************** Make atomic PRs. Focused on a single feature or topic. Don't mix different topics or issues in the same PR if it can be avoided.


[SUGGESTION] You may run into unnecessary commits, such as merge conflicts or minor refactorings. In that case, `git rebase -i`  and [squash](https://www.git-tower.com/learn/git/faq/git-squash) all your commits to one commit. 

[SUGGESTION] Rebase your branch on top of the latest main if your pull request branch is long-lived.

        
        ```
        git checkout main
        git pull
        git checkout my/branch
        git rebase main
        git push -f
        ```
        

### Submitting Bug Issues

1. If you identified a bug, please create a new issue or discuss it in our [forums](https://github.com/privacy-scaling-explorations/zkevm-circuits/discussions). 
2. In the description, provide the following:
    - Describe the bug
    - Concrete steps to reproduce the bug

See [this guide](https://stackoverflow.com/help/mcve) on how to create a minimal, complete, and verifiable example.

### Submitting Feature Issues

1. If you identified a feature, please create a new issue or discuss it in our forums. 
2. In the description, provide the following:
    - Describe the feature you would like
    - Additional context

### Adding Tests

If the change being proposed alters code, it is either adding new functionality to zkevm-circuits, or fixing existing, broken functionality. In both of these cases, the pull request should include one or more tests to ensure that zkevm-circuits does not regress in the future.

Types of tests include:

- **Unit tests**: Functions which have very specific tasks should be unit tested.
- **Integration tests**: For general purpose, far reaching functionality, integration tests should be added. The best way to add a new integration test is to look at existing ones and follow the style.

## General considerations

- When a PR implements a behaviour that follows a different pattern than the current design, or introduces a new design, please make sure to explain the reasoning and logic behind it. In such cases it's always better if there's an issue where that pattern / new design has been discussed and an agreement has been reached about it.
- We require at least 2 review approvals for each PR, except for the cases where the PR is considered trivial, where 1 review approval is enough. It's up to the maintainers to decide whether more than one review is required.
- Avoid requesting reviews of a PR in `zkevm-circuits` when the implementation follows a spec that is not yet in `master` at `zkevm-specs`. In such case, set the `zkevm-circuits` PR as draft to signal you're working on it but it's not yet ready for review.
- The author of the PR should be the one to merge their own PR after the required approvals. Only when the author has no merge permission will a reviewer perform the merge.

## Opcodes

- When working on an opcode implementation, please make sure to follow this order
    1. If the spec is not written, write it and submit a PR in `zkevm-specs`
    2. After the spec is merged, implement the opcode and submit a PR in `zkevm-circuits`
        - It's OK to work on the circuit and spec at the same time and have the implementation PR submitted before the spec is merged, but in such case, please set the implementation PR as draft until the spec is merged.
- Try to include `bus-mapping` + `zkevm-circuits` opcode implementations in the same PR, but never mixing more than one Opcode at a time.

## FAQs

Q: Do I need permissions on PSE org to create issues or PRs?

A: You don’t need permissions from PSE, can just create an issue or propose a PR and we will assign you issues or review/approve/merge PRs. 

Q: Is there a forum for discussing different issues or features where I can get started?

A: There’s the issues section in zkevm repos, but for more nuanced discussion join our [Github Discussions](https://github.com/privacy-scaling-explorations/zkevm-circuits/discussions) or [discord](https://discord.com/invite/sF5CT5rzrR).
