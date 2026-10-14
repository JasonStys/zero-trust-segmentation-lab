# Coding and contribution rules

Author: Jason Stys.

Shallow source: ztlab runtime, scripts, tests, examples, docs and workflows. Python control plane, Bash lifecycle and nftables packet projection each have a distinct task. No unnecessary UI/framework dependency.

Every Python file has a purpose docstring; every function/class has a description. Immutable data, exact schemas and meaningful names make contracts self-documenting. Generated headers give exact physical lines for Python AST definitions/parameters/assignments/attributes, and lexical Bash/workflow declarations. Shell helpers have purpose comments. Generated nft exports include exact chain locations and per-rule peer names. JSON/locks are explained in README inventory/contracts.

Run formatting first, then `python scripts/code_map.py`. Stage only reviewed files, regenerate `python scripts/file_guide.py`, and run all checks. Never adjust oracles or weaken coverage to hide defects.

Runtime dependencies empty; full development graph hash-locked; action/scanner sources pinned. Ubuntu signed distribution packages provide native tools; record actual versions in evidence rather than claiming they are a portable pinned dataplane.

No private inputs, keys, proofs, generated artifacts, caches or billing data in Git. No pull_request_target or secret-bearing native tests. Keep privileged helpers outside runtime. Extending real identity or network tools requires a new architecture/security review and authorized environment.
