# Security and disclosure boundary

This repository is intentionally self-contained and public. It includes only
the fixed task contract, public observations, signatures, public keys, hashes,
test results, and certified exit.

It must never contain private keys, salts, sealed policy contents, environment
files, private examples, or undisclosed operating material. `.private/`, key
files, seed files, and environment files are excluded from version control. The
release audit fails if a protected filename is tracked.

Signatures prove control of a key and integrity of signed bytes. They do not by
themselves prove legal identity or factual truth.

Report vulnerabilities through this repository's GitHub Issues without
including secrets or private material.
