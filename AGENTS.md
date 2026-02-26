# AGENTS: bpb

Public repository for `bpb` commit-signing utilities.

## Core Commands

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets --all-features`
- `cargo test --workspace`

## Always Do

- Keep cryptographic behavior explicit and tested.
- Preserve compatibility of CLI behavior unless change is intentional.

## Ask First

- Keychain behavior changes.
- Any change to signing format output.

## Never Do

- Never log or expose private key material.
- Never weaken signature validation behavior.
