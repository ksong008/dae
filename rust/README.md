# Rust Workspace

This workspace holds the staged Rust refactor for `dae`.

The first migration slice is `dae-domain-matcher`, which is intended to
replace the pure domain-matching logic behind the current Go routing and DNS
matchers before any runtime integration is attempted.

During the early migration phases, Rust crates here are expected to remain
detached from the active Go runtime path until parity tests and validation are
in place.

