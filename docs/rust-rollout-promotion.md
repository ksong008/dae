# Rust Rollout Promotion

This repo now has three local gate levels for the staged Rust runtime path:

1. `make rust-rollout-gate-local`
2. `make rust-rollout-chain-local`
3. `make rust-promotion-gate-local`

## Local gates

### `rust-rollout-gate-local`

Runs the `daerust` repo-local gate:

- Rust `dae-domain-matcher` test/build
- Rust `dae-sniffing` test/build
- tagged `rust_sniffing` lifecycle tests
- tagged Rust sniffing benchmarks
- tagged combined Rust DNS + Rust userspace routing integration test
- tagged combined `RouteDialTcp` benchmark
- tagged full-repo compile gate

### `rust-rollout-chain-local`

Runs the local three-repo chain:

- `daerust`
- `daewingrust`
- `daedrust`

The downstream repo paths are configurable through:

- `DAE_WING_REPO_DIR`
- `DAED_REPO_DIR`

Defaults are sibling checkouts:

- `../dae-wing`
- `../daed`

### `rust-promotion-gate-local`

Runs the full local chain gate and enforces benchmark thresholds:

- `BenchmarkRustHTTPHostInto <= 80 ns/op`, `0 B/op`, `0 allocs/op`
- `BenchmarkRustTLSSNIInto <= 65 ns/op`, `0 B/op`, `0 allocs/op`
- `BenchmarkRustQuicInitialSNIReuseScratch <= 1100 ns/op`, `0 B/op`, `0 allocs/op`
- `BenchmarkRustControlPlaneCombinedRouteDialTcp <= 900 ns/op`, `<= 400 B/op`, `<= 6 allocs/op`

## Remote workflow

The manual workflow `.github/workflows/daerust-promotion.yml` is the first remote-ready promotion entrypoint.

It checks out:

- `dae`
- `dae-wing`
- `daed`

Then it:

- prepares assets and eBPF artifacts in `dae`
- overlays the live `dae-wing` checkout into `daed/wing`
- rewrites `daed/wing/go.mod` to point at the checked-out `dae`
- runs `make rust-promotion-gate-local`

The `daed/wing` overlay is intentional. It lets the remote gate validate the live `daewingrust` checkout together with `daedrust`, instead of depending on a previously advanced submodule pointer.

There are also branch-specific workflows now:

- `.github/workflows/daerust.yml`
- `dae-wing/.github/workflows/daewingrust.yml`
- `daed/.github/workflows/daedrust.yml`

These are not reused from the older `daenew`, `daewing2.0`, or `daed2.0` lines. Each branch now has its own explicitly named workflow and gate surface.

## Promotion rule

The current staged Rust path is promotion-ready only when all of these are true:

1. `rust-promotion-gate-local` passes
2. the three-repo remote promotion workflow passes
3. no benchmark threshold regresses beyond the current scripted limits
4. the run still uses the intended downstream branches:
   - `daerust`
   - `daewingrust`
   - `daedrust`

Until then, the Rust runtime path remains explicit-rollout and validation-first, not default-on.
