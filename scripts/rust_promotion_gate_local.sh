#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ASSET_DIR="${DAE_LOCATION_ASSET:-$ROOT/.github/dae-assets}"
HTTP_MAX_NS="${RUST_HTTP_MAX_NS:-80}"
TLS_MAX_NS="${RUST_TLS_MAX_NS:-65}"
QUIC_MAX_NS="${RUST_QUIC_MAX_NS:-1100}"
ROUTE_MAX_NS="${RUST_ROUTE_MAX_NS:-900}"
ROUTE_MAX_B="${RUST_ROUTE_MAX_B:-400}"
ROUTE_MAX_ALLOCS="${RUST_ROUTE_MAX_ALLOCS:-6}"

check_benchmark() {
  local file="$1"
  local pattern="$2"
  local max_ns="$3"
  local max_b="$4"
  local max_allocs="$5"

  awk -v pattern="$pattern" -v max_ns="$max_ns" -v max_b="$max_b" -v max_allocs="$max_allocs" '
    $1 ~ pattern {
      count++
      for (i = 1; i <= NF; i++) {
        if ($i == "ns/op") ns = $(i-1) + 0
        if ($i == "B/op") b = $(i-1) + 0
        if ($i == "allocs/op") a = $(i-1) + 0
      }
      if (ns > worst_ns) worst_ns = ns
      if (b > worst_b) worst_b = b
      if (a > worst_allocs) worst_allocs = a
    }
    END {
      if (count == 0) {
        printf("benchmark %s not found in %s\n", pattern, FILENAME) > "/dev/stderr"
        exit 2
      }
      printf("checked %s: worst %.2f ns/op, %.0f B/op, %.0f allocs/op (limits %.2f / %.0f / %.0f)\n",
        pattern, worst_ns, worst_b, worst_allocs, max_ns, max_b, max_allocs)
      if (worst_ns > max_ns || worst_b > max_b || worst_allocs > max_allocs) {
        exit 1
      }
    }
  ' "$file"
}

cd "$ROOT"

PATH=/root/.local/go1.25.9/bin:$PATH DAE_LOCATION_ASSET="$ASSET_DIR" make rust-rollout-chain-local

sniff_bench="$(mktemp)"
route_bench="$(mktemp)"
trap 'rm -f "$sniff_bench" "$route_bench"' EXIT

PATH=/root/.local/go1.25.9/bin:$PATH \
DAE_LOCATION_ASSET="$ASSET_DIR" \
CGO_ENABLED=1 \
go test -tags='rust_sniffing' ./component/sniffing \
  -run '^$' \
  -bench 'Benchmark(RustQuicInitialSNIReuseScratch|RustHTTPHostInto|RustTLSSNIInto)$' \
  -benchmem -benchtime=500ms -count=3 | tee "$sniff_bench"

check_benchmark "$sniff_bench" '^BenchmarkRustHTTPHostInto-' "$HTTP_MAX_NS" 0 0
check_benchmark "$sniff_bench" '^BenchmarkRustTLSSNIInto-' "$TLS_MAX_NS" 0 0
check_benchmark "$sniff_bench" '^BenchmarkRustQuicInitialSNIReuseScratch-' "$QUIC_MAX_NS" 0 0

PATH=/root/.local/go1.25.9/bin:$PATH \
DAE_LOCATION_ASSET="$ASSET_DIR" \
CGO_ENABLED=1 \
go test -tags='rust_dns_request_matcher rust_userspace_routing' ./control \
  -run '^$' \
  -bench 'BenchmarkRustControlPlaneCombinedRouteDialTcp$' \
  -benchmem -benchtime=500ms -count=3 | tee "$route_bench"

check_benchmark "$route_bench" '^BenchmarkRustControlPlaneCombinedRouteDialTcp-' "$ROUTE_MAX_NS" "$ROUTE_MAX_B" "$ROUTE_MAX_ALLOCS"
