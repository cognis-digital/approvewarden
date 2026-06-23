# Ports of approvewarden

The same approval-audit core, ported across languages so you can drop
approvewarden into any stack or ship a single static binary. Every port
implements the same pipeline as the Python reference:

1. load an approval export (JSON or CSV),
2. normalize + validate each record (address regex, amount sentinels),
3. classify the allowance (`zero` / `finite` / `effectively_infinite` /
   `infinite` / `blanket`),
4. score drainer exposure 0-100 with the identical weighting, and
5. emit an aggregate report with the same JSON shape and `risk_level`.

All ports are **offline** — they read a local file and print JSON. No network.

| Language | Path | Run | Test |
|---|---|---|---|
| Python (reference) | [`../approvewarden/`](../approvewarden) | `approvewarden scan demos/01-basic/approvals.json` | `pytest` |
| JavaScript / Node | [`javascript/`](javascript) | `node ports/javascript/index.js demos/01-basic/approvals.json` | `node ports/javascript/test.js` |
| Go | [`go/`](go) | `cd ports/go && go run . ../../demos/01-basic/approvals.json` | `go test ./...` |
| Rust | [`rust/`](rust) | `cd ports/rust && cargo run -- ../../demos/01-basic/approvals.json` | `cargo test` |

## Parity

Run against `demos/01-basic/approvals.json` (fixed `now = 1749340800`), every
port reports the same numbers:

```
risk_score=100  risk_level=critical  active=5  infinite/blanket=4  worst=BAYC
```

## CI

Each port is built and smoke-tested on every push by
[`.github/workflows/ports.yml`](../.github/workflows/ports.yml) — Go (`go vet` +
`go test` + build + demo run), Rust (`cargo test` + release build + demo run),
and Node (`test.js` + demo run). The JS and Rust suites are also runnable
locally with only Node and a Rust toolchain installed.

Contributions of additional ports (Ruby, C#, Bun, Deno, WASM) are welcome —
see [../CONTRIBUTING.md](../CONTRIBUTING.md).
