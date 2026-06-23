# Ports of shipcheck

The **Dockerfile linter** at the heart of shipcheck, ported across languages so
you can drop it into any stack or ship a single static binary. Every port parses
a Dockerfile (merging backslash continuations + multi-stage builds) and emits the
**same `SC###` finding codes** and JSON report shape as the Python reference.

| Language | Path | Run | Test |
|---|---|---|---|
| Python (reference) | `../shipcheck/` | `shipcheck lint Dockerfile` | `pytest` (from repo root) |
| Go | `go/` | `cd ports/go && go run . Dockerfile` | `go test ./...` |
| Rust | `rust/` | `cd ports/rust && cargo run -- Dockerfile` | `cargo test` |
| JavaScript / Node | `javascript/` | `node ports/javascript/index.js Dockerfile` | `node ports/javascript/index.test.js` |

Each port:

- accepts a Dockerfile path (defaults to `Dockerfile`),
- prints a JSON report (`tool`, `path`, `findings[]`, `max_severity`),
- exits non-zero when the worst finding is `>= medium`,
- ships a smoke test that asserts the same codes as the reference
  (`SC101/SC110/SC120/SC2xx/SC300/SC310`).

All four are built and tested on every push by
[`../.github/workflows/ports.yml`](../.github/workflows/ports.yml), so the ports
are verifiable even if a given toolchain isn't installed locally.

> Note: the **`vulnmatch` / `db` / `feeds`** subcommands (offline OSV CVE
> matching and the bundled 262k-vuln database) live only in the Python package —
> the ports mirror the `lint` surface.

Contributions of additional ports (Ruby, C#, Bun, Deno, WASM) are welcome — see ../CONTRIBUTING.md.
