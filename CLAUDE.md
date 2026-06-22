# CLAUDE.md — vgi-ioc

Contributor/agent notes. User-facing docs live in `README.md`; this is the
"how it's built and where the sharp edges are" companion.

## What this is

A [VGI](https://query.farm) worker (Rust, compiled binary) exposing **IOC
(indicator-of-compromise) extraction and defang/refang** to DuckDB/SQL over
Arrow IPC. Built on the `vgi` crate (crates.io), modeled on `vgi-image` /
`vgi-barcode`. Catalog name `ioc` (single `main` schema). Pure text processing:
the only non-trivial deps are `regex` + `once_cell`. **Defensive CTI tool** — it
parses indicators out of reports; it does not generate attacks or touch the
network.

## Layout

```
Cargo.toml                          workspace; pins vgi = "0.5.0", regex, once_cell
crates/ioc-worker/
  src/main.rs                       Worker::new(); registers scalars + table fn
  src/ioc.rs                        PURE logic (no Arrow): defang/refang, extractors, classifiers + unit tests
  src/arrow_io.rs                   VARCHAR reads + LIST(VARCHAR) builder + in-process scalar test harness
  src/scalar/{fang,extract,classify,version,mod}.rs   thin Arrow scalar adapters
  src/table/{extract_iocs,mod}.rs   thin Arrow table-producer adapter
  tests/extract.rs                  integration tests (include ioc.rs by #[path], like vgi-barcode)
test/sql/*.test                     haybarn-unittest sqllogictest — authoritative E2E
Makefile                            test / test-unit / test-sql / lint / fmt / build / clean
```

Pattern: keep computation in `ioc.rs` (pure, unit-tested), keep Arrow
marshalling in `arrow_io.rs` + `scalar/*.rs` + `table/*.rs` (thin,
harness-tested).

## Refang-before-extract (the core design choice)

Reports defang indicators (`hxxp://evil[.]com`, `10[.]0[.]0[.]5`,
`bad[at]evil[.]com`). **Every extractor + `is_ioc` + `extract_iocs` runs
`refang` on a copy of the input before matching** so defanged indicators are
still found. Only `defang`/`refang` themselves skip this. See the module docs in
`ioc.rs`.

## False-positive policy

- URLs and e-mails "win" their host: a host already claimed by a URL/e-mail is
  not also emitted as a bare `domain` (avoids double-reporting in
  `extract_iocs`). `extract_domains` standalone still drops claimed hosts.
- Private/reserved IPs are kept (real indicators in a report).
- Domains require an alpha TLD (≥2 chars) — heuristic to avoid version strings.
- Input bounded to `MAX_INPUT_BYTES` (4 MiB), truncated at a char boundary.
  Never panics.

## Sharp edges (learned from the templates)

1. **`haybarn-unittest` skips `require vgi`** — `.test` files use explicit
   `statement ok` + `LOAD vgi;`. Functions live under the `ioc` catalog, so each
   file does `SET search_path = 'ioc.main'`, then `USE memory` before `DETACH`.
2. **Scalars are positional-only.** No optional args here; all our scalars are
   arity-1 (or 0 for `ioc_version`).
3. **Table functions take *constant* args, bound positionally** by the Rust SDK
   (no `name :=`). `extract_iocs('literal')` — read the const via
   `arguments.const_str(0)`.
4. **`LIST(VARCHAR)` returns** need the Arrow `DataType` to match between
   `on_bind` and `process`. We centralize this in
   `arrow_io::list_varchar_type()` / `list_varchar_builder()`: the element field
   is `Field::new("item", Utf8, true)` in BOTH the declared schema and the
   `ListBuilder`. A mismatch makes DuckDB reject the batch.
5. **NULL semantics:** scalar NULL in → NULL out; `extract_*` NULL in → NULL
   list (vs. empty list for "no matches"); `extract_iocs` NULL/empty → no rows.
6. **Determinism in SQL tests:** `extract_iocs` output is grouped by type but
   tests still `ORDER BY type, value` (or use `rowsort`) for stable comparison.

## Tests

- `cargo test --workspace` — `ioc.rs` unit tests (defang/refang round-trip,
  per-type extraction, overlap policy, hash_type, is_ioc, bounding) + the
  in-process Arrow-boundary tests in each `scalar/*.rs` + `tests/extract.rs`.
- `make test-sql` — the DuckDB E2E suite in `test/sql/*.test`.
