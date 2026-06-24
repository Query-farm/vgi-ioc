<p align="center">
  <img src="https://raw.githubusercontent.com/Query-farm/vgi/main/docs/vgi-logo.png" alt="Vector Gateway Interface (VGI)" width="320">
</p>

<p align="center"><em>A <a href="https://query.farm">Query.Farm</a> VGI worker for DuckDB.</em></p>

# Extract & Defang/Refang Threat Indicators (IOCs) in DuckDB

> **vgi-ioc** · a [Query.Farm](https://query.farm) VGI worker

A [VGI](https://query.farm) worker (Rust, a compiled binary) that brings
**cyber-threat indicator (IOC) extraction and defanging/refanging** to DuckDB /
SQL over Apache Arrow. DuckDB launches the worker and talks to it over Arrow
IPC; the functions appear under the catalog `ioc`, schema `main`.

This is a **defensive CTI tool**: it parses indicators out of free-text threat
reports (IPs, domains, URLs, e-mails, file hashes, CVEs) and converts between
their *live* and *defanged* (`hxxp://evil[.]com`) forms. It is pure text
processing — no network access, no native dependencies.

```sql
LOAD vgi;
ATTACH 'ioc' (TYPE vgi, LOCATION './target/release/ioc-worker');
SET search_path = 'ioc.main';

-- Make an indicator safe to paste into a report.
SELECT defang('http://evil.com/x');          -- → 'hxxp[://]evil[.]com/x'

-- Turn a defanged indicator back into live form.
SELECT refang('hxxp://evil[.]com');          -- → 'http://evil.com'

-- Pull indicators out of a (defanged) report. Extractors refang internally.
SELECT UNNEST(extract_ipv4('beacon from 10[.]0[.]0[.]5'));   -- → '10.0.0.5'
SELECT UNNEST(extract_cves('exploiting CVE-2024-1234'));     -- → 'CVE-2024-1234'

-- Classify a hash by length.
SELECT hash_type('d41d8cd98f00b204e9800998ecf8427e');        -- → 'md5'

-- Does this text contain any IOC?
SELECT is_ioc('CVE-2021-44228 in the logs');                 -- → true

-- Every distinct IOC as typed rows (table function).
SELECT type, value
FROM extract_iocs('beacon to hxxp://evil[.]com from 10[.]0[.]0[.]5')
ORDER BY type, value;
-- type | value
-- ipv4 | 10.0.0.5
-- url  | http://evil.com
```

## Functions

### Scalar

| Function | Returns | Description |
| --- | --- | --- |
| `defang(text)` | `VARCHAR` | Defang indicators: `http`→`hxxp`, `.`→`[.]`, `@`→`[at]`, `://`→`[://]`. |
| `refang(text)` | `VARCHAR` | Inverse of `defang` (recognizes common community conventions). |
| `extract_ipv4(text)` | `VARCHAR[]` | IPv4 addresses (private/reserved included). |
| `extract_ipv6(text)` | `VARCHAR[]` | IPv6 addresses (canonicalized). |
| `extract_domains(text)` | `VARCHAR[]` | Bare domains (URL/e-mail hosts excluded — see policy). |
| `extract_urls(text)` | `VARCHAR[]` | `http(s)://` / `ftp://` URLs. |
| `extract_emails(text)` | `VARCHAR[]` | E-mail addresses. |
| `extract_hashes(text)` | `VARCHAR[]` | MD5 / SHA1 / SHA256 file hashes. |
| `extract_cves(text)` | `VARCHAR[]` | CVE identifiers (`CVE-YYYY-NNNN+`). |
| `hash_type(s)` | `VARCHAR` | `'md5'` / `'sha1'` / `'sha256'` / `'sha512'` by length, else `NULL`. |
| `is_ioc(text)` | `BOOLEAN` | Whether the text contains **any** recognizable IOC. |
| `ioc_version()` | `VARCHAR` | Worker version string. |

### Table

| Function | Columns | Description |
| --- | --- | --- |
| `extract_iocs(text)` | `"type" VARCHAR, value VARCHAR` | One deduplicated row per IOC; `type` ∈ {ipv4, ipv6, url, email, domain, md5, sha1, sha256, sha512, cve}. |

> DuckDB table functions take **constant** arguments (no subqueries), so the
> `text` passed to `extract_iocs` must be a constant-foldable expression (a
> literal, or e.g. `defang('…')`). The per-type scalar `extract_*` functions
> operate on row columns and are the right choice for processing a table.

## Refang-before-extract

CTI reports defang indicators so they are safe to share, e.g.
`hxxp://evil[.]example[.]com/path`, `10[.]0[.]0[.]5`, `bad[at]evil[.]com`. A
naive extractor over the raw text would miss all of them.

**Every extractor and `is_ioc` / `extract_iocs` therefore runs `refang` on a
copy of the input first**, then matches real indicators. `defang` and `refang`
themselves are the only functions that do not refang first (they *are* the
fanging step). This means you can feed a raw defanged report straight to
`extract_ipv4(...)` / `extract_iocs(...)` and get live indicators back.

## False-positive policy

- **Overlap.** A bare domain that is already the host of an extracted URL or the
  domain part of an extracted e-mail is **not** also reported as a standalone
  `domain`. URLs and e-mails "win" their hosts, so `extract_iocs` never
  double-reports the same host under two types.
- **Private / reserved IPs are kept.** `10.x`, `192.168.x`, `127.0.0.1`, etc.
  are real indicators in a report (internal pivots, C2 on a compromised host).
  Filter them in SQL if you only want routable addresses.
- **TLD sanity.** A domain must end in an alphabetic TLD of length ≥ 2, which
  avoids matching most version strings and filenames. This is heuristic.
- **Input is bounded.** Each cell is scanned up to 4 MiB; longer text is
  truncated at a UTF-8 boundary before matching, so a pathological input cannot
  cause unbounded work. The worker never panics on any input.

## NULL handling

`NULL` text yields `NULL` (scalars) or no rows (`extract_iocs`). For the
`VARCHAR[]` extractors, `NULL` in → `NULL` list out; text with no matches → an
**empty** list (not `NULL`).

## Building & testing

```sh
cargo build --release            # produces target/release/ioc-worker
cargo test --workspace           # pure-Rust + Arrow-boundary unit/integration tests
make test-sql                    # DuckDB sqllogictest E2E (needs haybarn-unittest)
make lint                        # clippy -D warnings + rustfmt --check
```

The SQL E2E suite uses [`haybarn-unittest`](https://pypi.org/project/haybarn-unittest/)
(`uv tool install haybarn-unittest`).

## License

MIT © Query Farm LLC

---

## Authorship & License

Written by [Query.Farm](https://query.farm).

Copyright 2026 Query Farm LLC - https://query.farm

