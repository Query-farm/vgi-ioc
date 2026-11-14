# IOC notebooks

[01 · Count reports separately from repeated indicators](01_count_report_support_not_mentions.ipynb)
extracts typed candidates from six synthetic report rows, joins the worker's type
registry, and distinguishes repeated mentions, report–indicator pairs, and distinct
typed values. Two charts show count differences and a transparent report-coverage
shortlist. A separate release diagnostic exposes two false-positive domain tokens.

The default produces 13 report–indicator pairs and eight distinct typed candidates.
Changing `MIN_REPORTS` from 1 to 2 reduces the shortlist from eight to five without
changing the extracted population. The repeated IPv4 mention inside R1 contributes
one report–indicator row. R4's no-match text, R5's empty string and R6's missing text
remain separate, with a NULL candidate count for missing input.

## Run

Install [uv](https://docs.astral.sh/uv/). The initial run needs network access for
Python dependencies, the VGI extension and the native worker release. No Rust,
local worker binary, credentials or external intelligence service is needed.
Validation used macOS on Apple silicon and the native v0.4.0 release.

From the repository root:

```sh
uv sync --project notebooks --frozen
uv run --project notebooks --frozen python notebooks/execute.py
```

The complete `notebooks/` directory also runs independently:

```sh
cd notebooks
uv sync --frozen
uv run --frozen python execute.py
```

In an editor, select `notebooks/.venv/bin/python`, use `notebooks/` as the kernel
working directory, and restart/run all. Connection SQL, data and the parameter stay
visible. Import, plot, assertion and cleanup code is folded; useful outputs remain
visible. Charts use Seaborn styling and Matplotlib.

Run the one-parameter experiment without replacing the saved default:

```sh
uv run --project notebooks --frozen python notebooks/execute.py \
  --parameters '{"MIN_REPORTS":2}' \
  --output-dir notebooks/validation/two-reports
```

Set the value to 4 for the documented empty-shortlist boundary. The supported range
is an integer from 1 to 6. The runner starts a fresh kernel, rejects unknown parameters
and requires a separate output directory for overrides. It only replaces a saved
notebook after successful execution. Chart PNGs are written under ignored
`notebooks/validation/charts/` and embedded in the notebook.

## Portable connection

```sql
INSTALL vgi FROM community;
LOAD vgi;
ATTACH 'ioc' (TYPE vgi,LOCATION 'github-auto://Query-farm/vgi-ioc@v0.4.0');
```

The extension selects the native platform asset, checks its release checksum and
caches it. The notebook's separate lock uses Haybarn 2.0.0rc11. Root Cargo manifests
and lockfiles remain unchanged. After installation, extraction and defang/refang are
local text operations: no indicator is resolved, fetched, contacted or submitted.

## Interpretation and release limits

All report data is invented. Domains use `.test`, addresses include documentation
and private ranges, and the CVE-shaped token is illustrative rather than a verified
advisory. Hash classification recognizes hexadecimal form; it does not verify file
content. Extracted candidates are not evidence of compromise or maliciousness.

Every extractor refangs a copy of input before matching and deduplicates its returned
values per input. NULL lists and empty lists are distinct even though unnesting both
yields no rows. The notebook restores the original report population with a left
join and does not turn missing data into a known zero. Text is scanned only up to
4 MiB; these fixtures are checked to remain within that bound.

The scalar extractors accept columns. `extract_iocs` requires a constant argument;
the separate focused diagnostic uses a literal. URL/email hosts are excluded as
bare-domain candidates in the same input. However, v0.4.0 incorrectly emits
`tool.exe` from a URL path and `first.last` from an email local part as domains.
The notebook displays that behavior, separate from the shortlist population.
Repository revision `253bc0013d8baa5a5bb12a303d952032b1c14866` contains a later fix;
the released binary used here predates it. No source patch or local replacement
worker is hidden in the notebook.

The shortlist uses distinct supplied report IDs, preserving `(type, value)` keys
and report membership. It does not establish source independence, reputation or a
risk score. Defanged display strings are for presentation; exact typed values remain
the aggregation keys. Hash labels are shortened only in the chart.

Eleven SQL checks plus one coverage reconciliation audit input size, NULL/empty
semantics, duplicate handling, type registry coverage, boolean recognition, counts
and the demonstrated display round-trip. The known false positives remain visible
despite those structural checks. Validation includes default execution, detached
two-report and empty-shortlist runs, chart review, runner guards and notebook lint.
Source checks build and test the current repository separately; notebook execution
uses the published native release.

Current-source gates passed 37 Rust unit/integration tests, 68 stdio / 74 HTTP /
68 Unix SQL assertions across three cases per transport, Clippy/format/Rustdoc, and
executed metadata lint at 100/100 L2 with zero findings. A separate metadata run
against the older released binary reports 82/100 L0 with 13 existing task-coverage
warnings and no errors; it predates the source's published agent tasks. The notebook
does not claim that release metadata is clean or that its known extraction bugs are fixed.

The worker is MIT licensed. Official unmodified brand assets link to
[Query.Farm](https://query.farm/) and [VGI](https://query.farm/vgi/).
