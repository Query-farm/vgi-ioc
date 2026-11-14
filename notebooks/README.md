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

## Run locally or in Colab

[Open in Colab](https://colab.research.google.com/github/Query-farm/vgi-ioc/blob/main/notebooks/01_count_report_support_not_mentions.ipynb)
and run all. Its bootstrap installs only the base
[shared package v0.3.9](https://github.com/Query-farm/vgi-example-notebooks/tree/v0.3.9).
The same package supplies the published catalog title/subtitle, canonical branding
and SVG presentation. Local publication uses its `[runner]` extra. This notebook
requires no local helper, fixture files or worker source: one notebook file is enough.

Install Git and [uv](https://docs.astral.sh/uv/). The initial run needs network access
for Python dependencies, the VGI extension and the native worker release. No Rust,
credentials or external intelligence service is needed. From `notebooks/`:

```sh
uv sync --locked
uv run --locked vgi-notebooks 01_count_report_support_not_mentions.ipynb --timeout 300
```

In an editor, select `notebooks/.venv/bin/python`, restart and run all. The runner
creates its own temporary kernel specification. Parameters, connection SQL and
analytical SQL remain visible; Python setup, plots and prose-generation source are
folded. GitHub renders linked SVG assets; Jupyter and Colab reruns show native SVG.

Run the focused experiment without replacing the saved default:

```sh
uv run --locked vgi-notebooks 01_count_report_support_not_mentions.ipynb \
  --parameters '{"MIN_REPORTS":2}' --output-dir artifacts/two-reports --timeout 300
```

Set the value to `4` for the empty-shortlist boundary. The supported range is an
integer from 1 to 6. Overrides require a separate output directory and unknown
parameter names are rejected. Failed execution preserves the last successful default.
Generated review PNGs, logs and experiment copies are ignored; linked chart SVGs and
successful default outputs are committed.

## Portable connection

```sql
INSTALL vgi FROM community;
LOAD vgi;
ATTACH 'ioc' (TYPE vgi,LOCATION 'github-auto://Query-farm/vgi-ioc@v0.4.0');
```

The extension selects the native platform asset, checks its release checksum and
caches it. Validation used macOS arm64. The shared SQL connection starts with an
empty temporary secret directory and persistent secrets disabled. The notebook's separate lock uses Haybarn 2.0.0rc11. Root Cargo manifests
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
the aggregation keys. A visible round-trip table compares all eight unique keys,
their defanged forms and `refang` restorations. The restoration preserves all eight
keys in this sample, without claiming arbitrary prose is reversible. Hash labels
are shortened only in the chart.

Eleven SQL checks plus one coverage reconciliation audit input size, NULL/empty
semantics, duplicate handling, type registry coverage, boolean recognition, counts
and the demonstrated display round-trip. The known false positives remain visible
despite those structural checks. Validation includes default execution, detached
two-report and empty-shortlist runs, chart review, runner guards and notebook lint.
Source checks build and test the current repository separately; notebook execution
uses the published native release.

## Coverage and validation

[coverage.json](coverage.json) maps meaningful visible executed SQL to all **13 of
13** public logical names in both released and current catalogs (the required
minimum is seven). Complete function/table/view exports are retained, including
explicit empty results. The `ioc_types` table and its function alias count once.
The notebook's header uses the exact released catalog title and subtitle.

The notebook executes native **v0.4.0**. Current public baseline
`9922a4d6d3b99db9b49b2ddf815dbd4b6eba58f9` exposes the same interface, with the documented
extraction fixes. Current catalog evidence uses its existing previously validated
native binary; no source rebuild is required. Reviewed current-interface coverage
is distinct from exact-current notebook execution. The release/current diagnostic
retains the differing rows rather than implying the released false positives are fixed.

Default, detached two-report and empty-shortlist executions pass, with eleven SQL
invariants and one coverage reconciliation. A fresh Python 3.12 kernel also ran the
entire notebook after base-only installation with pandas 2.2.3, Matplotlib 3.10.0,
IPython 8.30.0, ipykernel 6.17.1 and jupyter-client 7.4.9 preloaded. Their versions
remained unchanged, `pip check` passed, and no runner dependency was installed.
That is local compatibility testing, not a manual hosted-Colab claim.

The existing green [source CI baseline](https://github.com/Query-farm/vgi-ioc/actions/runs/43572702578)
is reused for this notebook-only change; worker source and Cargo dependencies are
unchanged. Earlier rollout validation passed 37 Rust tests, 68/74/68 SQL assertions
across stdio/HTTP/Unix, Clippy/format/Rustdoc and current-source executed metadata
at 100/100 L2 with zero findings. Those source suites were not repeated here.
The prior separate metadata run against the older released binary reported 82/100
L0 with 13 task-coverage warnings and no errors. The notebook does not claim its
metadata warnings or known extraction bugs have been fixed.

The worker is MIT licensed. Official unchanged branding links to
[Query.Farm](https://query.farm/) and [VGI](https://query.farm/vgi/).
