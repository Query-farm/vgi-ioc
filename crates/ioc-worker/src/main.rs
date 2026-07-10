//! The `ioc` VGI worker — defensive CTI tooling.
//!
//! A standalone binary that DuckDB launches and talks to over Apache Arrow IPC
//! (`ATTACH 'ioc' (TYPE vgi, LOCATION '…')`). It extracts and defangs/refangs
//! cyber-threat indicators of compromise (IOCs) from free text under the
//! catalog `ioc`, schema `main`:
//!
//! ```sql
//! ATTACH 'ioc' (TYPE vgi, LOCATION './target/release/ioc-worker');
//! SET search_path = 'ioc.main';
//!
//! SELECT defang('http://evil.com/x');             -- 'hxxp[://]evil[.]com/x'
//! SELECT refang('hxxp://evil[.]com');             -- 'http://evil.com'
//! SELECT UNNEST(extract_ipv4('hit 10[.]0[.]0[.]5')); -- '10.0.0.5'
//! SELECT hash_type('d41d8cd98f00b204e9800998ecf8427e'); -- 'md5'
//! SELECT is_ioc('CVE-2024-1234 found');           -- true
//! SELECT * FROM extract_iocs('beacon to hxxp://evil[.]com from 10[.]0[.]0[.]5');
//! ```
//!
//! Pure IOC logic (defang/refang, extraction, classification) lives in `ioc.rs`;
//! the `scalar/` and `table/` modules are thin Arrow adapters over it. All
//! extractors operate on a *refanged* copy of the input so defanged indicators
//! in reports are still extracted (see `ioc.rs` docs).

mod arrow_io;
mod ioc;
mod meta;
mod scalar;
mod table;

use vgi::catalog::{CatSchema, CatView, CatalogModel};
use vgi::Worker;

/// Worker version string, surfaced by `ioc_version()`.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Catalog + schema metadata (description, provenance) surfaced to DuckDB and
/// the `vgi-lint` metadata-quality linter. The function objects themselves are
/// served from the registered scalars/table; this only adds catalog/schema-level
/// comments and tags.
/// A browsable, credential-free reference view: the registry of indicator types
/// this worker recognizes and which function extracts each. Backed entirely by
/// an inline `VALUES` list, so scanning it needs no network, secret, or upstream
/// (clears VGI911) and gives an agent a real table to inspect before it has to
/// guess a function's arguments (clears VGI146).
fn ioc_types_view() -> CatView {
    // NOTE: keep this list in sync with the indicator kinds emitted by
    // `ioc::extract_iocs` (ipv4/ipv6/url/email/domain/md5/sha1/sha256/sha512/cve).
    let definition = "\
        SELECT * FROM (VALUES \
          ('ipv4', 'network', 'extract_ipv4', '10[.]0[.]0[.]5', \
           'IPv4 address; private and reserved ranges are kept because they are still real indicators in a report.'), \
          ('ipv6', 'network', 'extract_ipv6', '2001:db8::1', \
           'IPv6 address, canonicalized to its compressed form.'), \
          ('domain', 'network', 'extract_domains', 'evil[.]example[.]com', \
           'Bare domain name with an alphabetic TLD of at least two characters; hosts already claimed by a URL or e-mail are excluded.'), \
          ('url', 'network', 'extract_urls', 'hxxp://evil[.]com/x', \
           'Web URL, returned in live (refanged) form.'), \
          ('email', 'email', 'extract_emails', 'bad[at]evil[.]com', \
           'E-mail address, returned in live (refanged) form.'), \
          ('md5', 'hash', 'extract_hashes', 'd41d8cd98f00b204e9800998ecf8427e', \
           '32 hex-character MD5 file hash; label it with hash_type.'), \
          ('sha1', 'hash', 'extract_hashes', 'da39a3ee5e6b4b0d3255bfef95601890afd80709', \
           '40 hex-character SHA-1 file hash; label it with hash_type.'), \
          ('sha256', 'hash', 'extract_hashes', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', \
           '64 hex-character SHA-256 file hash; label it with hash_type.'), \
          ('sha512', 'hash', 'extract_hashes', 'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e', \
           '128 hex-character SHA-512 file hash; label it with hash_type.'), \
          ('cve', 'vulnerability', 'extract_cves', 'CVE-2024-1234', \
           'CVE identifier (Common Vulnerabilities and Exposures).') \
        ) AS t(name, kind, extractor, example, description)"
        .to_string();

    CatView {
        name: "ioc_types".to_string(),
        definition,
        comment: Some(
            "Registry of the indicator-of-compromise types this worker recognizes: for each \
             type, the group it belongs to, the function that extracts it, a defanged example, \
             and a one-line description."
                .to_string(),
        ),
        tags: vec![
            ("vgi.title".to_string(), "IOC Type Registry".to_string()),
            ("vgi.category".to_string(), "Reference".to_string()),
            // VGI123 classifying tags (bare keys) for faceting/navigation.
            ("domain".to_string(), "security".to_string()),
            ("topic".to_string(), "ioc-reference".to_string()),
            (
                "vgi.keywords".to_string(),
                r#"["ioc types","indicator types","registry","reference","catalog","ipv4","ipv6","domain","url","email","hash","cve","extractor","which function"]"#
                    .to_string(),
            ),
            (
                "vgi.doc_llm".to_string(),
                "A browsable reference table listing every indicator-of-compromise type this \
                 worker can recognize. Columns: `name` (the type, e.g. ipv4, sha256, cve), \
                 `kind` (a coarse group: network, email, hash, or vulnerability), `extractor` \
                 (the scalar function that pulls this type out of text, e.g. extract_ipv4), \
                 `example` (a short defanged sample value), and `description`. Query it to \
                 discover what the worker extracts and which function to call, before running \
                 the specific extractor or the all-in-one extract_iocs table function. Ten rows, \
                 one per type; no arguments, no network, always safe to scan."
                    .to_string(),
            ),
            (
                "vgi.doc_md".to_string(),
                "## `ioc_types` — indicator type registry\n\n\
                 A small, static reference table you can browse to see exactly which \
                 indicator-of-compromise types this worker recognizes and which function \
                 extracts each. Handy as a first stop before calling a specific extractor.\n\n\
                 | column | meaning |\n\
                 |---|---|\n\
                 | `name` | the indicator type — `ipv4`, `ipv6`, `domain`, `url`, `email`, `md5`, `sha1`, `sha256`, `sha512`, `cve` |\n\
                 | `kind` | coarse group: `network`, `email`, `hash`, or `vulnerability` |\n\
                 | `extractor` | the scalar function that pulls this type out of text |\n\
                 | `example` | a short defanged sample value |\n\
                 | `description` | one-line notes on how the type is matched |\n\n\
                 Ten rows, one per type. It is backed by an inline literal list, so scanning it \
                 needs no network or credentials. To pull every type out of a report at once, \
                 use the `extract_iocs` table function instead."
                    .to_string(),
            ),
            (
                "vgi.example_queries".to_string(),
                r#"[
  {
    "description": "List the network-layer indicator types and the function that extracts each.",
    "sql": "SELECT name, extractor FROM ioc.main.ioc_types WHERE kind = 'network' ORDER BY name"
  },
  {
    "description": "Count how many indicator types fall into each coarse group.",
    "sql": "SELECT kind, count(*) AS n_types FROM ioc.main.ioc_types GROUP BY kind ORDER BY kind"
  }
]"#
                .to_string(),
            ),
        ],
        column_comments: vec![
            (
                "name".to_string(),
                "The indicator type identifier (matches the `type` column emitted by extract_iocs)."
                    .to_string(),
            ),
            (
                "kind".to_string(),
                "Coarse group the type belongs to: network, email, hash, or vulnerability."
                    .to_string(),
            ),
            (
                "extractor".to_string(),
                "Name of the scalar function that extracts this indicator type from text."
                    .to_string(),
            ),
            (
                "example".to_string(),
                "A short, defanged example value of this indicator type.".to_string(),
            ),
            (
                "description".to_string(),
                "One-line notes on how this indicator type is matched.".to_string(),
            ),
        ],
    }
}

fn catalog_metadata(name: &str) -> CatalogModel {
    CatalogModel {
        name: name.to_string(),
        comment: Some(
            "Defensive CTI tooling: extract and defang/refang indicators of compromise (IOCs) \
             from free text."
                .to_string(),
        ),
        tags: vec![
            (
                "vgi.title".to_string(),
                "IOC Extraction & Defang/Refang".to_string(),
            ),
            (
                "vgi.keywords".to_string(),
                r#"["ioc","indicator of compromise","cyber threat intelligence","cti","defang","refang","extract","ipv4","ipv6","domain","url","email","hash","md5","sha1","sha256","sha512","cve","threat hunting","malware","security"]"#
                    .to_string(),
            ),
            (
                "vgi.doc_llm".to_string(),
                "Parse cyber-threat indicators of compromise (IOCs) out of free-text reports: \
                 IPv4/IPv6 addresses, domains, URLs, e-mail addresses, file hashes \
                 (md5/sha1/sha256/sha512) and CVE identifiers. Defang indicators to make them \
                 safe to share (http->hxxp, .->[.], @->[at]) and refang them back to live form, \
                 classify a hash by length, and test whether text contains any IOC. Every \
                 extractor refangs its input first, so indicators that were defanged in a report \
                 are still found. A purely defensive parsing tool — it reads indicators, it never \
                 generates attacks or touches the network."
                    .to_string(),
            ),
            (
                "vgi.doc_md".to_string(),
                "# IOC Extraction & Defang/Refang for DuckDB\n\n\
                 Pull indicators of compromise (IOCs) out of cyber-threat-intelligence (CTI) \
                 reports and defang or refang them with plain SQL — no Python notebook, regex \
                 cheat-sheet, or external service required. The `ioc` extension turns DuckDB into \
                 an IOC parser that recognizes IPv4 and IPv6 addresses, domains, URLs, e-mail \
                 addresses, file hashes (MD5, SHA-1, SHA-256, SHA-512) and CVE identifiers, and \
                 converts between live indicators (`http://evil.com`) and the *defanged* form \
                 (`hxxp[://]evil[.]com`) that analysts use to share malware artifacts safely. It \
                 is built for threat hunters, incident responders, SOC analysts and data engineers \
                 who already keep logs, alerts and reports in DuckDB and want indicator extraction \
                 to be just another column expression.\n\n\
                 This is a purely **defensive** tool: it reads and rewrites indicators that already \
                 exist in your text — it never generates attacks, resolves names, or touches the \
                 network. Extraction is powered by the Rust [`regex`](https://github.com/rust-lang/regex) \
                 crate ([documentation](https://docs.rs/regex/latest/regex/)), whose linear-time, \
                 backtracking-free engine matches large reports without catastrophic blowup. The \
                 worker is a standalone binary that DuckDB attaches over Apache Arrow IPC, so \
                 results stream back as native Arrow columns. A key design choice is \
                 *refang-before-extract*: every extractor (and `is_ioc` / `extract_iocs`) first \
                 refangs a copy of its input, so indicators that were defanged in a report — \
                 `10[.]0[.]0[.]5`, `bad[at]evil[.]com`, `hxxp://evil[.]com` — are still found. \
                 Only defanging and refanging themselves skip that step.\n\n\
                 Reach for it whenever indicators live inside free text rather than tidy columns: \
                 enriching an alerts or tickets table, building a watchlist from an incident \
                 report, sanitizing artifacts before sharing them, or joining extracted \
                 indicators against a threat feed. Attach it with \
                 `ATTACH 'ioc' (TYPE vgi, LOCATION '…')`, then browse the `main` schema to \
                 discover the available functions — each is categorized (extraction, \
                 defang/refang, classification) and carries its own worked examples. Source and \
                 issues live at [Query-farm/vgi-ioc](https://github.com/Query-farm/vgi-ioc); the \
                 worker is part of the VGI ecosystem from [Query Farm](https://query.farm)."
                    .to_string(),
            ),
            ("vgi.author".to_string(), "Query.Farm".to_string()),
            (
                "vgi.copyright".to_string(),
                "Copyright 2026 Query Farm LLC - https://query.farm".to_string(),
            ),
            ("vgi.license".to_string(), "MIT".to_string()),
            (
                "vgi.support_contact".to_string(),
                "https://github.com/Query-farm/vgi-ioc/issues".to_string(),
            ),
            (
                "vgi.support_policy_url".to_string(),
                "https://github.com/Query-farm/vgi-ioc/blob/main/README.md".to_string(),
            ),
            // VGI152: analyst tasks `vgi-lint simulate` uses to measure how well an
            // agent can actually drive this worker. Each reference_sql is
            // self-contained and runnable against an attached `ioc` worker.
            (
                "vgi.agent_test_tasks".to_string(),
                r#"[
  {
    "name": "extract-all-iocs",
    "prompt": "From the text 'beacon to hxxp://evil[.]com from 10[.]0[.]0[.]5', list every indicator of compromise, one indicator per row, with two columns: its type and its value.",
    "reference_sql": "SELECT type, value FROM ioc.main.extract_iocs('beacon to hxxp://evil[.]com from 10[.]0[.]0[.]5') ORDER BY type, value",
    "unordered": true,
    "ignore_column_names": true
  },
  {
    "name": "defang-url",
    "prompt": "Return a single value: the URL http://evil.com/x rewritten into its defanged, safe-to-share form (so it cannot be clicked when pasted into a report).",
    "reference_sql": "SELECT ioc.main.defang('http://evil.com/x') AS safe",
    "unordered": true,
    "ignore_column_names": true
  },
  {
    "name": "classify-hash",
    "prompt": "Return a single value naming the hash algorithm that produced the digest d41d8cd98f00b204e9800998ecf8427e.",
    "reference_sql": "SELECT ioc.main.hash_type('d41d8cd98f00b204e9800998ecf8427e') AS algorithm",
    "unordered": true,
    "ignore_column_names": true
  },
  {
    "name": "detect-ioc",
    "prompt": "Return a single boolean value that is true when the text 'exploiting CVE-2024-1234 in the wild' contains any indicator of compromise, and false otherwise.",
    "reference_sql": "SELECT ioc.main.is_ioc('exploiting CVE-2024-1234 in the wild') AS has_ioc",
    "unordered": true,
    "ignore_column_names": true
  },
  {
    "name": "extract-ipv4-from-defanged",
    "prompt": "From the defanged report 'callback from 10[.]0[.]0[.]5 and 192[.]168[.]1[.]1', return the IPv4 addresses one address per row (a single column of scalar address strings, not a list).",
    "reference_sql": "SELECT UNNEST(ioc.main.extract_ipv4('callback from 10[.]0[.]0[.]5 and 192[.]168[.]1[.]1')) AS ip ORDER BY ip",
    "unordered": true,
    "ignore_column_names": true
  },
  {
    "name": "extract-ipv6",
    "prompt": "From the text 'C2 at 2001:db8::1 observed', return the IPv6 addresses, one address per row (a single column of scalar address strings, not a list).",
    "reference_sql": "SELECT UNNEST(ioc.main.extract_ipv6('C2 at 2001:db8::1 observed')) AS ip",
    "unordered": true,
    "ignore_column_names": true
  },
  {
    "name": "extract-urls",
    "prompt": "From the defanged text 'payload from hxxp://evil[.]com/x', return the URLs in live (clickable) form, one URL per row.",
    "reference_sql": "SELECT UNNEST(ioc.main.extract_urls('payload from hxxp://evil[.]com/x')) AS url",
    "unordered": true,
    "ignore_column_names": true
  },
  {
    "name": "extract-domains",
    "prompt": "From the defanged text 'callback to evil[.]example[.]com', return the bare domain names, one domain per row.",
    "reference_sql": "SELECT UNNEST(ioc.main.extract_domains('callback to evil[.]example[.]com')) AS domain",
    "unordered": true,
    "ignore_column_names": true
  },
  {
    "name": "extract-emails",
    "prompt": "From the defanged text 'phish from bad[at]evil[.]com', return the e-mail addresses in live form, one address per row.",
    "reference_sql": "SELECT UNNEST(ioc.main.extract_emails('phish from bad[at]evil[.]com')) AS email",
    "unordered": true,
    "ignore_column_names": true
  },
  {
    "name": "extract-hashes",
    "prompt": "From the text 'sample md5 d41d8cd98f00b204e9800998ecf8427e', return the file hashes, one hash per row.",
    "reference_sql": "SELECT UNNEST(ioc.main.extract_hashes('sample md5 d41d8cd98f00b204e9800998ecf8427e')) AS hash",
    "unordered": true,
    "ignore_column_names": true
  },
  {
    "name": "extract-cves",
    "prompt": "From the text 'exploiting CVE-2024-1234 in the wild', return the CVE identifiers, one per row.",
    "reference_sql": "SELECT UNNEST(ioc.main.extract_cves('exploiting CVE-2024-1234 in the wild')) AS cve",
    "unordered": true,
    "ignore_column_names": true
  },
  {
    "name": "refang-indicator",
    "prompt": "Return a single value: the defanged indicator 'hxxp://evil[.]com' restored to its live, canonical form.",
    "reference_sql": "SELECT ioc.main.refang('hxxp://evil[.]com') AS live",
    "unordered": true,
    "ignore_column_names": true
  },
  {
    "name": "worker-version",
    "prompt": "Return a single value: the version string reported by the running ioc worker.",
    "reference_sql": "SELECT ioc.main.ioc_version() AS version",
    "unordered": true,
    "ignore_column_names": true
  },
  {
    "name": "browse-ioc-types",
    "prompt": "Using the ioc_types reference table in the ioc worker, return a single count of how many distinct indicator types it can recognize.",
    "reference_sql": "SELECT count(*) AS n FROM ioc.main.ioc_types",
    "unordered": true,
    "ignore_column_names": true
  }
]"#
                .to_string(),
            ),
        ],
        source_url: Some("https://github.com/Query-farm/vgi-ioc".to_string()),
        schemas: vec![CatSchema {
            name: "main".to_string(),
            comment: Some(
                "IOC extraction and defang/refang functions for cyber-threat intelligence."
                    .to_string(),
            ),
            tags: vec![
                ("vgi.title".to_string(), "IOC — main".to_string()),
                (
                    "vgi.keywords".to_string(),
                    r#"["ioc","indicator of compromise","defang","refang","extract_ipv4","extract_ipv6","extract_domains","extract_urls","extract_emails","extract_hashes","extract_cves","hash_type","is_ioc","extract_iocs","cyber threat intelligence","cti","security"]"#
                        .to_string(),
                ),
                // VGI123 classifying tags (bare keys: domain/category/topic) for faceting.
                ("domain".to_string(), "security".to_string()),
                ("category".to_string(), "threat-intelligence".to_string()),
                ("topic".to_string(), "ioc-extraction".to_string()),
                // VGI413: ordered category registry. Every function tags itself with a
                // matching `vgi.category`; categories drive navigation, listing sections,
                // and SEO descriptions.
                (
                    "vgi.categories".to_string(),
                    r#"[
  {"name": "Extraction", "description": "Pull indicators of compromise out of free text — one type at a time or every type at once."},
  {"name": "Defang & Refang", "description": "Neutralize live indicators so they are safe to share, or restore defanged indicators to their live form."},
  {"name": "Classification", "description": "Label or detect indicators: classify a file hash by algorithm, or test whether text contains any indicator."},
  {"name": "Reference", "description": "Browsable reference data: the registry of indicator types this worker recognizes and which function extracts each."},
  {"name": "Utility", "description": "Diagnostics and build information for the worker."}
]"#
                    .to_string(),
                ),
                (
                    "vgi.doc_llm".to_string(),
                    "IOC extraction and defang/refang functions: pull IPv4/IPv6, domains, URLs, \
                     e-mails, hashes and CVEs out of text, defang/refang indicators, classify a \
                     hash by length, and test whether text contains any indicator."
                        .to_string(),
                ),
                (
                    "vgi.doc_md".to_string(),
                    "## IOC extraction & defang/refang\n\n\
                     Indicator-of-compromise tooling for cyber-threat intelligence, served over \
                     Apache Arrow. Pull IPv4/IPv6 addresses, domains, URLs, e-mails, file hashes \
                     and CVE identifiers out of free-text reports with plain SQL, and convert \
                     between live and *defanged* indicator forms.\n\n\
                     ### Key concepts\n\n\
                     - **Refang-before-extract** — every extractor refangs a copy of its input \
                     first, so indicators defanged in a report (`hxxp://evil[.]com`, \
                     `10[.]0[.]0[.]5`, `bad[at]evil[.]com`) are still found.\n\
                     - **Defang / refang** — neutralize live indicators so they are safe to \
                     paste into a ticket or chat, or restore them to live form.\n\
                     - **Deduplicated, typed output** — the all-in-one extractor returns one \
                     `(type, value)` row per distinct indicator.\n\n\
                     ### When to use it\n\n\
                     Reach for this schema when indicators live inside free text rather than \
                     tidy columns — enriching an alerts table, building a watchlist from an \
                     incident report, or sanitizing artifacts before sharing them. Browse the \
                     functions below, grouped by category, each with its own worked examples."
                        .to_string(),
                ),
                // VGI506 representative example queries for the schema.
                (
                    "vgi.example_queries".to_string(),
                    "SELECT ioc.main.defang('http://evil.com/x');\n\
                     SELECT ioc.main.refang('hxxp://evil[.]com');\n\
                     SELECT UNNEST(ioc.main.extract_ipv4('beacon from 10[.]0[.]0[.]5'));\n\
                     SELECT UNNEST(ioc.main.extract_urls('payload from hxxp://evil[.]com/x'));\n\
                     SELECT ioc.main.hash_type('d41d8cd98f00b204e9800998ecf8427e');\n\
                     SELECT ioc.main.is_ioc('exploiting CVE-2024-1234');\n\
                     SELECT * FROM ioc.main.extract_iocs('beacon to hxxp://evil[.]com from \
                     10[.]0[.]0[.]5');"
                        .to_string(),
                ),
            ],
            views: vec![ioc_types_view()],
            macros: Vec::new(),
            tables: Vec::new(),
        }],
        ..Default::default()
    }
}

fn main() {
    // Logs MUST go to stderr — stdout is the Arrow-IPC channel.
    let _ = env_logger::Builder::from_env(env_logger::Env::default().filter_or("VGI_LOG", "info"))
        .format_timestamp_millis()
        .try_init();

    // The catalog name DuckDB sees in `ATTACH 'ioc' (TYPE vgi, …)`. Default to
    // `ioc`, but honor an explicit override so a test harness can rename.
    if std::env::var_os("VGI_WORKER_CATALOG_NAME").is_none() {
        std::env::set_var("VGI_WORKER_CATALOG_NAME", "ioc");
    }

    let catalog_name =
        std::env::var("VGI_WORKER_CATALOG_NAME").unwrap_or_else(|_| "ioc".to_string());

    let mut worker = Worker::new();
    scalar::register(&mut worker);
    table::register(&mut worker);
    worker.set_catalog(catalog_metadata(&catalog_name));
    worker.run();
}
