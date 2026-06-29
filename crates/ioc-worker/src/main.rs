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

use vgi::catalog::{CatSchema, CatalogModel};
use vgi::Worker;

/// Worker version string, surfaced by `ioc_version()`.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Catalog + schema metadata (description, provenance) surfaced to DuckDB and
/// the `vgi-lint` metadata-quality linter. The function objects themselves are
/// served from the registered scalars/table; this only adds catalog/schema-level
/// comments and tags.
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
                 Only `defang` and `refang` themselves skip that step.\n\n\
                 Attach it with `ATTACH 'ioc' (TYPE vgi, LOCATION '…')` and call the scalar \
                 functions `defang` and `refang` to neutralize or restore a single indicator; \
                 `extract_ipv4`, `extract_ipv6`, `extract_domains`, `extract_urls`, \
                 `extract_emails`, `extract_hashes` and `extract_cves` to return a `LIST(VARCHAR)` \
                 of matches of one type; `hash_type` to classify a hash by length (md5/sha1/sha256/\
                 sha512); `is_ioc` to test whether any indicator is present; and `ioc_version` for \
                 the build version. The table function `extract_iocs` explodes a blob of text into \
                 one `(type, value)` row per indicator across every type at once — ideal for \
                 enriching an alerts table, building a watchlist, or joining extracted indicators \
                 against threat feeds. Source and issues live at \
                 [Query-farm/vgi-ioc](https://github.com/Query-farm/vgi-ioc); the worker is part \
                 of the VGI ecosystem from [Query Farm](https://query.farm)."
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
                (
                    "vgi.doc_llm".to_string(),
                    "IOC extraction and defang/refang functions: pull IPv4/IPv6, domains, URLs, \
                     e-mails, hashes and CVEs out of text, defang/refang indicators, classify a \
                     hash by length, and test whether text contains any indicator."
                        .to_string(),
                ),
                (
                    "vgi.doc_md".to_string(),
                    "IOC extraction and defang/refang functions for cyber-threat intelligence, \
                     served over Apache Arrow. Pull IPv4/IPv6 addresses, domains, URLs, e-mails, \
                     file hashes and CVE identifiers out of free-text reports; defang indicators \
                     to make them safe to share and refang them back to live form; classify a \
                     hash by length; and test whether text contains any indicator. Every \
                     extractor refangs its input first, so indicators that were defanged in a \
                     report are still found."
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
            views: Vec::new(),
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
