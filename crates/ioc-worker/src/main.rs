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
mod scalar;
mod table;

use vgi::Worker;

/// Worker version string, surfaced by `ioc_version()`.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
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

    let mut worker = Worker::new();
    scalar::register(&mut worker);
    table::register(&mut worker);
    worker.run();
}
