//! Integration tests: black-box exercise of the worker's pure IOC logic over a
//! realistic defanged threat-report string, the same way the SQL E2E suite
//! drives it but without the Arrow/RPC layer.
//!
//! The pure logic lives in a private module of the binary crate, so we include
//! it by path — the same trick `vgi-barcode` uses for its integration tests.

#[path = "../src/ioc.rs"]
#[allow(dead_code)]
mod ioc;

const REPORT: &str = "Beacon to hxxp://evil[.]example[.]com/path from 10[.]0[.]0[.]5, \
    hash a1b2c3d4e5f60718293a4b5c6d7e8f90, also \
    e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855, \
    contact bad[at]evil[.]example[.]com, CVE-2024-1234 and CVE-2023-1.";

#[test]
fn report_extractors_return_refanged_indicators() {
    assert_eq!(ioc::extract_ipv4(REPORT), vec!["10.0.0.5"]);
    assert_eq!(
        ioc::extract_urls(REPORT),
        vec!["http://evil.example.com/path"]
    );
    assert_eq!(ioc::extract_emails(REPORT), vec!["bad@evil.example.com"]);

    let cves = ioc::extract_cves(REPORT);
    assert!(cves.contains(&"CVE-2024-1234".to_string()));
    // "CVE-2023-1" has only 1 digit in the sequence -> not a valid (NNNN+) CVE.
    assert!(!cves.iter().any(|c| c == "CVE-2023-1"));

    let hashes = ioc::extract_hashes(REPORT);
    assert!(hashes.contains(&"a1b2c3d4e5f60718293a4b5c6d7e8f90".to_string())); // md5
    assert!(hashes
        .contains(&"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string()));
}

#[test]
fn defang_refang_roundtrip_on_report() {
    // Refanging the already-defanged report yields live indicators.
    let live = ioc::refang(REPORT);
    assert!(live.contains("http://evil.example.com/path"));
    assert!(live.contains("10.0.0.5"));
    assert!(live.contains("bad@evil.example.com"));

    // Defanging a clean string then refanging recovers the indicators.
    let clean = "see http://a.example.org and mail x@a.example.org and ip 9.9.9.9";
    let round = ioc::refang(&ioc::defang(clean));
    assert!(round.contains("http://a.example.org"));
    assert!(round.contains("x@a.example.org"));
    assert!(round.contains("9.9.9.9"));
}

#[test]
fn extract_iocs_typed_rows() {
    let rows = ioc::extract_iocs(REPORT);
    let has = |k: &str, v: &str| rows.iter().any(|r| r.kind == k && r.value == v);
    assert!(has("ipv4", "10.0.0.5"));
    assert!(has("url", "http://evil.example.com/path"));
    assert!(has("email", "bad@evil.example.com"));
    assert!(has("md5", "a1b2c3d4e5f60718293a4b5c6d7e8f90"));
    assert!(has(
        "sha256",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    ));
    assert!(has("cve", "CVE-2024-1234"));
    // The URL/e-mail host is not separately a domain row.
    assert!(!rows
        .iter()
        .any(|r| r.kind == "domain" && r.value == "evil.example.com"));
}

#[test]
fn empty_and_clean_inputs() {
    assert!(ioc::extract_iocs("").is_empty());
    assert!(ioc::extract_iocs("nothing to see here, move along").is_empty());
    assert!(!ioc::is_ioc(""));
    assert!(ioc::is_ioc(REPORT));
}

#[test]
fn hash_type_lengths() {
    assert_eq!(
        ioc::hash_type("a1b2c3d4e5f60718293a4b5c6d7e8f90"),
        Some("md5")
    );
    assert_eq!(ioc::hash_type(&"a".repeat(40)), Some("sha1"));
    assert_eq!(ioc::hash_type(&"a".repeat(64)), Some("sha256"));
    assert_eq!(ioc::hash_type(&"a".repeat(128)), Some("sha512"));
    assert_eq!(ioc::hash_type("hello"), None);
}
