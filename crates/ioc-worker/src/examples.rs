//! Composed worked examples: queries that combine two or more of this worker's
//! objects (the `extract_iocs` table function, the `ioc_types` view, and the
//! scalar extractors/classifiers) the way an analyst actually would.
//!
//! Each example is defined once here and referenced from both the schema-level
//! `vgi.example_queries` list (`lib.rs`) and the example list of every object
//! it showcases, so the text cannot drift between copies. All are offline and
//! deterministic (inline literals only).

use crate::meta::Example;

/// `extract_iocs` joined to the `ioc_types` registry.
pub const IOCS_BY_KIND: Example<'static> = Example {
    description: "Label every indicator pulled from a defanged report with its coarse group \
                  (network, email, hash, vulnerability) and the single-type extractor for it, \
                  by joining extract_iocs to the ioc_types registry.",
    sql: "SELECT t.kind, i.type, i.value, t.extractor FROM ioc.main.extract_iocs('dropper hxxps://cdn[.]evil[.]com/a.exe (sha256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855) beacons to 203[.]0[.]113[.]7, exploits CVE-2021-44228, phish from ops[at]evil[.]com') AS i JOIN ioc.main.ioc_types AS t ON t.name = i.type ORDER BY t.kind, i.type, i.value",
};

/// `defang` applied to every row of `extract_iocs`.
pub const DEFANGED_WATCHLIST: Example<'static> = Example {
    description: "Turn a live incident note into a safe-to-share watchlist: extract every \
                  indicator with extract_iocs, then defang each value so none of them is \
                  clickable.",
    sql: "SELECT i.type, ioc.main.defang(i.value) AS shareable FROM ioc.main.extract_iocs('beacon to http://evil.com/gate.php from 10.0.0.5, contact bad@evil.com') AS i ORDER BY i.type, shareable",
};

/// `extract_hashes` unnested per alert row, each hash labelled by `hash_type`.
pub const ALERT_HASHES_BY_ALGORITHM: Example<'static> = Example {
    description: "For each alert in a table, list the file hashes it mentions with their \
                  algorithm: unnest extract_hashes over the alert text and label each hash with \
                  hash_type (alerts without hashes produce no rows).",
    sql: "WITH alerts(id, body) AS (VALUES (1, 'dropped d41d8cd98f00b204e9800998ecf8427e and da39a3ee5e6b4b0d3255bfef95601890afd80709'), (2, 'user reset password'), (3, 'payload e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')) SELECT a.id, h.hash, ioc.main.hash_type(h.hash) AS algorithm FROM alerts AS a, UNNEST(ioc.main.extract_hashes(a.body)) AS h(hash) ORDER BY a.id, algorithm",
};

/// `is_ioc` as a triage filter, then per-type extractor counts per ticket.
pub const TICKET_TRIAGE: Example<'static> = Example {
    description: "Triage a ticket queue: keep only tickets whose text contains any indicator \
                  (is_ioc), then count the IPv4 addresses, URLs and CVEs each one mentions.",
    sql: "WITH tickets(id, body) AS (VALUES (1, 'beacon to hxxp://evil[.]com/x from 10[.]0[.]0[.]5'), (2, 'password reset for jsmith'), (3, 'exploiting CVE-2024-1234 via 10[.]0[.]0[.]5 and 10[.]0[.]0[.]9'), (4, 'printer offline on floor 3')) SELECT id, len(ioc.main.extract_ipv4(body)) AS n_ips, len(ioc.main.extract_urls(body)) AS n_urls, len(ioc.main.extract_cves(body)) AS n_cves FROM tickets WHERE ioc.main.is_ioc(body) ORDER BY id",
};

/// Every composed example, in schema-list order.
pub const COMPOSED: [Example<'static>; 4] = [
    IOCS_BY_KIND,
    DEFANGED_WATCHLIST,
    ALERT_HASHES_BY_ALGORITHM,
    TICKET_TRIAGE,
];

/// The composed examples shown on `object`'s own example list (the vgi-lint
/// agent simulator only shows agents per-object examples, never schema-level
/// lists, so each composed example is attached to the objects it showcases).
pub fn composed_for(object: &str) -> &'static [Example<'static>] {
    match object {
        "extract_iocs" => &[IOCS_BY_KIND, DEFANGED_WATCHLIST],
        "ioc_types" => &[IOCS_BY_KIND],
        "defang" => &[DEFANGED_WATCHLIST],
        "extract_hashes" | "hash_type" => &[ALERT_HASHES_BY_ALGORITHM],
        "is_ioc" => &[TICKET_TRIAGE],
        _ => &[],
    }
}

/// `object`'s `vgi.example_queries` list: its own single-function example
/// first, then any composed examples attached to it.
pub fn object_examples_json(object: &str, description: &str, sql: &str) -> String {
    let mut list = vec![Example { description, sql }];
    list.extend_from_slice(composed_for(object));
    crate::meta::example_list_json(&list)
}
