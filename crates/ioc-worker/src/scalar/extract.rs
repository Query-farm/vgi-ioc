//! `extract_<kind>(text) -> VARCHAR[]` — the per-type indicator extractors.
//!
//! All seven extractors (`extract_ipv4`, `extract_ipv6`, `extract_domains`,
//! `extract_urls`, `extract_emails`, `extract_hashes`, `extract_cves`) share
//! this adapter: each refangs its input first (see `ioc.rs`), then returns the
//! deduplicated matches as a `LIST(VARCHAR)`. NULL in → NULL out (a NULL list,
//! not an empty list); no matches → an empty list.

use arrow_array::builder::ListBuilder;
use arrow_array::builder::StringBuilder;
use arrow_array::{ArrayRef, RecordBatch};
use vgi::{
    ArgSpec, BindParams, BindResponse, FunctionExample, FunctionMetadata, ProcessParams,
    ScalarFunction,
};
use vgi_rpc::{Result, RpcError};

use crate::arrow_io::{finish_list, list_varchar_builder, list_varchar_type, text_str};
use crate::ioc;

/// The extraction function applied per cell.
type ExtractFn = fn(&str) -> Vec<String>;

pub struct Extract {
    name: &'static str,
    desc: &'static str,
    func: ExtractFn,
    example_sql: &'static str,
    example_desc: &'static str,
    title: &'static str,
    desc_llm: &'static str,
    desc_md: &'static str,
    keywords: &'static str,
}

impl Extract {
    pub fn ipv4() -> Self {
        Extract {
            name: "extract_ipv4",
            desc: "Extract IPv4 addresses (refangs first; private/reserved included) as VARCHAR[]",
            func: ioc::extract_ipv4,
            example_sql: "SELECT UNNEST(ioc.main.extract_ipv4('beacon from 10[.]0[.]0[.]5'));",
            example_desc: "Pull the defanged IPv4 address out of a report (returns '10.0.0.5').",
            title: "Extract IPv4 Addresses",
            desc_llm: "Extract every distinct IPv4 address from free text and return them as a \
                       `VARCHAR` list. The input is refanged first, so defanged forms like \
                       '10[.]0[.]0[.]5' are matched; private and reserved ranges are kept because \
                       they are still real indicators in a report. NULL in -> NULL list; no \
                       matches -> empty list.",
            desc_md: "Extract IPv4 addresses from text as `VARCHAR[]` (refangs first), e.g. \
                      `extract_ipv4('beacon from 10[.]0[.]0[.]5')` -> `['10.0.0.5']`.",
            keywords: r#"["extract ipv4","ip address","ipv4","ip","network indicator","beacon","c2","refang","extract ip"]"#,
        }
    }
    pub fn ipv6() -> Self {
        Extract {
            name: "extract_ipv6",
            desc: "Extract IPv6 addresses (refangs first; canonicalized) as VARCHAR[]",
            func: ioc::extract_ipv6,
            example_sql: "SELECT UNNEST(ioc.main.extract_ipv6('C2 at 2001:db8::1 observed'));",
            example_desc: "Pull an IPv6 address out of free text (returns '2001:db8::1').",
            title: "Extract IPv6 Addresses",
            desc_llm: "Extract every distinct IPv6 address from free text and return them as a \
                       `VARCHAR` list, canonicalized to their compressed form. The input is \
                       refanged first. NULL in -> NULL list; no matches -> empty list.",
            desc_md: "Extract IPv6 addresses from text as `VARCHAR[]` (refangs first, \
                      canonicalized), e.g. `extract_ipv6('C2 at 2001:db8::1')` -> \
                      `['2001:db8::1']`.",
            keywords: r#"["extract ipv6","ipv6","ip address","ip","network indicator","c2","refang","extract ip"]"#,
        }
    }
    pub fn domains() -> Self {
        Extract {
            name: "extract_domains",
            desc: "Extract bare domains (refangs first; URL/e-mail hosts excluded) as VARCHAR[]",
            func: ioc::extract_domains,
            example_sql:
                "SELECT UNNEST(ioc.main.extract_domains('callback to evil[.]example[.]com'));",
            example_desc: "Pull a bare defanged domain out of a report \
                           (returns 'evil.example.com').",
            title: "Extract Bare Domains",
            desc_llm: "Extract every distinct bare domain name from free text and return them as \
                       a `VARCHAR` list. The input is refanged first. Hosts already claimed by a \
                       URL or e-mail are excluded to avoid double-reporting, and a domain must \
                       have an alphabetic TLD of at least two characters. NULL in -> NULL list; \
                       no matches -> empty list.",
            desc_md: "Extract bare domains from text as `VARCHAR[]` (refangs first; URL/e-mail \
                      hosts excluded), e.g. `extract_domains('callback to evil[.]example[.]com')` \
                      -> `['evil.example.com']`.",
            keywords: r#"["extract domains","domain","hostname","fqdn","bare domain","refang","c2 domain","extract domain"]"#,
        }
    }
    pub fn urls() -> Self {
        Extract {
            name: "extract_urls",
            desc: "Extract URLs (refangs first) as VARCHAR[]",
            func: ioc::extract_urls,
            example_sql:
                "SELECT UNNEST(ioc.main.extract_urls('payload from hxxp://evil[.]com/x'));",
            example_desc: "Pull a defanged URL out of a report \
                           (returns 'http://evil.com/x').",
            title: "Extract Web URLs",
            desc_llm: "Extract every distinct URL from free text and return them as a `VARCHAR` \
                       list in live (refanged) form. The input is refanged first, so defanged \
                       links like 'hxxp://evil[.]com/x' are matched. NULL in -> NULL list; no \
                       matches -> empty list.",
            desc_md: "Extract URLs from text as `VARCHAR[]` (refangs first), e.g. \
                      `extract_urls('payload from hxxp://evil[.]com/x')` -> \
                      `['http://evil.com/x']`.",
            keywords: r#"["extract urls","url","link","uri","web address","refang","payload url","c2 url","extract url"]"#,
        }
    }
    pub fn emails() -> Self {
        Extract {
            name: "extract_emails",
            desc: "Extract e-mail addresses (refangs first) as VARCHAR[]",
            func: ioc::extract_emails,
            example_sql: "SELECT UNNEST(ioc.main.extract_emails('phish from bad[at]evil[.]com'));",
            example_desc: "Pull a defanged e-mail address out of a report \
                           (returns 'bad@evil.com').",
            title: "Extract E-mail Addresses",
            desc_llm: "Extract every distinct e-mail address from free text and return them as a \
                       `VARCHAR` list in live (refanged) form. The input is refanged first, so \
                       defanged forms like 'bad[at]evil[.]com' are matched. NULL in -> NULL \
                       list; no matches -> empty list.",
            desc_md: "Extract e-mail addresses from text as `VARCHAR[]` (refangs first), e.g. \
                      `extract_emails('phish from bad[at]evil[.]com')` -> `['bad@evil.com']`.",
            keywords: r#"["extract emails","email","e-mail","address","phishing","sender","refang","at sign","extract email"]"#,
        }
    }
    pub fn hashes() -> Self {
        Extract {
            name: "extract_hashes",
            desc: "Extract md5/sha1/sha256 hashes (refangs first) as VARCHAR[]",
            func: ioc::extract_hashes,
            example_sql: "SELECT UNNEST(ioc.main.extract_hashes('sample md5 d41d8cd98f00b204e9800998ecf8427e'));",
            example_desc: "Pull a file hash out of a report \
                           (returns 'd41d8cd98f00b204e9800998ecf8427e').",
            title: "Extract File Hashes",
            desc_llm: "Extract every distinct file hash (md5, sha1, sha256) from free text and \
                       return them as a `VARCHAR` list. The input is refanged first. Pair with \
                       `hash_type` to label each hash by algorithm. NULL in -> NULL list; no \
                       matches -> empty list.",
            desc_md: "Extract md5/sha1/sha256 hashes from text as `VARCHAR[]` (refangs first), \
                      e.g. `extract_hashes('sample md5 d41d8cd9...')` -> `['d41d8cd9...']`.",
            keywords: r#"["extract hashes","hash","md5","sha1","sha256","file hash","fingerprint","checksum","sample","refang","extract hash"]"#,
        }
    }
    pub fn cves() -> Self {
        Extract {
            name: "extract_cves",
            desc: "Extract CVE identifiers (refangs first) as VARCHAR[]",
            func: ioc::extract_cves,
            example_sql:
                "SELECT UNNEST(ioc.main.extract_cves('exploiting CVE-2024-1234 in the wild'));",
            example_desc: "Pull a CVE identifier out of a report (returns 'CVE-2024-1234').",
            title: "Extract CVE Identifiers",
            desc_llm: "Extract every distinct CVE identifier (Common Vulnerabilities and \
                       Exposures id, e.g. CVE-2024-1234) from free text and return them as a \
                       `VARCHAR` list. The input is refanged first. NULL in -> NULL list; no \
                       matches -> empty list.",
            desc_md: "Extract CVE identifiers from text as `VARCHAR[]` (refangs first), e.g. \
                      `extract_cves('exploiting CVE-2024-1234')` -> `['CVE-2024-1234']`.",
            keywords: r#"["extract cves","cve","vulnerability","cve id","common vulnerabilities and exposures","exploit","advisory","extract cve"]"#,
        }
    }
}

impl ScalarFunction for Extract {
    fn name(&self) -> &str {
        self.name
    }

    fn metadata(&self) -> FunctionMetadata {
        FunctionMetadata {
            description: self.desc.into(),
            return_type: Some(list_varchar_type()),
            examples: vec![FunctionExample {
                sql: self.example_sql.into(),
                description: self.example_desc.into(),
                expected_output: None,
            }],
            tags: crate::meta::object_tags(
                self.title,
                self.desc_llm,
                self.desc_md,
                self.keywords,
                "Extraction",
                &crate::meta::example_queries_json(self.example_desc, self.example_sql),
            ),
            ..Default::default()
        }
    }

    fn argument_specs(&self) -> Vec<ArgSpec> {
        vec![ArgSpec::any_column(
            "text",
            0,
            "The free text to scan for indicators; it is refanged before matching so \
             defanged forms are still found",
        )]
    }

    fn on_bind(&self, _params: &BindParams) -> Result<BindResponse> {
        // The declared element type MUST match the array built in `process`.
        Ok(BindResponse::result(list_varchar_type()))
    }

    fn process(&self, params: &ProcessParams, batch: &RecordBatch) -> Result<RecordBatch> {
        let col = batch.column(0);
        let rows = batch.num_rows();
        let mut builder: ListBuilder<StringBuilder> = list_varchar_builder();
        for i in 0..rows {
            match text_str(col, i)? {
                // NULL in → NULL list out.
                None => builder.append_null(),
                Some(text) => {
                    for v in (self.func)(text) {
                        builder.values().append_value(&v);
                    }
                    // Close the (possibly empty) list for this row.
                    builder.append(true);
                }
            }
        }
        let arr: ArrayRef = finish_list(builder);
        debug_assert_eq!(arr.data_type(), &list_varchar_type());
        RecordBatch::try_new(params.output_schema.clone(), vec![arr])
            .map_err(|e| RpcError::runtime_error(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arrow_io::test_support::{bound_type, list_row, run_scalar_text};
    use arrow_array::Array;
    use vgi::arguments::Arguments;

    const REPORT: &str = "Beacon to hxxp://evil[.]example[.]com/path from 10[.]0[.]0[.]5, \
        md5 d41d8cd98f00b204e9800998ecf8427e, exploiting CVE-2024-1234";

    #[test]
    fn binds_list_varchar() {
        assert_eq!(bound_type(&Extract::ipv4()), list_varchar_type());
        assert_eq!(bound_type(&Extract::cves()), list_varchar_type());
    }

    #[test]
    fn extracts_refanged_indicators() {
        let out = run_scalar_text(&Extract::ipv4(), &[Some(REPORT)], Arguments::default()).unwrap();
        assert_eq!(list_row(&out, 0), vec!["10.0.0.5"]);

        let out = run_scalar_text(&Extract::urls(), &[Some(REPORT)], Arguments::default()).unwrap();
        assert_eq!(list_row(&out, 0), vec!["http://evil.example.com/path"]);

        let out = run_scalar_text(&Extract::cves(), &[Some(REPORT)], Arguments::default()).unwrap();
        assert_eq!(list_row(&out, 0), vec!["CVE-2024-1234"]);

        let out =
            run_scalar_text(&Extract::hashes(), &[Some(REPORT)], Arguments::default()).unwrap();
        assert_eq!(list_row(&out, 0), vec!["d41d8cd98f00b204e9800998ecf8427e"]);
    }

    #[test]
    fn null_in_null_out_and_empty_is_empty_list() {
        let out = run_scalar_text(&Extract::ipv4(), &[None], Arguments::default()).unwrap();
        assert!(out.is_null(0));

        let out = run_scalar_text(
            &Extract::ipv4(),
            &[Some("no ips here")],
            Arguments::default(),
        )
        .unwrap();
        assert!(!out.is_null(0));
        assert_eq!(list_row(&out, 0), Vec::<String>::new());
    }
}
