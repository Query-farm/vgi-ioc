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
use vgi::{ArgSpec, BindParams, BindResponse, FunctionMetadata, ProcessParams, ScalarFunction};
use vgi_rpc::{Result, RpcError};

use crate::arrow_io::{finish_list, list_varchar_builder, list_varchar_type, text_str};
use crate::ioc;

/// The extraction function applied per cell.
type ExtractFn = fn(&str) -> Vec<String>;

pub struct Extract {
    name: &'static str,
    desc: &'static str,
    func: ExtractFn,
}

impl Extract {
    pub fn ipv4() -> Self {
        Extract {
            name: "extract_ipv4",
            desc: "Extract IPv4 addresses (refangs first; private/reserved included) as VARCHAR[]",
            func: ioc::extract_ipv4,
        }
    }
    pub fn ipv6() -> Self {
        Extract {
            name: "extract_ipv6",
            desc: "Extract IPv6 addresses (refangs first; canonicalized) as VARCHAR[]",
            func: ioc::extract_ipv6,
        }
    }
    pub fn domains() -> Self {
        Extract {
            name: "extract_domains",
            desc: "Extract bare domains (refangs first; URL/e-mail hosts excluded) as VARCHAR[]",
            func: ioc::extract_domains,
        }
    }
    pub fn urls() -> Self {
        Extract {
            name: "extract_urls",
            desc: "Extract URLs (refangs first) as VARCHAR[]",
            func: ioc::extract_urls,
        }
    }
    pub fn emails() -> Self {
        Extract {
            name: "extract_emails",
            desc: "Extract e-mail addresses (refangs first) as VARCHAR[]",
            func: ioc::extract_emails,
        }
    }
    pub fn hashes() -> Self {
        Extract {
            name: "extract_hashes",
            desc: "Extract md5/sha1/sha256 hashes (refangs first) as VARCHAR[]",
            func: ioc::extract_hashes,
        }
    }
    pub fn cves() -> Self {
        Extract {
            name: "extract_cves",
            desc: "Extract CVE identifiers (refangs first) as VARCHAR[]",
            func: ioc::extract_cves,
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
            ..Default::default()
        }
    }

    fn argument_specs(&self) -> Vec<ArgSpec> {
        vec![ArgSpec::any_column("text", 0, "Free text (VARCHAR)")]
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
