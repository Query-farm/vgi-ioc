//! `extract_iocs(text) -> ("type" VARCHAR, value VARCHAR)` — one row per
//! distinct IOC found in `text`.
//!
//! The text is a bind-time constant (DuckDB table functions take constant
//! arguments, not row columns — bound positionally by the Rust SDK). The input
//! is refanged first, results are deduplicated, and `type` is one of
//! {ipv4, ipv6, url, email, domain, md5, sha1, sha256, sha512, cve}. A NULL or
//! empty text yields zero rows.

use std::sync::Arc;

use arrow_array::builder::StringBuilder;
use arrow_array::{ArrayRef, RecordBatch};
use arrow_schema::{DataType, Field, Schema, SchemaRef};
use vgi::table_function::{TableFunction, TableProducer};
use vgi::{ArgSpec, BindParams, BindResponse, FunctionExample, FunctionMetadata, ProcessParams};
use vgi_rpc::{OutputCollector, Result, RpcError};

use crate::ioc::{self, Indicator};

/// Guaranteed-runnable, catalog-qualified examples (VGI509). Each `sql` is
/// self-contained and re-runnable against an attached `ioc` worker. We omit
/// `expected_result` deliberately — the linter only needs each query to execute
/// cleanly, and pinning exact match output would be brittle.
const EXECUTABLE_EXAMPLES: &str = r#"[
  {
    "description": "Extract every distinct indicator from a defanged report as (type, value) rows.",
    "sql": "SELECT type, value FROM ioc.main.extract_iocs('beacon to hxxp://evil[.]com from 10[.]0[.]0[.]5') ORDER BY type, value"
  },
  {
    "description": "Defang a live URL so it is safe to paste into a report.",
    "sql": "SELECT ioc.main.defang('http://evil.com/x') AS safe"
  },
  {
    "description": "Refang a defanged URL back to its live form.",
    "sql": "SELECT ioc.main.refang('hxxp://evil[.]com') AS live"
  },
  {
    "description": "Pull the defanged IPv4 address out of a report.",
    "sql": "SELECT UNNEST(ioc.main.extract_ipv4('beacon from 10[.]0[.]0[.]5')) AS ip"
  },
  {
    "description": "Classify a 32-character hex string as an MD5 hash.",
    "sql": "SELECT ioc.main.hash_type('d41d8cd98f00b204e9800998ecf8427e') AS kind"
  },
  {
    "description": "Test whether free text contains any indicator of compromise.",
    "sql": "SELECT ioc.main.is_ioc('exploiting CVE-2024-1234') AS hit"
  }
]"#;

pub struct ExtractIocs;

fn output_schema() -> SchemaRef {
    // `type` is quoted in SQL (reserved-ish word); the Arrow field is plainly
    // named "type".
    Arc::new(Schema::new(vec![
        Field::new("type", DataType::Utf8, false),
        Field::new("value", DataType::Utf8, false),
    ]))
}

impl TableFunction for ExtractIocs {
    fn name(&self) -> &str {
        "extract_iocs"
    }

    fn metadata(&self) -> FunctionMetadata {
        let mut tags = crate::meta::object_tags(
            "Extract All IOCs",
            "Scan free text and return every distinct indicator of compromise as (type, value) \
             rows, one row per indicator. Covered types are ipv4, ipv6, url, email, domain, md5, \
             sha1, sha256, sha512, and cve. The text is refanged first so defanged indicators \
             are found, results are deduplicated, and URL/e-mail hosts are not double-reported as \
             bare domains. The text argument is a bind-time constant; a NULL or empty text yields \
             zero rows. Use this as the one-shot table function when you want all indicator types \
             at once instead of calling each extractor separately.",
            "Extract every distinct IOC from text as `(type, value)` rows: one row per \
             indicator, across all supported types at once. The input is refanged first so \
             defanged indicators are still found, results are deduplicated, and a URL or \
             e-mail host is not double-reported as a bare domain. See the executable \
             examples for runnable queries.",
            r#"["extract iocs","all indicators","ioc table","type value","ipv4","ipv6","url","email","domain","hash","cve","threat report","refang","deduplicate","one-shot"]"#,
            "Extraction",
        );
        tags.push((
            "vgi.result_columns_schema".into(),
            r#"[
  {"name": "type", "type": "VARCHAR", "description": "Indicator type: one of ipv4, ipv6, url, email, domain, md5, sha1, sha256, sha512, cve."},
  {"name": "value", "type": "VARCHAR", "description": "The refanged (live-form) indicator value."}
]"#
            .into(),
        ));
        tags.push(("vgi.executable_examples".into(), EXECUTABLE_EXAMPLES.into()));
        FunctionMetadata {
            description: "Extract every distinct IOC from text as (type, value) rows \
                          (refangs first; deduplicated)"
                .into(),
            examples: vec![FunctionExample {
                sql: "SELECT type, count(*) AS n \
                      FROM ioc.main.extract_iocs('beacon to hxxp://evil[.]com from \
                      10[.]0[.]0[.]5 and bad[at]evil[.]com') \
                      GROUP BY type ORDER BY type;"
                    .into(),
                description: "Count the distinct indicators found in a defanged report, grouped \
                              by indicator type."
                    .into(),
                expected_output: None,
            }],
            tags,
            ..Default::default()
        }
    }

    fn argument_specs(&self) -> Vec<ArgSpec> {
        vec![ArgSpec::const_arg(
            "text",
            0,
            "varchar",
            "The bind-time-constant text to scan; it is refanged before matching and every \
             distinct indicator becomes a (type, value) row",
        )]
    }

    fn on_bind(&self, _params: &BindParams) -> Result<BindResponse> {
        Ok(BindResponse {
            output_schema: output_schema(),
            opaque_data: Vec::new(),
        })
    }

    fn producer(&self, params: &ProcessParams) -> Result<Box<dyn TableProducer>> {
        // NULL / absent text → no rows.
        let rows = match params.arguments.const_str(0) {
            None => Vec::new(),
            Some(text) => ioc::extract_iocs(&text),
        };
        Ok(Box::new(IocProducer {
            schema: params.output_schema.clone(),
            rows,
            done: false,
        }))
    }
}

struct IocProducer {
    schema: SchemaRef,
    rows: Vec<Indicator>,
    done: bool,
}

impl TableProducer for IocProducer {
    fn next_batch(&mut self, _out: &mut OutputCollector) -> Result<Option<RecordBatch>> {
        if self.done {
            return Ok(None);
        }
        self.done = true;

        let mut ty = StringBuilder::new();
        let mut value = StringBuilder::new();
        for ind in &self.rows {
            ty.append_value(ind.kind);
            value.append_value(&ind.value);
        }
        let cols: Vec<ArrayRef> = vec![Arc::new(ty.finish()), Arc::new(value.finish())];
        Ok(Some(
            RecordBatch::try_new(self.schema.clone(), cols)
                .map_err(|e| RpcError::runtime_error(e.to_string()))?,
        ))
    }
}
