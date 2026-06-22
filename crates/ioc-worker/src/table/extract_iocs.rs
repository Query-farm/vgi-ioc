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
use vgi::{ArgSpec, BindParams, BindResponse, FunctionMetadata, ProcessParams};
use vgi_rpc::{OutputCollector, Result, RpcError};

use crate::ioc::{self, Indicator};

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
        FunctionMetadata {
            description: "Extract every distinct IOC from text as (type, value) rows \
                          (refangs first; deduplicated)"
                .into(),
            ..Default::default()
        }
    }

    fn argument_specs(&self) -> Vec<ArgSpec> {
        vec![ArgSpec::const_arg(
            "text",
            0,
            "varchar",
            "Free text to scan (VARCHAR constant)",
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
