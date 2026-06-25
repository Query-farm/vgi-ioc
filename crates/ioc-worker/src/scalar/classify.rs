//! `hash_type(s) -> VARCHAR` and `is_ioc(text) -> BOOLEAN`.
//!
//! `hash_type` classifies a hex string by length: `md5`/`sha1`/`sha256`/`sha512`
//! or NULL. `is_ioc` reports whether text contains ANY recognizable IOC (after
//! refanging). NULL in → NULL out.

use std::sync::Arc;

use arrow_array::builder::{BooleanBuilder, StringBuilder};
use arrow_array::{ArrayRef, RecordBatch};
use arrow_schema::DataType;
use vgi::{
    ArgSpec, BindParams, BindResponse, FunctionExample, FunctionMetadata, ProcessParams,
    ScalarFunction,
};
use vgi_rpc::{Result, RpcError};

use crate::arrow_io::text_str;
use crate::ioc;

// ---------------------------------------------------------------------------
// hash_type(s) -> VARCHAR
// ---------------------------------------------------------------------------

pub struct HashType;

impl ScalarFunction for HashType {
    fn name(&self) -> &str {
        "hash_type"
    }

    fn metadata(&self) -> FunctionMetadata {
        FunctionMetadata {
            description: "Classify a hex string as 'md5'|'sha1'|'sha256'|'sha512' by length, \
                          or NULL if it is not a recognized hash"
                .into(),
            return_type: Some(DataType::Utf8),
            examples: vec![FunctionExample {
                sql: "SELECT ioc.main.hash_type('d41d8cd98f00b204e9800998ecf8427e');".into(),
                description: "Classify a 32-character hex string as an MD5 hash (returns 'md5')."
                    .into(),
                expected_output: None,
            }],
            tags: crate::meta::object_tags(
                "Classify Hash Type",
                "Classify a hexadecimal string as a file-hash algorithm by its length: 32 hex \
                 chars -> 'md5', 40 -> 'sha1', 64 -> 'sha256', 128 -> 'sha512'. Returns NULL for \
                 anything that is not a recognized hash length. Use it to label extracted hash \
                 indicators by algorithm.",
                "Classify a hex string by length as `md5`/`sha1`/`sha256`/`sha512`, or NULL, \
                 e.g. `hash_type('d41d8cd98f00b204e9800998ecf8427e')` -> `'md5'`.",
                r#"["hash type","hash_type","md5","sha1","sha256","sha512","classify hash","hash length","fingerprint","file hash","algorithm"]"#,
            ),
            ..Default::default()
        }
    }

    fn argument_specs(&self) -> Vec<ArgSpec> {
        vec![ArgSpec::any_column(
            "s",
            0,
            "The candidate hash to classify; its length determines the reported algorithm",
        )]
    }

    fn on_bind(&self, _params: &BindParams) -> Result<BindResponse> {
        Ok(BindResponse::result(DataType::Utf8))
    }

    fn process(&self, params: &ProcessParams, batch: &RecordBatch) -> Result<RecordBatch> {
        let col = batch.column(0);
        let rows = batch.num_rows();
        let mut out = StringBuilder::new();
        for i in 0..rows {
            match text_str(col, i)? {
                None => out.append_null(),
                Some(s) => match ioc::hash_type(s) {
                    Some(t) => out.append_value(t),
                    None => out.append_null(),
                },
            }
        }
        let arr: ArrayRef = Arc::new(out.finish());
        RecordBatch::try_new(params.output_schema.clone(), vec![arr])
            .map_err(|e| RpcError::runtime_error(e.to_string()))
    }
}

// ---------------------------------------------------------------------------
// is_ioc(text) -> BOOLEAN
// ---------------------------------------------------------------------------

pub struct IsIoc;

impl ScalarFunction for IsIoc {
    fn name(&self) -> &str {
        "is_ioc"
    }

    fn metadata(&self) -> FunctionMetadata {
        FunctionMetadata {
            description: "True if the text contains ANY recognizable IOC (refangs first)".into(),
            return_type: Some(DataType::Boolean),
            examples: vec![FunctionExample {
                sql: "SELECT ioc.main.is_ioc('beacon to 10[.]0[.]0[.]5');".into(),
                description: "Test whether free text contains any indicator of compromise \
                              (returns true)."
                    .into(),
                expected_output: None,
            }],
            tags: crate::meta::object_tags(
                "Text Contains IOC",
                "Return true when the given free text contains ANY recognizable indicator of \
                 compromise — an IPv4/IPv6 address, domain, URL, e-mail, file hash, or CVE id. \
                 The text is refanged first, so defanged indicators (hxxp, [.], [at]) still \
                 count. Use it as a fast predicate to flag or filter rows worth deeper extraction.",
                "True if text contains any IOC (refangs first), e.g. \
                 `is_ioc('beacon to 10[.]0[.]0[.]5')` -> `true`.",
                r#"["is_ioc","contains ioc","has indicator","detect","predicate","flag","screen","triage","threat detection"]"#,
            ),
            ..Default::default()
        }
    }

    fn argument_specs(&self) -> Vec<ArgSpec> {
        vec![ArgSpec::any_column(
            "text",
            0,
            "The free text to test; it is refanged before checking so defanged indicators \
             still count",
        )]
    }

    fn on_bind(&self, _params: &BindParams) -> Result<BindResponse> {
        Ok(BindResponse::result(DataType::Boolean))
    }

    fn process(&self, params: &ProcessParams, batch: &RecordBatch) -> Result<RecordBatch> {
        let col = batch.column(0);
        let rows = batch.num_rows();
        let mut out = BooleanBuilder::new();
        for i in 0..rows {
            match text_str(col, i)? {
                None => out.append_null(),
                Some(text) => out.append_value(ioc::is_ioc(text)),
            }
        }
        let arr: ArrayRef = Arc::new(out.finish());
        RecordBatch::try_new(params.output_schema.clone(), vec![arr])
            .map_err(|e| RpcError::runtime_error(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arrow_io::test_support::{bound_type, run_scalar_text};
    use arrow_array::cast::AsArray;
    use arrow_array::Array;
    use vgi::arguments::Arguments;

    #[test]
    fn hash_type_binds_and_classifies() {
        assert_eq!(bound_type(&HashType), DataType::Utf8);
        let md5 = "d41d8cd98f00b204e9800998ecf8427e";
        let out = run_scalar_text(&HashType, &[Some(md5)], Arguments::default()).unwrap();
        assert_eq!(out.as_string::<i32>().value(0), "md5");
        let out = run_scalar_text(&HashType, &[Some("notahash")], Arguments::default()).unwrap();
        assert!(out.is_null(0));
        let out = run_scalar_text(&HashType, &[None], Arguments::default()).unwrap();
        assert!(out.is_null(0));
    }

    #[test]
    fn is_ioc_binds_and_evaluates() {
        assert_eq!(bound_type(&IsIoc), DataType::Boolean);
        let out = run_scalar_text(
            &IsIoc,
            &[Some("beacon to 10[.]0[.]0[.]5"), Some("nothing here"), None],
            Arguments::default(),
        )
        .unwrap();
        let b = out.as_boolean();
        assert!(b.value(0));
        assert!(!b.value(1));
        assert!(out.is_null(2));
    }
}
