//! `defang(text) -> VARCHAR` and `refang(text) -> VARCHAR`.
//!
//! `defang` makes indicators safe to paste (`http`→`hxxp`, `.`→`[.]`,
//! `@`→`[at]`, `://`→`[://]`); `refang` is the inverse. Pure text transforms;
//! NULL in → NULL out.

use std::sync::Arc;

use arrow_array::builder::StringBuilder;
use arrow_array::{ArrayRef, RecordBatch};
use arrow_schema::DataType;
use vgi::{
    ArgSpec, BindParams, BindResponse, FunctionExample, FunctionMetadata, ProcessParams,
    ScalarFunction,
};
use vgi_rpc::{Result, RpcError};

use crate::arrow_io::text_str;
use crate::ioc;

/// Which direction this transform runs.
#[derive(Clone, Copy)]
enum Dir {
    Defang,
    Refang,
}

pub struct Fang {
    dir: Dir,
    name: &'static str,
    desc: &'static str,
    example_sql: &'static str,
    example_desc: &'static str,
    title: &'static str,
    desc_llm: &'static str,
    desc_md: &'static str,
    keywords: &'static str,
}

impl Fang {
    pub fn defang() -> Self {
        Fang {
            dir: Dir::Defang,
            name: "defang",
            desc: "Defang indicators in text so they are safe to share \
                   (http->hxxp, .->[.], @->[at], ://->[://])",
            example_sql: "SELECT ioc.main.defang('http://evil.com/x');",
            example_desc: "Defang a live URL so it is safe to paste into a report \
                           (returns 'hxxp[://]evil[.]com/x').",
            title: "Defang Indicators",
            desc_llm: "Rewrite the live indicators in a string into a neutralized, \
                       safe-to-share form so pasting a report into chat, e-mail, or a ticket \
                       cannot accidentally create a clickable link or live address: \
                       `http`->`hxxp`, `.`->`[.]`, `@`->`[at]`, and `://`->`[://]`. Pure text \
                       transform; NULL in -> NULL out. The inverse of `refang`.",
            desc_md: "Defang indicators so they are safe to share, e.g. \
                      `defang('http://evil.com/x')` -> `'hxxp[://]evil[.]com/x'`.",
            keywords: "defang, neutralize, sanitize, safe to share, hxxp, bracket dots, \
                       make safe, redact link, indicator, url, domain",
        }
    }

    pub fn refang() -> Self {
        Fang {
            dir: Dir::Refang,
            name: "refang",
            desc: "Refang defanged indicators back to live form \
                   (hxxp->http, [.]->., [at]->@, [://]->://)",
            example_sql: "SELECT ioc.main.refang('hxxp://evil[.]com');",
            example_desc: "Refang a defanged URL back to live form (returns \
                           'http://evil.com').",
            title: "Refang Indicators",
            desc_llm: "Restore defanged indicators in a string back to their live, canonical \
                       form: `hxxp`->`http`, `[.]`->`.`, `[at]`->`@`, and `[://]`->`://`. The \
                       inverse of `defang`. Pure text transform; NULL in -> NULL out. The \
                       extractors call this internally so defanged indicators are still matched.",
            desc_md: "Refang defanged indicators back to live form, e.g. \
                      `refang('hxxp://evil[.]com')` -> `'http://evil.com'`.",
            keywords: "refang, restore, undefang, rehydrate, live form, canonical, hxxp to http, \
                       unbracket, indicator, url, domain",
        }
    }
}

impl ScalarFunction for Fang {
    fn name(&self) -> &str {
        self.name
    }

    fn metadata(&self) -> FunctionMetadata {
        FunctionMetadata {
            description: self.desc.into(),
            return_type: Some(DataType::Utf8),
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
                "scalar/fang.rs",
            ),
            ..Default::default()
        }
    }

    fn argument_specs(&self) -> Vec<ArgSpec> {
        vec![ArgSpec::any_column("text", 0, "Free text (VARCHAR)")]
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
                Some(text) => {
                    let transformed = match self.dir {
                        Dir::Defang => ioc::defang(text),
                        Dir::Refang => ioc::refang(text),
                    };
                    out.append_value(&transformed);
                }
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
    fn binds_varchar() {
        assert_eq!(bound_type(&Fang::defang()), DataType::Utf8);
        assert_eq!(bound_type(&Fang::refang()), DataType::Utf8);
    }

    #[test]
    fn defang_then_refang_recovers_indicators() {
        let live = "http://evil.example.com from 1.2.3.4";
        let d = run_scalar_text(&Fang::defang(), &[Some(live)], Arguments::default()).unwrap();
        let fanged = d.as_string::<i32>().value(0).to_string();
        assert!(fanged.contains("hxxp[://]evil[.]example[.]com"));
        assert!(!fanged.contains("1.2.3.4"));

        let r = run_scalar_text(&Fang::refang(), &[Some(&fanged)], Arguments::default()).unwrap();
        let back = r.as_string::<i32>().value(0);
        assert!(back.contains("http://evil.example.com"));
        assert!(back.contains("1.2.3.4"));
    }

    #[test]
    fn null_in_null_out() {
        let out = run_scalar_text(&Fang::defang(), &[None], Arguments::default()).unwrap();
        assert!(out.is_null(0));
        let out = run_scalar_text(&Fang::refang(), &[None], Arguments::default()).unwrap();
        assert!(out.is_null(0));
    }
}
