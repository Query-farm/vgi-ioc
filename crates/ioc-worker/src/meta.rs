//! Shared helpers for the per-object discovery/description metadata that the
//! `vgi-lint` strict profile expects on **every** function and table.
//!
//! Each function/table surfaces these in its `FunctionMetadata.tags`:
//! - `vgi.title` (VGI124)   — human-friendly display name
//! - `vgi.doc_llm` (VGI112) — Markdown narrative aimed at LLMs/agents
//! - `vgi.doc_md` (VGI113)  — Markdown narrative for human docs
//! - `vgi.keywords` (VGI126) — comma-separated search terms/synonyms
//! - `vgi.category` (VGI413)  — names one of the schema's `vgi.categories`
//! - `vgi.example_queries` (VGI515) — a JSON list of `{description, sql}`
//!   objects. This is the carrier the linter reads for example descriptions:
//!   the native `duckdb_functions().examples` column drops the per-example
//!   description text, so we mirror each worked example here with its prose.
//!
//! Per-object `vgi.source_url` is intentionally NOT emitted: provenance lives
//! once on the catalog (`CatalogModel.source_url`); repeating it on every
//! object is redundant (VGI139).

/// Build the standard per-object discovery/description tags. `category` must
/// name one of the entries in the schema's `vgi.categories` registry;
/// `example_queries` is a JSON list of `{description, sql}` objects (see
/// [`example_queries_json`]).
pub fn object_tags(
    title: &str,
    description_llm: &str,
    description_md: &str,
    keywords: &str,
    category: &str,
    example_queries: &str,
) -> Vec<(String, String)> {
    vec![
        ("vgi.title".to_string(), title.to_string()),
        ("vgi.doc_llm".to_string(), description_llm.to_string()),
        ("vgi.doc_md".to_string(), description_md.to_string()),
        ("vgi.keywords".to_string(), keywords.to_string()),
        ("vgi.category".to_string(), category.to_string()),
        (
            "vgi.example_queries".to_string(),
            example_queries.to_string(),
        ),
    ]
}

/// Escape a string for embedding inside a JSON double-quoted value.
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// Build a single-element `vgi.example_queries` JSON list from one worked
/// example (`sql`) and its human-readable `description` (VGI515).
pub fn example_queries_json(description: &str, sql: &str) -> String {
    format!(
        "[{{\"description\": \"{}\", \"sql\": \"{}\"}}]",
        json_escape(description),
        json_escape(sql)
    )
}
