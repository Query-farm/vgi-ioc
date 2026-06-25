//! Shared helpers for the per-object discovery/description metadata that the
//! `vgi-lint` strict profile expects on **every** function and table.
//!
//! Each function/table surfaces these in its `FunctionMetadata.tags`:
//! - `vgi.title` (VGI124)   — human-friendly display name
//! - `vgi.doc_llm` (VGI112) — Markdown narrative aimed at LLMs/agents
//! - `vgi.doc_md` (VGI113)  — Markdown narrative for human docs
//! - `vgi.keywords` (VGI126) — comma-separated search terms/synonyms
//!
//! Per-object `vgi.source_url` is intentionally NOT emitted: provenance lives
//! once on the catalog (`CatalogModel.source_url`); repeating it on every
//! object is redundant (VGI139).

/// Build the four standard per-object discovery/description tags.
pub fn object_tags(
    title: &str,
    description_llm: &str,
    description_md: &str,
    keywords: &str,
) -> Vec<(String, String)> {
    vec![
        ("vgi.title".to_string(), title.to_string()),
        ("vgi.doc_llm".to_string(), description_llm.to_string()),
        ("vgi.doc_md".to_string(), description_md.to_string()),
        ("vgi.keywords".to_string(), keywords.to_string()),
    ]
}
