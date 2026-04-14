//! Build script — generates `tool_meta()` from `tools.yaml`.
//!
//! Produces a compile-time lookup table mapping Rust tool function names
//! to their binary, category, and provisioning role from `tools.yaml`.
//! The generated file is written to `$OUT_DIR/tool_meta.rs` and included
//! by `telemetry/mitre.rs` via `include!`.

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io::Write;
use std::path::Path;

use serde::Deserialize;

#[derive(Deserialize)]
struct ToolsFile {
    roles: BTreeMap<String, RoleDef>,
}

#[derive(Deserialize)]
struct RoleDef {
    tools: Vec<ToolCategory>,
}

#[derive(Deserialize)]
struct ToolCategory {
    category: String,
    binaries: Vec<String>,
    #[serde(default)]
    fn_names: Vec<String>,
}

fn main() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let yaml_path = Path::new(&manifest_dir)
        .parent() // workspace root
        .unwrap()
        .join("tools.yaml");

    println!("cargo::rerun-if-changed={}", yaml_path.display());

    let yaml_content = fs::read_to_string(&yaml_path).unwrap_or_else(|e| {
        panic!("Failed to read {}: {e}", yaml_path.display());
    });

    let tools_file: ToolsFile = serde_yaml::from_str(&yaml_content).unwrap_or_else(|e| {
        panic!("Failed to parse {}: {e}", yaml_path.display());
    });

    let out_dir = env::var("OUT_DIR").unwrap();
    let dest = Path::new(&out_dir).join("tool_meta.rs");
    let mut f = fs::File::create(&dest).unwrap();

    // Collect all (fn_name → (primary_binary, category, role)) entries.
    let mut entries: Vec<(String, String, String, String)> = Vec::new();

    for (role, def) in &tools_file.roles {
        for cat in &def.tools {
            let primary_binary = cat.binaries.first().map(|s| s.as_str()).unwrap_or("");
            for fn_name in &cat.fn_names {
                entries.push((
                    fn_name.clone(),
                    primary_binary.to_string(),
                    cat.category.clone(),
                    role.clone(),
                ));
            }
        }
    }

    // Sort by fn_name for deterministic output and binary search.
    entries.sort_by(|a, b| a.0.cmp(&b.0));

    // Generate the struct and lookup function.
    writeln!(
        f,
        "/// Tool metadata derived from `tools.yaml` at compile time."
    )
    .unwrap();
    writeln!(f, "///").unwrap();
    writeln!(f, "/// Auto-generated — do not edit by hand.").unwrap();
    writeln!(f, "#[derive(Debug, Clone, Copy)]").unwrap();
    writeln!(f, "pub struct ToolMeta {{").unwrap();
    writeln!(f, "    pub fn_name: &'static str,").unwrap();
    writeln!(f, "    pub binary: &'static str,").unwrap();
    writeln!(f, "    pub category: &'static str,").unwrap();
    writeln!(f, "    pub role: &'static str,").unwrap();
    writeln!(f, "}}").unwrap();
    writeln!(f).unwrap();

    writeln!(f, "/// All tool metadata entries, sorted by function name.").unwrap();
    writeln!(f, "static TOOL_META_TABLE: &[ToolMeta] = &[").unwrap();
    for (fn_name, binary, category, role) in &entries {
        writeln!(
            f,
            "    ToolMeta {{ fn_name: {fn_name:?}, binary: {binary:?}, category: {category:?}, role: {role:?} }},"
        )
        .unwrap();
    }
    writeln!(f, "];").unwrap();
    writeln!(f).unwrap();

    writeln!(f, "/// Look up tool metadata by Rust function name.").unwrap();
    writeln!(
        f,
        "pub fn tool_meta(fn_name: &str) -> Option<&'static ToolMeta> {{"
    )
    .unwrap();
    writeln!(
        f,
        "    TOOL_META_TABLE.binary_search_by_key(&fn_name, |m| m.fn_name).ok().map(|i| &TOOL_META_TABLE[i])"
    )
    .unwrap();
    writeln!(f, "}}").unwrap();
}
