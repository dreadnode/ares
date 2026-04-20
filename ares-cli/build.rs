//! Build script — generates `tools_for_role()` from `tools.yaml`.
//!
//! The generated file is written to `$OUT_DIR/tool_tables.rs` and
//! included by `tool_check.rs` via `include!`.

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
    binaries: Vec<String>,
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
    let dest = Path::new(&out_dir).join("tool_tables.rs");
    let mut f = fs::File::create(&dest).unwrap();

    // Generate WORKER_ROLES constant (used in tests).
    let role_names: Vec<&str> = tools_file.roles.keys().map(|s| s.as_str()).collect();
    writeln!(f, "/// All worker roles that have tool requirements.").unwrap();
    writeln!(f, "#[cfg(test)]").unwrap();
    writeln!(f, "const WORKER_ROLES: &[&str] = &[").unwrap();
    for role in &role_names {
        writeln!(f, "    {role:?},").unwrap();
    }
    writeln!(f, "];\n").unwrap();

    // Generate tools_for_role().
    writeln!(
        f,
        "/// Tools expected on each worker role's container image."
    )
    .unwrap();
    writeln!(f, "///").unwrap();
    writeln!(
        f,
        "/// Auto-generated from `tools.yaml` — do not edit by hand."
    )
    .unwrap();
    writeln!(
        f,
        "fn tools_for_role(role: &str) -> &'static [&'static str] {{"
    )
    .unwrap();
    writeln!(f, "    match role {{").unwrap();

    for (role, def) in &tools_file.roles {
        let binaries: Vec<&str> = def
            .tools
            .iter()
            .flat_map(|cat| cat.binaries.iter().map(|s| s.as_str()))
            .collect();
        writeln!(f, "        {role:?} => &[").unwrap();
        for bin in &binaries {
            writeln!(f, "            {bin:?},").unwrap();
        }
        writeln!(f, "        ],").unwrap();
    }

    writeln!(f, "        _ => &[],").unwrap();
    writeln!(f, "    }}").unwrap();
    writeln!(f, "}}").unwrap();
}
