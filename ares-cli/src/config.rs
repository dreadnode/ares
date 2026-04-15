use anyhow::{Context, Result};

use ares_core::config::AresConfig;

use crate::cli::ConfigCommands;

pub(crate) fn run_config(cmd: ConfigCommands) -> Result<()> {
    match cmd {
        ConfigCommands::Show { models, config } => config_show(config, models),
        ConfigCommands::Validate { config } => config_validate(config),
        ConfigCommands::SetModel {
            role,
            model,
            all,
            config,
        } => config_set_model(config, role, model, all),
    }
}

fn resolve_config_path(explicit: Option<String>) -> Result<std::path::PathBuf> {
    if let Some(p) = explicit {
        let path = std::path::PathBuf::from(&p);
        if path.exists() {
            return Ok(path);
        }
        anyhow::bail!("Config file not found: {p}");
    }
    AresConfig::resolve_path()
}

fn config_show(config_path: Option<String>, models_only: bool) -> Result<()> {
    let path = resolve_config_path(config_path)?;
    let cfg = AresConfig::load(&path)?;

    if models_only {
        println!("Model assignments (from {}):", path.display());
        println!();
        let mut roles: Vec<_> = cfg.agents.iter().collect();
        roles.sort_by_key(|(k, _)| (*k).clone());
        let max_len = roles.iter().map(|(k, _)| k.len()).max().unwrap_or(0);
        for (role, agent) in &roles {
            println!("  {:<width$}  {}", role, agent.model, width = max_len);
        }
        println!();
        return Ok(());
    }

    println!("# Resolved config: {}\n", path.display());

    // Operation
    println!("operation:");
    println!("  name: {}", cfg.operation.name);
    println!("  namespace: {}", cfg.operation.namespace);
    println!(
        "  checkpoint_interval: {}s",
        cfg.operation.checkpoint_interval
    );
    println!(
        "  max_concurrent_tasks: {}",
        cfg.operation.max_concurrent_tasks
    );
    println!(
        "  task_dispatch_delay: {}s",
        cfg.operation.task_dispatch_delay
    );
    println!(
        "  rate_limit_backoff: {}s",
        cfg.operation.rate_limit_backoff
    );
    println!(
        "  rate_limit_threshold: {}",
        cfg.operation.rate_limit_threshold
    );
    println!(
        "  stop_on_domain_admin: {}",
        cfg.operation.stop_on_domain_admin
    );
    println!(
        "  stop_on_golden_ticket: {}",
        cfg.operation.stop_on_golden_ticket
    );

    // Agents
    println!("\nagents:");
    let mut roles: Vec<_> = cfg.agents.iter().collect();
    roles.sort_by_key(|(k, _)| (*k).clone());
    for (role, agent) in &roles {
        println!("  {}:", role);
        println!("    model: {}", agent.model);
        println!("    max_steps: {}", agent.max_steps);
        if !agent.pod_selector.is_empty() {
            println!("    pod_selector: {}", agent.pod_selector);
        }
        if !agent.capabilities.is_empty() {
            println!("    capabilities: {} tools", agent.capabilities.len());
        }
        if !agent.tools.is_empty() {
            println!("    tools: {} dispatch actions", agent.tools.len());
        }
    }

    // Timeouts
    println!("\ntimeouts:");
    println!("  agent_heartbeat: {}s", cfg.timeouts.agent_heartbeat);
    println!("  task_timeout: {}s", cfg.timeouts.task_timeout);
    println!(
        "  operation_timeout: {}s ({}h)",
        cfg.timeouts.operation_timeout,
        cfg.timeouts.operation_timeout / 3600
    );
    println!("  lateral_movement: {}s", cfg.timeouts.lateral_movement);
    println!("  hash_cracking: {}s", cfg.timeouts.hash_cracking);
    println!("  exploitation: {}s", cfg.timeouts.exploitation);

    // Recovery
    println!("\nrecovery:");
    println!("  enabled: {}", cfg.recovery.enabled);
    println!("  max_retries: {}", cfg.recovery.max_retries);
    println!("  retry_delay: {}s", cfg.recovery.retry_delay);

    // Vulnerability priorities
    println!("\nvulnerability_priorities:");
    let mut vulns: Vec<_> = cfg.vulnerability_priorities.iter().collect();
    vulns.sort_by_key(|(_, v)| **v);
    for (vuln, priority) in &vulns {
        println!("  {}: {}", vuln, priority);
    }

    // Context management
    println!("\ncontext_management:");
    println!(
        "  max_context_tokens: {}",
        cfg.context_management.max_context_tokens
    );
    println!(
        "  min_messages_to_keep: {}",
        cfg.context_management.min_messages_to_keep
    );
    println!(
        "  max_output_chars: {}",
        cfg.context_management.max_output_chars
    );

    // Grafana
    if let Some(ref g) = cfg.grafana {
        println!("\ngrafana:");
        println!("  enabled: {}", g.enabled);
        println!("  dashboard_uid: {}", g.dashboard_uid);
    }

    Ok(())
}

fn config_validate(config_path: Option<String>) -> Result<()> {
    let path = resolve_config_path(config_path)?;
    let cfg = AresConfig::load(&path)?;

    let mut warnings = Vec::new();

    // Check all agents have models
    for (role, agent) in &cfg.agents {
        if agent.model.is_empty() {
            warnings.push(format!("Agent '{}' has no model set", role));
        }
    }

    // Check expected roles exist
    let expected_roles = [
        "orchestrator",
        "recon",
        "credential_access",
        "cracker",
        "acl",
        "privesc",
        "lateral",
        "coercion",
    ];
    for role in &expected_roles {
        if !cfg.agents.contains_key(*role) {
            warnings.push(format!("Expected agent role '{}' not found", role));
        }
    }

    // Check timeouts are reasonable
    if cfg.timeouts.operation_timeout < cfg.timeouts.task_timeout {
        warnings.push("operation_timeout is less than task_timeout".to_string());
    }

    if warnings.is_empty() {
        println!(
            "Config OK: {} ({}  agent roles)",
            path.display(),
            cfg.agents.len()
        );
    } else {
        println!("Config: {} ({} warnings)\n", path.display(), warnings.len());
        for w in &warnings {
            println!("  WARNING: {}", w);
        }
    }

    Ok(())
}

fn config_set_model(
    config_path: Option<String>,
    role: Option<String>,
    model: String,
    all: bool,
) -> Result<()> {
    let path = resolve_config_path(config_path)?;

    // Read the raw YAML to do text-level replacement (preserves comments and formatting).
    let contents = std::fs::read_to_string(&path)
        .with_context(|| format!("Failed to read {}", path.display()))?;

    // Also parse to validate and get the agent list
    let cfg = AresConfig::load(&path)?;

    if all {
        // Replace model for all agents
        let mut new_contents = contents.clone();
        for (role_name, agent) in &cfg.agents {
            new_contents = replace_model_in_yaml(&new_contents, role_name, &agent.model, &model);
        }
        std::fs::write(&path, &new_contents)
            .with_context(|| format!("Failed to write {}", path.display()))?;

        println!("Set all {} roles to model '{}'", cfg.agents.len(), model);
        return Ok(());
    }

    let role = role.context("Role argument is required when --all is not set")?;

    if !cfg.agents.contains_key(&role) {
        let available: Vec<_> = cfg.agent_roles();
        anyhow::bail!(
            "Unknown role '{}'. Available roles: {}",
            role,
            available.join(", ")
        );
    }

    let old_model = cfg.agents[&role].model.as_str();
    let new_contents = replace_model_in_yaml(&contents, &role, old_model, &model);
    std::fs::write(&path, &new_contents)
        .with_context(|| format!("Failed to write {}", path.display()))?;

    println!("{}: {} -> {}", role, old_model, model);
    Ok(())
}

/// Replace the model value for a specific role in the YAML text.
///
/// This does a targeted text replacement to preserve comments and formatting.
/// It finds the role's section under `agents:` and replaces its `model:` line.
fn replace_model_in_yaml(yaml: &str, role: &str, _old_model: &str, new_model: &str) -> String {
    // Strategy: find `  {role}:\n` then the next `    model: "{old}"` line
    let role_header = format!("  {}:", role);
    let mut result = String::with_capacity(yaml.len());
    let lines = yaml.lines().peekable();
    let mut in_target_role = false;
    let mut replaced = false;

    for line in lines {
        if line.starts_with(&role_header)
            && (line.len() == role_header.len()
                || line[role_header.len()..].starts_with(' ')
                || line[role_header.len()..].starts_with('\n'))
        {
            in_target_role = true;
            result.push_str(line);
            result.push('\n');
            continue;
        }

        if in_target_role && !replaced {
            let trimmed = line.trim();
            if trimmed.starts_with("model:") {
                // Replace the model value, preserving indentation
                let indent = &line[..line.len() - line.trim_start().len()];
                let new_line = format!("{}model: \"{}\"", indent, new_model);
                result.push_str(&new_line);
                result.push('\n');
                replaced = true;
                in_target_role = false;
                continue;
            }
        }

        // If we hit a new role (non-indented or less-indented), we left the target
        if in_target_role && !line.starts_with("    ") && !line.is_empty() && !line.starts_with('#')
        {
            in_target_role = false;
        }

        result.push_str(line);
        result.push('\n');
    }

    // Remove trailing extra newline if original didn't have one
    if !yaml.ends_with('\n') && result.ends_with('\n') {
        result.pop();
    }

    result
}
