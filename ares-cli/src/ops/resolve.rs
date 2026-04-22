//! AWS EC2 target resolution: resolve Name tag patterns to private IPs.

use anyhow::{Context, Result};
use tracing::info;

/// Resolve EC2 instance Name tags to private IP addresses.
///
/// Calls `aws ec2 describe-instances` with a Name tag filter and returns
/// the private IPs of all matching running instances.
pub(crate) fn resolve_ec2_targets(
    name_pattern: &str,
    aws_profile: &str,
    aws_region: &str,
) -> Result<Vec<String>> {
    info!(
        "Resolving EC2 targets matching '{}' (profile={}, region={})",
        name_pattern, aws_profile, aws_region
    );

    let output = std::process::Command::new("aws")
        .args([
            "ec2",
            "describe-instances",
            "--profile",
            aws_profile,
            "--region",
            aws_region,
            "--filters",
            "Name=instance-state-name,Values=running",
            "--query",
            &format!(
                "Reservations[*].Instances[?contains(Tags[?Key==`Name`].Value|[0], `{}`)].PrivateIpAddress",
                name_pattern
            ),
            "--output",
            "text",
        ])
        .output()
        .context("failed to run aws CLI — is it installed?")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("Unable to locate credentials")
            || stderr.contains("ExpiredToken")
            || stderr.contains("InvalidClientTokenId")
        {
            anyhow::bail!(
                "AWS authentication failed for profile '{aws_profile}'. \
                 Run: aws sso login --profile {aws_profile}"
            );
        }
        anyhow::bail!("aws ec2 describe-instances failed: {}", stderr.trim());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let ips: Vec<String> = stdout
        .split_whitespace()
        .filter(|s| !s.is_empty() && s.contains('.'))
        .map(|s| s.to_string())
        .collect();

    if ips.is_empty() {
        anyhow::bail!("No running EC2 instances found matching Name tag: {name_pattern}");
    }

    info!("Resolved {} target(s): {}", ips.len(), ips.join(", "));
    Ok(ips)
}

/// Check if a string looks like an IP address (simple heuristic).
pub(crate) fn looks_like_ip(s: &str) -> bool {
    s.split(',').all(|part| {
        let trimmed = part.trim();
        !trimmed.is_empty()
            && trimmed
                .split('.')
                .filter(|octet| octet.parse::<u8>().is_ok())
                .count()
                == 4
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn looks_like_ip_single() {
        assert!(looks_like_ip("192.168.58.10"));
        assert!(looks_like_ip("192.168.58.10"));
    }

    #[test]
    fn looks_like_ip_comma_separated() {
        assert!(looks_like_ip("192.168.58.10,192.168.58.11"));
    }

    #[test]
    fn looks_like_ip_not_ip() {
        assert!(!looks_like_ip("dreadgoad"));
        assert!(!looks_like_ip("my-server"));
        assert!(!looks_like_ip(""));
    }
}
