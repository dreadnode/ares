//! Output noise filtering for tool results.
//!
//! Strips MOTD banners, box-drawing garbage, "command not found" noise,
//! empty section headers, and excessive blank lines before the LLM sees
//! tool output. Mirrors the Python orchestrator's `_filter_motd_garbage`
//! and related helpers.

use regex::Regex;
use std::sync::LazyLock;

// ── Box-drawing characters that appear in MOTD banners ──────────────────────

const BOX_CHARS: &[char] = &[
    '┏', '┃', '┗', '┓', '┛', '━', '─', '│', '┌', '┐', '└', '┘', '├', '┤', '┬', '┴', '┼', '╔', '╗',
    '╚', '╝', '║', '═',
];

// ── Substrings that mark a line as MOTD / banner noise ──────────────────────

const MOTD_MARKERS: &[&str] = &[
    "message from kali",
    "minimal installation",
    "kali.org",
    "hushlogin",
    "supplementary tools",
    "learn how",
    "the programs included with",
    "debian gnu/linux",
    "come with absolutely no warranty",
    "free software",
    "last login:",
    "welcome to",
];

// ── Substrings that mark "not found" or similar noise lines ─────────────────

const NOISE_MARKERS: &[&str] = &[
    "command not found",
    "no such file or directory",
    "not recognized as an internal or external command",
    "is not recognized as",
];

// ── Regex: section header lines ──────────────────────────────────────────────

static SECTION_HEADER_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^={5,}\s+[^=]+\s+={5,}\s*$").unwrap());

// ── Regex: collapse 3+ consecutive blank lines into 2 ───────────────────────

static EXCESS_BLANKS_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\n{4,}").unwrap());

/// Returns `true` if the line looks like MOTD / banner garbage.
fn is_motd_line(line: &str) -> bool {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return false;
    }

    // Pure box-drawing lines (all chars are box-drawing or whitespace)
    if trimmed
        .chars()
        .all(|c| BOX_CHARS.contains(&c) || c.is_whitespace())
    {
        return true;
    }

    // Lines that start and end with box-drawing chars (banner frames with text inside)
    let chars: Vec<char> = trimmed.chars().collect();
    if chars.len() >= 2
        && BOX_CHARS.contains(&chars[0])
        && BOX_CHARS.contains(chars.last().unwrap())
    {
        return true;
    }

    // Kali/Parrot prompt patterns: ┌──(user㉿host)-[path] and └─$
    if trimmed.starts_with("┌──") || trimmed.starts_with("└─") {
        return true;
    }

    let lower = trimmed.to_lowercase();
    MOTD_MARKERS.iter().any(|m| lower.contains(m))
}

/// Returns `true` if the line is a "command not found" or similar noise.
fn is_noise_line(line: &str) -> bool {
    let lower = line.to_lowercase();
    NOISE_MARKERS.iter().any(|m| lower.contains(m))
}

/// Filter noise from tool output before it reaches the LLM.
///
/// Steps:
/// 1. Remove lines that are MOTD / banner garbage
/// 2. Remove "command not found" and similar noise lines
/// 3. Remove empty section headers (header with no body before next header or EOF)
/// 4. Collapse excessive blank lines (3+ → 2)
/// 5. Trim leading/trailing whitespace
pub fn filter_output(raw: &str) -> String {
    let filtered: Vec<&str> = raw
        .lines()
        .filter(|line| !is_motd_line(line) && !is_noise_line(line))
        .collect();

    // Remove empty section headers (header followed by another header or EOF)
    let mut result_lines: Vec<&str> = Vec::with_capacity(filtered.len());
    for (i, line) in filtered.iter().enumerate() {
        if SECTION_HEADER_RE.is_match(line) {
            // Check if there's any non-empty, non-header content before the next
            // header or end-of-input
            let has_body = filtered[i + 1..]
                .iter()
                .take_while(|l| !SECTION_HEADER_RE.is_match(l))
                .any(|l| !l.trim().is_empty());
            if !has_body {
                continue; // skip this empty header
            }
        }
        result_lines.push(line);
    }

    let mut result = result_lines.join("\n");

    result = EXCESS_BLANKS_RE.replace_all(&result, "\n\n\n").to_string();

    result.trim().to_string()
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_box_drawing_lines() {
        let input = "┏━━━━━━━━━━━━━━┓\n┃  Kali Linux  ┃\n┗━━━━━━━━━━━━━━┛\nActual output here";
        let out = filter_output(input);
        assert_eq!(out, "Actual output here");
    }

    #[test]
    fn strips_motd_markers() {
        let input = "Welcome to Kali GNU/Linux\nThe programs included with Debian GNU/Linux\ncome with ABSOLUTELY NO WARRANTY\nNmap scan report for 192.168.58.10";
        let out = filter_output(input);
        assert_eq!(out, "Nmap scan report for 192.168.58.10");
    }

    #[test]
    fn strips_command_not_found() {
        let input = "bash: nmap: command not found\nsome real output";
        let out = filter_output(input);
        assert_eq!(out, "some real output");
    }

    #[test]
    fn strips_last_login() {
        let input = "Last login: Mon Apr  7 12:34:56 2025 from 192.168.58.10\nActual output";
        let out = filter_output(input);
        assert_eq!(out, "Actual output");
    }

    #[test]
    fn removes_empty_section_headers() {
        let input = "===== SMB Shares =====\n===== Policies =====\nSome policy data";
        let out = filter_output(input);
        assert_eq!(out, "===== Policies =====\nSome policy data");
    }

    #[test]
    fn collapses_excessive_blank_lines() {
        let input = "line1\n\n\n\n\n\nline2";
        let out = filter_output(input);
        assert_eq!(out, "line1\n\n\nline2");
    }

    #[test]
    fn preserves_clean_output() {
        let input = "Nmap scan report for 192.168.58.10\nPORT   STATE SERVICE\n22/tcp open  ssh\n80/tcp open  http";
        let out = filter_output(input);
        assert_eq!(out, input);
    }

    #[test]
    fn handles_empty_input() {
        assert_eq!(filter_output(""), "");
        assert_eq!(filter_output("   \n\n  "), "");
    }

    #[test]
    fn mixed_noise_and_real_output() {
        let input = "\
┌──(kali㉿kali)-[~]
└─$ nmap -sV 192.168.58.10
Last login: Mon Apr  7 12:00:00 2025
The programs included with Debian GNU/Linux are free software
Starting Nmap 7.94 ( https://nmap.org )
Nmap scan report for 192.168.58.10
PORT   STATE SERVICE
22/tcp open  ssh

Nmap done: 1 IP address (1 host up)";

        let out = filter_output(input);
        assert!(out.starts_with("Starting Nmap"));
        assert!(out.contains("22/tcp open  ssh"));
        assert!(!out.contains("kali"));
        assert!(!out.contains("Last login"));
    }

    #[test]
    fn strips_hushlogin_hint() {
        let input = "To suppress this message create a .hushlogin file\nreal data";
        let out = filter_output(input);
        assert_eq!(out, "real data");
    }

    #[test]
    fn strips_learn_how_line() {
        let input = "Learn how to install supplementary tools at kali.org/docs\nreal data";
        let out = filter_output(input);
        assert_eq!(out, "real data");
    }
}
