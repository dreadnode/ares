//! Replay side of Tempo trace capture: read `tempo/traces.jsonl.gz` from a
//! snapshot bundle and push each trace back into an ephemeral Tempo via the
//! OTLP HTTP endpoint. Companion to the capture-side `export_tempo_traces`
//! function in `capture.rs`; together they make the demo dashboard's
//! attack-graph panel render on a captured op, not just live.
//!
//! The capture side writes one full trace per gzipped line, in the shape
//! Tempo's `/api/traces/{id}` endpoint returns — `{"batches": [...]}` where
//! each batch is an OTLP `ResourceSpans`. The OTLP HTTP push endpoint
//! (`/v1/traces`) expects the sibling wire shape — `{"resourceSpans": [...]}`.
//! [`push_traces_bundle`] does that rename in-flight so the replay stack
//! receives what it expects.

use std::io::BufRead;
use std::path::Path;

use anyhow::{Context, Result};
use flate2::read::GzDecoder;
use tracing::info;

/// Default OTLP HTTP endpoint on the ephemeral replay stack. Overridable via
/// `ARES_REPLAY_TEMPO_OTLP_URL` when the stack exposes OTLP on a different
/// port or path.
pub(crate) const DEFAULT_TEMPO_OTLP_URL_SUFFIX: &str = ":4318/v1/traces";

/// Push a snapshot's `tempo/traces.jsonl.gz` into the given OTLP HTTP endpoint.
///
/// Returns the number of traces successfully pushed. Returns `Ok(0)` (never
/// errors) for missing / empty bundles so a snapshot captured before
/// `tempo_traces_captured` was wired can still replay end-to-end.
pub(crate) async fn push_traces_bundle(
    snapshot_dir: &Path,
    otlp_url: &str,
    bearer_token: Option<&str>,
) -> Result<usize> {
    let bundle_path = snapshot_dir.join("tempo").join("traces.jsonl.gz");
    if !bundle_path.exists() {
        info!(path = %bundle_path.display(), "no Tempo bundle in snapshot — skipping push");
        return Ok(0);
    }

    let file = std::fs::File::open(&bundle_path)
        .with_context(|| format!("open {}", bundle_path.display()))?;
    let reader = std::io::BufReader::new(GzDecoder::new(file));

    let client = reqwest::Client::new();
    let mut pushed = 0usize;
    let mut skipped = 0usize;
    let mut failed = 0usize;

    for (line_idx, line) in reader.lines().enumerate() {
        let line = line.with_context(|| format!("read line {line_idx} from bundle"))?;
        if line.trim().is_empty() {
            continue;
        }
        let payload = match rewrite_batches_to_resource_spans(&line) {
            Ok(p) => p,
            Err(e) => {
                skipped += 1;
                info!(line = line_idx, err = %e, "skipping malformed trace line");
                continue;
            }
        };
        let mut req = client
            .post(otlp_url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(payload);
        if let Some(token) = bearer_token {
            req = req.bearer_auth(token);
        }
        match req.send().await {
            Ok(resp) if resp.status().is_success() => pushed += 1,
            Ok(resp) => {
                failed += 1;
                info!(status = %resp.status(), line = line_idx, "tempo push non-2xx");
            }
            Err(e) => {
                failed += 1;
                info!(line = line_idx, err = %e, "tempo push transport error");
            }
        }
    }

    if failed > 0 || skipped > 0 {
        info!(
            pushed,
            skipped, failed, "tempo push completed with partial failures"
        );
    } else {
        info!(pushed, "tempo push completed");
    }
    Ok(pushed)
}

/// Rewrite a captured trace line from Tempo's `{"batches": [...]}` shape to
/// the OTLP-HTTP-request `{"resourceSpans": [...]}` shape. Wraps a bare array
/// as `resourceSpans` too so the function tolerates both older captures and
/// direct OTLP payloads.
fn rewrite_batches_to_resource_spans(line: &str) -> Result<String> {
    let mut v: serde_json::Value = serde_json::from_str(line).context("parse trace line")?;
    if let Some(obj) = v.as_object_mut() {
        if let Some(batches) = obj.remove("batches") {
            obj.insert("resourceSpans".to_string(), batches);
        } else if obj.contains_key("resourceSpans") {
            // already in push shape
        } else {
            anyhow::bail!("trace line has neither `batches` nor `resourceSpans` key");
        }
    } else if v.is_array() {
        v = serde_json::json!({ "resourceSpans": v });
    } else {
        anyhow::bail!("trace line is neither object nor array");
    }
    serde_json::to_string(&v).context("re-serialize trace line")
}

/// Derive the OTLP HTTP endpoint from a stack IP unless the operator has
/// overridden it via `ARES_REPLAY_TEMPO_OTLP_URL`.
pub(crate) fn otlp_url_for_stack(stack_ip: &str) -> String {
    std::env::var("ARES_REPLAY_TEMPO_OTLP_URL")
        .unwrap_or_else(|_| format!("http://{stack_ip}{DEFAULT_TEMPO_OTLP_URL_SUFFIX}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rewrites_batches_to_resource_spans() {
        let line = r#"{"batches":[{"resource":{"attributes":[]}}]}"#;
        let out = rewrite_batches_to_resource_spans(line).unwrap();
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert!(v.get("resourceSpans").is_some());
        assert!(v.get("batches").is_none());
        assert_eq!(v["resourceSpans"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn passes_through_already_correct_shape() {
        let line = r#"{"resourceSpans":[{"resource":{"attributes":[]}}]}"#;
        let out = rewrite_batches_to_resource_spans(line).unwrap();
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["resourceSpans"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn wraps_bare_array_as_resource_spans() {
        let line = r#"[{"resource":{"attributes":[]}}]"#;
        let out = rewrite_batches_to_resource_spans(line).unwrap();
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["resourceSpans"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn rejects_line_without_recognised_shape() {
        let err = rewrite_batches_to_resource_spans(r#"{"nope": 1}"#).unwrap_err();
        assert!(err.to_string().contains("neither"));
    }

    #[test]
    fn otlp_url_default_and_override() {
        // One test, not two — cargo runs tests in parallel and `std::env` is
        // process-global, so splitting default vs override across two `#[test]`s
        // races. The default case pins the port and path that the demo
        // docker-compose exposes (`4318`, `/v1/traces`); the override case
        // proves the `ARES_REPLAY_TEMPO_OTLP_URL` escape hatch works.
        unsafe {
            std::env::remove_var("ARES_REPLAY_TEMPO_OTLP_URL");
        }
        assert_eq!(
            otlp_url_for_stack("192.168.58.99"),
            "http://192.168.58.99:4318/v1/traces"
        );

        unsafe {
            std::env::set_var(
                "ARES_REPLAY_TEMPO_OTLP_URL",
                "https://tempo.example/v1/traces",
            );
        }
        assert_eq!(
            otlp_url_for_stack("192.168.58.99"),
            "https://tempo.example/v1/traces"
        );
        unsafe {
            std::env::remove_var("ARES_REPLAY_TEMPO_OTLP_URL");
        }
    }

    #[tokio::test]
    async fn missing_bundle_returns_ok_zero() {
        let dir = tempfile::tempdir().unwrap();
        let pushed = push_traces_bundle(dir.path(), "http://127.0.0.1:1/v1/traces", None)
            .await
            .unwrap();
        assert_eq!(pushed, 0);
    }
}
