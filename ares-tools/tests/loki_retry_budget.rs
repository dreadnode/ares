//! End-to-end guard for the Loki per-query wall-clock budget.
//!
//! Lives in `tests/` rather than beside the unit tests because it needs a
//! process where the `HTTP_CLIENT` and Loki config globals are still unset:
//! both initialise once per process from the environment this test controls.
//!
//! The regression it pins: `MAX_RETRIES` bounds the attempt *count*, not the
//! time, so a Loki that accepts the connection and then never answers used to
//! cost `MAX_RETRIES * LOKI_TIMEOUT_SECS`. Under the detection sweep's fixed
//! concurrency that wedged whole slots and starved the catalog.

use std::time::{Duration, Instant};

const TIMEOUT_SECS: u64 = 2;

/// Accept connections forever and never write a response.
///
/// Sockets are parked in a vec rather than dropped, because closing them would
/// hand the client a connection error — a *fast* failure, which is the case
/// this test is specifically not about.
fn spawn_blackhole() -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind blackhole");
    let addr = listener.local_addr().expect("addr");
    std::thread::spawn(move || {
        let mut parked = Vec::new();
        for stream in listener.incoming() {
            match stream {
                Ok(s) => parked.push(s),
                Err(_) => break,
            }
        }
    });
    format!("http://{addr}")
}

#[tokio::test(flavor = "multi_thread")]
async fn hung_loki_costs_one_timeout_not_three() {
    let url = spawn_blackhole();
    std::env::set_var("LOKI_URL", &url);
    std::env::remove_var("LOKI_AUTH_TOKEN");
    std::env::remove_var("GRAFANA_URL");
    std::env::remove_var("GRAFANA_SERVICE_ACCOUNT_TOKEN");
    std::env::remove_var("GRAFANA_API_KEY");
    std::env::set_var("LOKI_TIMEOUT_SECS", TIMEOUT_SECS.to_string());
    std::env::remove_var("LOKI_QUERY_BUDGET_SECS");

    let started = Instant::now();
    let result = ares_tools::blue::loki::query_log_entries(
        r#"{job="windows-security"}"#,
        "2026-07-28T03:46:22Z",
        "2026-07-28T04:10:32Z",
        100,
    )
    .await;
    let elapsed = started.elapsed();

    let err = result.expect_err("a blackholed Loki must not yield entries");

    // Two attempts' worth is the failure signal: the old code spent three.
    assert!(
        elapsed < Duration::from_secs(TIMEOUT_SECS * 2),
        "query took {elapsed:?}, which means it retried past its budget of {TIMEOUT_SECS}s"
    );
    assert!(
        elapsed >= Duration::from_secs(TIMEOUT_SECS),
        "query returned in {elapsed:?}, too fast to have actually hit the request timeout"
    );
    assert!(
        err.to_string().contains("attempt(s)"),
        "error should report the attempts actually made, got: {err}"
    );
}
