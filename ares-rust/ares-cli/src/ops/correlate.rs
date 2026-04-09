use anyhow::{Context, Result};

use ares_core::correlation::redblue::RedBlueCorrelator;

pub(crate) fn ops_correlate(
    reports_dir: String,
    time_window: i64,
    json_output: bool,
) -> Result<()> {
    let reports_path = std::path::Path::new(&reports_dir);
    if !reports_path.exists() {
        anyhow::bail!("Reports directory does not exist: {reports_dir}");
    }

    let correlator = RedBlueCorrelator::new(reports_path, Some(time_window));
    let reports = correlator
        .run_full_analysis()
        .context("Failed to run correlation analysis")?;

    if reports.is_empty() {
        println!("No red team reports found in {reports_dir}");
        return Ok(());
    }

    for report in &reports {
        if json_output {
            let json = serde_json::to_string_pretty(&report.to_value())?;
            println!("{json}");
        } else {
            let md = RedBlueCorrelator::generate_report_markdown(report);
            println!("{md}");
        }

        // Summary line
        println!();
        println!(
            "Correlation: {} | Activities: {} | Detected: {} ({:.0}%) | Gaps: {} | FP: {} | MTTD: {}",
            report.red_operation_id,
            report.total_red_activities,
            report.matched_activities,
            report.detection_rate * 100.0,
            report.undetected_activities,
            report.false_positive_detections,
            report
                .mean_time_to_detect
                .map(|t| format!("{t:.0}s"))
                .unwrap_or_else(|| "N/A".to_string()),
        );
    }

    Ok(())
}
