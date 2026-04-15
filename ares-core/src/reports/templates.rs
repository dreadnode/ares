//! Embedded template strings for report generation.

pub(crate) const REDTEAM_SUMMARY_TEMPLATE: &str =
    include_str!("../../templates/redteam/reports/operation_summary.md.tera");
pub(crate) const REDTEAM_COMPREHENSIVE_TEMPLATE: &str =
    include_str!("../../templates/redteam/reports/comprehensive_report.md.tera");
#[cfg(feature = "blue")]
pub(crate) const BLUETEAM_COMPREHENSIVE_TEMPLATE: &str =
    include_str!("../../templates/blueteam/reports/comprehensive_report.md.tera");
#[cfg(feature = "blue")]
pub(crate) const BLUETEAM_INVESTIGATION_TEMPLATE: &str =
    include_str!("../../templates/blueteam/reports/investigation_report.md.tera");
