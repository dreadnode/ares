//! Blue team report generator.

mod coverage;
mod generator;
mod provenance;
mod types;

pub use coverage::{CoverageEntry, MissedEntry, RedTeamCoverage, DETECTION_TOLERANCE_SECS};
pub use generator::BlueTeamReportGenerator;
pub use types::{
    BlueTeamAlertSummary, BlueTeamEvidenceItem, BlueTeamEvidenceLevel, BlueTeamInvestigationDetail,
    BlueTeamReportInput, BlueTeamTechnique, PyramidEntry,
};
