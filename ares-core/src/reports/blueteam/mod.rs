//! Blue team report generator.

mod coverage;
mod generator;
mod provenance;
mod types;

pub use coverage::{CoverageEntry, RedTeamCoverage};
pub use generator::BlueTeamReportGenerator;
pub use types::{
    BlueTeamAlertSummary, BlueTeamEvidenceItem, BlueTeamEvidenceLevel, BlueTeamInvestigationDetail,
    BlueTeamReportInput, BlueTeamTechnique, PyramidEntry,
};
