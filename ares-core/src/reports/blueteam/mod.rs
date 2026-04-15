//! Blue team report generator.

mod generator;
mod types;

pub use generator::BlueTeamReportGenerator;
pub use types::{
    BlueTeamAlertSummary, BlueTeamEvidenceItem, BlueTeamEvidenceLevel, BlueTeamInvestigationDetail,
    BlueTeamReportInput, BlueTeamTechnique, PyramidEntry,
};
