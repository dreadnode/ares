//! `BlueTeamReportGenerator` — struct, constructor, and `Default` impl.
//!
//! The three large report methods live in separate submodules:
//! - [`render`]            — `generate(&BlueTeamReportInput)`
//! - [`from_states`]       — `generate_from_states(&[SharedBlueTeamState])`
//! - [`from_investigation`] — `generate_investigation(&SharedBlueTeamState)`

mod from_investigation;
mod from_states;
mod render;

use crate::reports::templates::{BLUETEAM_COMPREHENSIVE_TEMPLATE, BLUETEAM_INVESTIGATION_TEMPLATE};
use tera::Tera;

/// Generates markdown reports from blue team operation data using Tera templates.
pub struct BlueTeamReportGenerator {
    pub(super) tera: Tera,
}

impl BlueTeamReportGenerator {
    /// Create a new blue team report generator with embedded templates.
    pub fn new() -> Result<Self, tera::Error> {
        let mut tera = Tera::default();
        tera.add_raw_template("comprehensive_report", BLUETEAM_COMPREHENSIVE_TEMPLATE)?;
        tera.add_raw_template("investigation_report", BLUETEAM_INVESTIGATION_TEMPLATE)?;
        Ok(Self { tera })
    }
}

impl Default for BlueTeamReportGenerator {
    fn default() -> Self {
        Self::new().expect("Failed to initialize blue team report templates")
    }
}
