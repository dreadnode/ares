//! PyO3 Python extension module for ares-core.
//!
//! This module is only compiled when the `python` feature is enabled.
//! It registers all pyclass types and provides helper functions for
//! deserializing models from JSON strings.

use pyo3::prelude::*;

use crate::models::{
    AgentInfo, AgentRole, Credential, Hash, Host, OperationMeta, Share, SharedRedTeamState, Target,
    TaskInfo, TaskResult, TaskStatus, TaskStatusRecord, User, VulnerabilityInfo,
};

/// Parse a JSON string into a Credential.
#[pyfunction]
fn parse_credential(json_str: &str) -> PyResult<Credential> {
    serde_json::from_str(json_str)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Invalid JSON: {e}")))
}

/// Parse a JSON string into a Hash.
#[pyfunction]
fn parse_hash(json_str: &str) -> PyResult<Hash> {
    serde_json::from_str(json_str)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Invalid JSON: {e}")))
}

/// Parse a JSON string into a Host.
#[pyfunction]
fn parse_host(json_str: &str) -> PyResult<Host> {
    serde_json::from_str(json_str)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Invalid JSON: {e}")))
}

/// Parse a JSON string into a Target.
#[pyfunction]
fn parse_target(json_str: &str) -> PyResult<Target> {
    serde_json::from_str(json_str)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Invalid JSON: {e}")))
}

/// Parse a JSON string into a VulnerabilityInfo.
#[pyfunction]
fn parse_vulnerability(json_str: &str) -> PyResult<VulnerabilityInfo> {
    serde_json::from_str(json_str)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Invalid JSON: {e}")))
}

/// Parse a JSON string into a TaskInfo.
#[pyfunction]
fn parse_task_info(json_str: &str) -> PyResult<TaskInfo> {
    serde_json::from_str(json_str)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Invalid JSON: {e}")))
}

/// Parse a JSON string into a TaskResult.
#[pyfunction]
fn parse_task_result(json_str: &str) -> PyResult<TaskResult> {
    serde_json::from_str(json_str)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Invalid JSON: {e}")))
}

/// The ares_core Python module.
#[pymodule]
fn ares_core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Register all pyclass types
    m.add_class::<Target>()?;
    m.add_class::<Host>()?;
    m.add_class::<User>()?;
    m.add_class::<Credential>()?;
    m.add_class::<Hash>()?;
    m.add_class::<Share>()?;
    m.add_class::<AgentRole>()?;
    m.add_class::<TaskStatus>()?;
    m.add_class::<TaskInfo>()?;
    m.add_class::<TaskResult>()?;
    m.add_class::<VulnerabilityInfo>()?;
    m.add_class::<AgentInfo>()?;
    m.add_class::<TaskStatusRecord>()?;
    m.add_class::<OperationMeta>()?;
    m.add_class::<SharedRedTeamState>()?;

    // Register helper functions
    m.add_function(wrap_pyfunction!(parse_credential, m)?)?;
    m.add_function(wrap_pyfunction!(parse_hash, m)?)?;
    m.add_function(wrap_pyfunction!(parse_host, m)?)?;
    m.add_function(wrap_pyfunction!(parse_target, m)?)?;
    m.add_function(wrap_pyfunction!(parse_vulnerability, m)?)?;
    m.add_function(wrap_pyfunction!(parse_task_info, m)?)?;
    m.add_function(wrap_pyfunction!(parse_task_result, m)?)?;

    Ok(())
}
