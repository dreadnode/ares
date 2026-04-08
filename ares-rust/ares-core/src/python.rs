//! PyO3 Python extension module for ares-core.
//!
//! This module is only compiled when the `python` feature is enabled.
//! It registers all pyclass types, provides helper functions for
//! deserializing models from JSON strings, and exposes the Redis state
//! backend and task queue as synchronous Python classes.

use pyo3::prelude::*;
use pyo3::types::PyBool;
use redis::AsyncCommands;
use std::sync::Mutex;

/// Helper: convert a bool to a PyObject (avoids Borrowed move issues with PyO3 0.23).
fn bool_to_py(py: Python<'_>, val: bool) -> PyObject {
    PyBool::new(py, val).to_owned().into_any().unbind()
}

use crate::models::{
    AgentInfo, AgentRole, BlueTaskInfo, Credential, Evidence, Hash, Host, InvestigationStage,
    OperationMeta, PyramidLevel, Share, SharedBlueTeamState, SharedRedTeamState, Target, TaskInfo,
    TaskResult, TaskStatus, TaskStatusRecord, TimelineEvent, TriageDecision, TriageRecord, User,
    VulnerabilityInfo,
};

// ============================================================================
// Parse helpers
// ============================================================================

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

// ============================================================================
// Parsing wrappers
// ============================================================================

/// Parse secretsdump output into a list of dicts.
#[pyfunction]
fn py_parse_secretsdump(output: &str) -> Vec<std::collections::HashMap<String, PyObject>> {
    use crate::parsing;
    Python::with_gil(|py| {
        parsing::parse_secretsdump(output)
            .into_iter()
            .map(|h| {
                let mut m = std::collections::HashMap::new();
                m.insert(
                    "username".into(),
                    h.username.into_pyobject(py).unwrap().into_any().unbind(),
                );
                m.insert(
                    "domain".into(),
                    h.domain.into_pyobject(py).unwrap().into_any().unbind(),
                );
                m.insert(
                    "rid".into(),
                    h.rid.into_pyobject(py).unwrap().into_any().unbind(),
                );
                m.insert(
                    "lm_hash".into(),
                    h.lm_hash.into_pyobject(py).unwrap().into_any().unbind(),
                );
                m.insert(
                    "nt_hash".into(),
                    h.nt_hash.into_pyobject(py).unwrap().into_any().unbind(),
                );
                m.insert(
                    "hash_value".into(),
                    h.hash_value.into_pyobject(py).unwrap().into_any().unbind(),
                );
                m.insert("is_krbtgt".into(), bool_to_py(py, h.is_krbtgt));
                m.insert(
                    "is_administrator".into(),
                    bool_to_py(py, h.is_administrator),
                );
                m.insert(
                    "is_machine_account".into(),
                    bool_to_py(py, h.is_machine_account),
                );
                m
            })
            .collect()
    })
}

/// Extract Kerberos hashes from tool output into a list of dicts.
#[pyfunction]
fn py_extract_kerberos_hashes(output: &str) -> Vec<std::collections::HashMap<String, PyObject>> {
    use crate::parsing;
    Python::with_gil(|py| {
        parsing::extract_kerberos_hashes(output)
            .into_iter()
            .map(|h| {
                let mut m = std::collections::HashMap::new();
                m.insert(
                    "username".into(),
                    h.username.into_pyobject(py).unwrap().into_any().unbind(),
                );
                m.insert(
                    "domain".into(),
                    h.domain.into_pyobject(py).unwrap().into_any().unbind(),
                );
                m.insert(
                    "hash_value".into(),
                    h.hash_value.into_pyobject(py).unwrap().into_any().unbind(),
                );
                let type_str = match h.hash_type {
                    parsing::KerberosHashType::TGS => "TGS",
                    parsing::KerberosHashType::AsRep => "AsRep",
                };
                m.insert(
                    "hash_type".into(),
                    type_str.into_pyobject(py).unwrap().into_any().unbind(),
                );
                m
            })
            .collect()
    })
}

/// Extract NTLM hashes from tool output into a list of dicts.
#[pyfunction]
fn py_extract_ntlm_hashes(output: &str) -> Vec<std::collections::HashMap<String, PyObject>> {
    use crate::parsing;
    Python::with_gil(|py| {
        parsing::extract_ntlm_hashes(output)
            .into_iter()
            .map(|h| {
                let mut m = std::collections::HashMap::new();
                m.insert(
                    "username".into(),
                    h.username.into_pyobject(py).unwrap().into_any().unbind(),
                );
                m.insert(
                    "domain".into(),
                    h.domain.into_pyobject(py).unwrap().into_any().unbind(),
                );
                m.insert(
                    "rid".into(),
                    h.rid.into_pyobject(py).unwrap().into_any().unbind(),
                );
                m.insert(
                    "lm_hash".into(),
                    h.lm_hash.into_pyobject(py).unwrap().into_any().unbind(),
                );
                m.insert(
                    "nt_hash".into(),
                    h.nt_hash.into_pyobject(py).unwrap().into_any().unbind(),
                );
                m.insert(
                    "hash_value".into(),
                    h.hash_value.into_pyobject(py).unwrap().into_any().unbind(),
                );
                m.insert("is_krbtgt".into(), bool_to_py(py, h.is_krbtgt));
                m.insert(
                    "is_administrator".into(),
                    bool_to_py(py, h.is_administrator),
                );
                m.insert(
                    "is_machine_account".into(),
                    bool_to_py(py, h.is_machine_account),
                );
                m
            })
            .collect()
    })
}

/// Extract hosts from netexec SMB output into a list of dicts.
#[pyfunction]
fn py_extract_hosts(output: &str) -> Vec<std::collections::HashMap<String, PyObject>> {
    use crate::parsing;
    Python::with_gil(|py| {
        parsing::extract_hosts(output)
            .into_iter()
            .map(|h| {
                let mut m = std::collections::HashMap::new();
                m.insert(
                    "ip".into(),
                    h.ip.into_pyobject(py).unwrap().into_any().unbind(),
                );
                m.insert(
                    "hostname".into(),
                    h.hostname.into_pyobject(py).unwrap().into_any().unbind(),
                );
                m.insert(
                    "os".into(),
                    h.os.into_pyobject(py).unwrap().into_any().unbind(),
                );
                m.insert(
                    "domain".into(),
                    h.domain.into_pyobject(py).unwrap().into_any().unbind(),
                );
                m
            })
            .collect()
    })
}

/// Extract delegation entries from findDelegation output into a list of dicts.
#[pyfunction]
fn py_extract_delegations(output: &str) -> Vec<std::collections::HashMap<String, PyObject>> {
    use crate::parsing;
    Python::with_gil(|py| {
        parsing::extract_delegations(output)
            .into_iter()
            .map(|d| {
                let mut m = std::collections::HashMap::new();
                m.insert(
                    "account".into(),
                    d.account.into_pyobject(py).unwrap().into_any().unbind(),
                );
                m.insert(
                    "account_type".into(),
                    d.account_type
                        .into_pyobject(py)
                        .unwrap()
                        .into_any()
                        .unbind(),
                );
                let dtype = match d.delegation_type {
                    parsing::DelegationType::Unconstrained => "Unconstrained",
                    parsing::DelegationType::Constrained => "Constrained",
                    parsing::DelegationType::RBCD => "RBCD",
                };
                m.insert(
                    "delegation_type".into(),
                    dtype.into_pyobject(py).unwrap().into_any().unbind(),
                );
                let spn: PyObject = match d.target_spn {
                    Some(s) => s.into_pyobject(py).unwrap().into_any().unbind(),
                    None => py.None().into_pyobject(py).unwrap().into_any().unbind(),
                };
                m.insert("target_spn".into(), spn);
                m
            })
            .collect()
    })
}

/// Extract the first domain SID from output, or None.
#[pyfunction]
fn py_extract_domain_sid(output: &str) -> Option<String> {
    crate::parsing::extract_domain_sid(output)
}

/// Extract SMB shares from netexec output into a list of dicts.
#[pyfunction]
fn py_extract_shares(output: &str) -> Vec<std::collections::HashMap<String, PyObject>> {
    use crate::parsing;
    Python::with_gil(|py| {
        parsing::extract_shares(output)
            .into_iter()
            .map(|s| {
                let mut m = std::collections::HashMap::new();
                m.insert(
                    "host".into(),
                    s.host.into_pyobject(py).unwrap().into_any().unbind(),
                );
                m.insert(
                    "name".into(),
                    s.name.into_pyobject(py).unwrap().into_any().unbind(),
                );
                m.insert(
                    "permissions".into(),
                    s.permissions.into_pyobject(py).unwrap().into_any().unbind(),
                );
                m.insert(
                    "comment".into(),
                    s.comment.into_pyobject(py).unwrap().into_any().unbind(),
                );
                m
            })
            .collect()
    })
}

// ============================================================================
// Helper: convert redis::RedisError -> PyErr
// ============================================================================

fn redis_err(e: redis::RedisError) -> PyErr {
    pyo3::exceptions::PyRuntimeError::new_err(format!("Redis error: {e}"))
}

// ============================================================================
// Shared Redis connection holder with lazy init
// ============================================================================

/// Holds a tokio runtime and a lazily-initialized Redis connection.
///
/// Uses `Mutex` for interior mutability so the type is `Sync` (required by
/// PyO3 0.23+). The mutex is only held briefly to take/put the connection.
struct RedisHandle {
    runtime: tokio::runtime::Runtime,
    redis_url: String,
    connection: Mutex<Option<redis::aio::MultiplexedConnection>>,
}

impl RedisHandle {
    fn new(redis_url: String) -> PyResult<Self> {
        let runtime = tokio::runtime::Runtime::new().map_err(|e| {
            pyo3::exceptions::PyRuntimeError::new_err(format!(
                "Failed to create tokio runtime: {e}"
            ))
        })?;
        Ok(Self {
            runtime,
            redis_url,
            connection: Mutex::new(None),
        })
    }

    /// Run an async closure that takes a mutable reference to the Redis connection.
    fn run<F, Fut, T>(&self, f: F) -> PyResult<T>
    where
        F: FnOnce(redis::aio::MultiplexedConnection) -> Fut,
        Fut: std::future::Future<
            Output = Result<(T, redis::aio::MultiplexedConnection), redis::RedisError>,
        >,
    {
        // Take the connection out (or create one)
        let conn = {
            let mut guard = self.connection.lock().map_err(|e| {
                pyo3::exceptions::PyRuntimeError::new_err(format!("Lock poisoned: {e}"))
            })?;
            guard.take()
        };

        let conn = match conn {
            Some(c) => c,
            None => {
                let client = redis::Client::open(self.redis_url.as_str()).map_err(|e| {
                    pyo3::exceptions::PyValueError::new_err(format!("Invalid Redis URL: {e}"))
                })?;
                self.runtime
                    .block_on(client.get_multiplexed_async_connection())
                    .map_err(redis_err)?
            }
        };

        let result = self.runtime.block_on(f(conn));
        match result {
            Ok((val, conn)) => {
                // Put the connection back
                if let Ok(mut guard) = self.connection.lock() {
                    *guard = Some(conn);
                }
                Ok(val)
            }
            Err(e) => {
                // Connection may be broken, don't put it back
                Err(redis_err(e))
            }
        }
    }
}

// ============================================================================
// PyRedisStateBackend
// ============================================================================

/// Python-facing Redis state backend.
///
/// Wraps the async `RedisStateReader` methods behind a synchronous interface
/// by using a per-instance tokio `Runtime`.
#[pyclass]
struct PyRedisStateBackend {
    handle: RedisHandle,
}

#[pymethods]
impl PyRedisStateBackend {
    #[new]
    fn new(redis_url: &str) -> PyResult<Self> {
        Ok(Self {
            handle: RedisHandle::new(redis_url.to_string())?,
        })
    }

    /// Load the full SharedRedTeamState for an operation, or None if it doesn't exist.
    fn load_state(&self, operation_id: &str) -> PyResult<Option<SharedRedTeamState>> {
        let op_id = operation_id.to_string();
        self.handle.run(|mut conn| async move {
            let reader = crate::state::RedisStateReader::new(op_id);
            let result = reader.load_state(&mut conn).await?;
            Ok((result, conn))
        })
    }

    /// Get all credentials for an operation.
    fn get_credentials(&self, operation_id: &str) -> PyResult<Vec<Credential>> {
        let op_id = operation_id.to_string();
        self.handle.run(|mut conn| async move {
            let reader = crate::state::RedisStateReader::new(op_id);
            let result = reader.get_credentials(&mut conn).await?;
            Ok((result, conn))
        })
    }

    /// Get all hashes for an operation.
    fn get_hashes(&self, operation_id: &str) -> PyResult<Vec<Hash>> {
        let op_id = operation_id.to_string();
        self.handle.run(|mut conn| async move {
            let reader = crate::state::RedisStateReader::new(op_id);
            let result = reader.get_hashes(&mut conn).await?;
            Ok((result, conn))
        })
    }

    /// Get all hosts for an operation.
    fn get_hosts(&self, operation_id: &str) -> PyResult<Vec<Host>> {
        let op_id = operation_id.to_string();
        self.handle.run(|mut conn| async move {
            let reader = crate::state::RedisStateReader::new(op_id);
            let result = reader.get_hosts(&mut conn).await?;
            Ok((result, conn))
        })
    }

    /// Get all users for an operation.
    fn get_users(&self, operation_id: &str) -> PyResult<Vec<User>> {
        let op_id = operation_id.to_string();
        self.handle.run(|mut conn| async move {
            let reader = crate::state::RedisStateReader::new(op_id);
            let result = reader.get_users(&mut conn).await?;
            Ok((result, conn))
        })
    }

    /// Get all vulnerabilities for an operation as a dict.
    fn get_vulnerabilities(
        &self,
        operation_id: &str,
    ) -> PyResult<std::collections::HashMap<String, VulnerabilityInfo>> {
        let op_id = operation_id.to_string();
        self.handle.run(|mut conn| async move {
            let reader = crate::state::RedisStateReader::new(op_id);
            let result = reader.get_vulnerabilities(&mut conn).await?;
            Ok((result, conn))
        })
    }

    /// Add a credential from JSON. Returns true if it was new (not a duplicate).
    fn add_credential(&self, operation_id: &str, credential_json: &str) -> PyResult<bool> {
        let cred: Credential = serde_json::from_str(credential_json)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Invalid JSON: {e}")))?;
        let op_id = operation_id.to_string();
        self.handle.run(|mut conn| async move {
            let reader = crate::state::RedisStateReader::new(op_id);
            let result = reader.add_credential(&mut conn, &cred).await?;
            Ok((result, conn))
        })
    }

    /// Add a hash from JSON. Returns true if it was new (not a duplicate).
    fn add_hash(&self, operation_id: &str, hash_json: &str) -> PyResult<bool> {
        let hash: Hash = serde_json::from_str(hash_json)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Invalid JSON: {e}")))?;
        let op_id = operation_id.to_string();
        self.handle.run(|mut conn| async move {
            let reader = crate::state::RedisStateReader::new(op_id);
            let result = reader.add_hash(&mut conn, &hash).await?;
            Ok((result, conn))
        })
    }

    /// Add a host from JSON.
    fn add_host(&self, operation_id: &str, host_json: &str) -> PyResult<bool> {
        let host: Host = serde_json::from_str(host_json)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Invalid JSON: {e}")))?;
        let op_id = operation_id.to_string();
        self.handle.run(|mut conn| async move {
            let reader = crate::state::RedisStateReader::new(op_id);
            reader.add_host(&mut conn, &host).await?;
            Ok((true, conn))
        })
    }

    /// Add a vulnerability from JSON. Returns true if it was new.
    fn add_vulnerability(&self, operation_id: &str, vuln_json: &str) -> PyResult<bool> {
        let vuln: VulnerabilityInfo = serde_json::from_str(vuln_json)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Invalid JSON: {e}")))?;
        let op_id = operation_id.to_string();
        self.handle.run(|mut conn| async move {
            let reader = crate::state::RedisStateReader::new(op_id);
            let result = reader.add_vulnerability(&mut conn, &vuln).await?;
            Ok((result, conn))
        })
    }

    /// Set a domain SID for an operation.
    fn set_domain_sid(&self, operation_id: &str, domain: &str, sid: &str) -> PyResult<()> {
        let op_id = operation_id.to_string();
        let domain = domain.to_string();
        let sid = sid.to_string();
        self.handle.run(|mut conn| async move {
            let reader = crate::state::RedisStateReader::new(op_id);
            reader.set_domain_sid(&mut conn, &domain, &sid).await?;
            Ok(((), conn))
        })
    }

    /// Delete an operation and all associated Redis keys. Returns number of keys deleted.
    fn delete_operation(&self, operation_id: &str) -> PyResult<usize> {
        let op_id = operation_id.to_string();
        self.handle.run(|mut conn| async move {
            let result = crate::state::delete_operation(&mut conn, &op_id).await?;
            Ok((result, conn))
        })
    }

    /// List all operation IDs.
    fn list_operations(&self) -> PyResult<Vec<String>> {
        self.handle.run(|mut conn| async move {
            let result = crate::state::list_operation_ids(&mut conn).await?;
            Ok((result, conn))
        })
    }

    /// Check if an operation is currently running (has an active lock).
    fn is_running(&self, operation_id: &str) -> PyResult<bool> {
        let op_id = operation_id.to_string();
        self.handle.run(|mut conn| async move {
            let reader = crate::state::RedisStateReader::new(op_id);
            let result = reader.is_running(&mut conn).await?;
            Ok((result, conn))
        })
    }

    /// Resolve the latest operation ID, preferring running operations.
    fn resolve_latest_operation(&self) -> PyResult<Option<String>> {
        self.handle.run(|mut conn| async move {
            let result = crate::state::resolve_latest_operation(&mut conn).await?;
            Ok((result, conn))
        })
    }
}

// ============================================================================
// PyTaskQueue
// ============================================================================

/// Python-facing task queue for submitting tasks and checking results.
///
/// Uses Redis lists for task queues and string keys for task status/results.
#[pyclass]
struct PyTaskQueue {
    handle: RedisHandle,
}

#[pymethods]
impl PyTaskQueue {
    #[new]
    fn new(redis_url: &str) -> PyResult<Self> {
        Ok(Self {
            handle: RedisHandle::new(redis_url.to_string())?,
        })
    }

    /// Submit a task to the queue. Returns the generated task_id.
    ///
    /// The task is pushed to `ares:queue:{role}` as a JSON payload and a
    /// status record is written to `ares:task_status:{task_id}`.
    fn submit_task(
        &self,
        role: &str,
        task_type: &str,
        payload_json: &str,
        priority: i32,
    ) -> PyResult<String> {
        // Validate the payload is valid JSON
        let payload: serde_json::Value = serde_json::from_str(payload_json).map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!("Invalid payload JSON: {e}"))
        })?;

        let task_id = uuid::Uuid::new_v4().to_string();
        let queue_key = format!("ares:queue:{role}");

        let task_envelope = serde_json::json!({
            "task_id": task_id,
            "task_type": task_type,
            "role": role,
            "payload": payload,
            "priority": priority,
            "submitted_at": chrono::Utc::now().to_rfc3339(),
        });
        let envelope_str = serde_json::to_string(&task_envelope).map_err(|e| {
            pyo3::exceptions::PyRuntimeError::new_err(format!("Serialization error: {e}"))
        })?;

        let status_record = serde_json::json!({
            "operation_id": payload.get("operation_id").and_then(|v| v.as_str()).unwrap_or(""),
            "status": "pending",
            "task_type": task_type,
            "role": role,
            "payload": payload,
        });
        let status_str = serde_json::to_string(&status_record).map_err(|e| {
            pyo3::exceptions::PyRuntimeError::new_err(format!("Serialization error: {e}"))
        })?;

        let task_id_clone = task_id.clone();
        let high_priority = priority > 5;

        self.handle.run(|mut conn| async move {
            if high_priority {
                let _: () = conn.lpush(&queue_key, &envelope_str).await?;
            } else {
                let _: () = conn.rpush(&queue_key, &envelope_str).await?;
            }

            let status_key = format!("{}:{}", crate::state::TASK_STATUS_PREFIX, task_id_clone);
            let _: () = conn.set_ex(&status_key, &status_str, 86400).await?;

            Ok((task_id_clone, conn))
        })
    }

    /// Check the result of a task. Returns the JSON result string or None if not yet complete.
    fn check_result(&self, task_id: &str) -> PyResult<Option<String>> {
        let status_key = format!("{}:{}", crate::state::TASK_STATUS_PREFIX, task_id);

        self.handle.run(|mut conn| async move {
            let result: Option<String> = conn.get(&status_key).await?;

            let ret = match result {
                Some(json_str) => {
                    if let Ok(val) = serde_json::from_str::<serde_json::Value>(&json_str) {
                        let status = val.get("status").and_then(|v| v.as_str()).unwrap_or("");
                        if status == "completed" || status == "failed" {
                            Some(json_str)
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                }
                None => None,
            };

            Ok((ret, conn))
        })
    }

    /// Try to acquire an operation lock with the given TTL (seconds).
    /// Returns true if the lock was acquired.
    fn try_acquire_lock(&self, operation_id: &str, ttl: u64) -> PyResult<bool> {
        let lock_key = crate::state::build_lock_key(operation_id);

        self.handle.run(|mut conn| async move {
            let result: bool = conn.set_nx(&lock_key, "locked").await?;
            if result {
                let _: () = conn.expire(&lock_key, ttl as i64).await?;
            }
            Ok((result, conn))
        })
    }

    /// Extend an existing operation lock's TTL (seconds).
    /// Returns true if the lock exists and was extended.
    fn extend_lock(&self, operation_id: &str, ttl: u64) -> PyResult<bool> {
        let lock_key = crate::state::build_lock_key(operation_id);

        self.handle.run(|mut conn| async move {
            let exists: bool = conn.exists(&lock_key).await?;
            if exists {
                let _: () = conn.expire(&lock_key, ttl as i64).await?;
            }
            Ok((exists, conn))
        })
    }
}

// ============================================================================
// PyBlueStateReader
// ============================================================================

/// Python-facing Redis state backend for blue team investigations.
///
/// Wraps the async `BlueStateReader` methods behind a synchronous interface
/// by using a per-instance tokio `Runtime`.
#[pyclass]
struct PyBlueStateReader {
    handle: RedisHandle,
}

#[pymethods]
impl PyBlueStateReader {
    #[new]
    fn new(redis_url: &str) -> PyResult<Self> {
        Ok(Self {
            handle: RedisHandle::new(redis_url.to_string())?,
        })
    }

    /// Load the full SharedBlueTeamState for an investigation, or None if it doesn't exist.
    fn load_state(&self, investigation_id: &str) -> PyResult<Option<SharedBlueTeamState>> {
        let inv_id = investigation_id.to_string();
        self.handle.run(|mut conn| async move {
            let reader = crate::state::BlueStateReader::new(inv_id);
            let result = reader.load_state(&mut conn).await?;
            Ok((result, conn))
        })
    }

    /// Get all evidence for an investigation.
    fn get_evidence(&self, investigation_id: &str) -> PyResult<Vec<Evidence>> {
        let inv_id = investigation_id.to_string();
        self.handle.run(|mut conn| async move {
            let reader = crate::state::BlueStateReader::new(inv_id);
            let result = reader.get_evidence(&mut conn).await?;
            Ok((result, conn))
        })
    }

    /// Get timeline events for an investigation.
    fn get_timeline(&self, investigation_id: &str) -> PyResult<Vec<TimelineEvent>> {
        let inv_id = investigation_id.to_string();
        self.handle.run(|mut conn| async move {
            let reader = crate::state::BlueStateReader::new(inv_id);
            let result = reader.get_timeline(&mut conn).await?;
            Ok((result, conn))
        })
    }

    /// Get MITRE ATT&CK technique IDs for an investigation.
    fn get_techniques(&self, investigation_id: &str) -> PyResult<Vec<String>> {
        let inv_id = investigation_id.to_string();
        self.handle.run(|mut conn| async move {
            let reader = crate::state::BlueStateReader::new(inv_id);
            let result = reader.get_techniques(&mut conn).await?;
            Ok((result, conn))
        })
    }

    /// Get MITRE ATT&CK tactic IDs for an investigation.
    fn get_tactics(&self, investigation_id: &str) -> PyResult<Vec<String>> {
        let inv_id = investigation_id.to_string();
        self.handle.run(|mut conn| async move {
            let reader = crate::state::BlueStateReader::new(inv_id);
            let result = reader.get_tactics(&mut conn).await?;
            Ok((result, conn))
        })
    }

    /// Get technique name mappings for an investigation.
    fn get_technique_names(
        &self,
        investigation_id: &str,
    ) -> PyResult<std::collections::HashMap<String, String>> {
        let inv_id = investigation_id.to_string();
        self.handle.run(|mut conn| async move {
            let reader = crate::state::BlueStateReader::new(inv_id);
            let result = reader.get_technique_names(&mut conn).await?;
            Ok((result, conn))
        })
    }

    /// Get queried hosts for an investigation.
    fn get_hosts(&self, investigation_id: &str) -> PyResult<Vec<String>> {
        let inv_id = investigation_id.to_string();
        self.handle.run(|mut conn| async move {
            let reader = crate::state::BlueStateReader::new(inv_id);
            let result = reader.get_hosts(&mut conn).await?;
            Ok((result, conn))
        })
    }

    /// Get queried users for an investigation.
    fn get_users(&self, investigation_id: &str) -> PyResult<Vec<String>> {
        let inv_id = investigation_id.to_string();
        self.handle.run(|mut conn| async move {
            let reader = crate::state::BlueStateReader::new(inv_id);
            let result = reader.get_users(&mut conn).await?;
            Ok((result, conn))
        })
    }

    /// Get executed query types for an investigation.
    fn get_query_types(&self, investigation_id: &str) -> PyResult<Vec<String>> {
        let inv_id = investigation_id.to_string();
        self.handle.run(|mut conn| async move {
            let reader = crate::state::BlueStateReader::new(inv_id);
            let result = reader.get_query_types(&mut conn).await?;
            Ok((result, conn))
        })
    }

    /// Get recommendations for an investigation.
    fn get_recommendations(&self, investigation_id: &str) -> PyResult<Vec<String>> {
        let inv_id = investigation_id.to_string();
        self.handle.run(|mut conn| async move {
            let reader = crate::state::BlueStateReader::new(inv_id);
            let result = reader.get_recommendations(&mut conn).await?;
            Ok((result, conn))
        })
    }

    /// Get the current triage decision for an investigation.
    fn get_triage_decision(&self, investigation_id: &str) -> PyResult<Option<String>> {
        let inv_id = investigation_id.to_string();
        self.handle.run(|mut conn| async move {
            let reader = crate::state::BlueStateReader::new(inv_id);
            let result = reader.get_triage_decision(&mut conn).await?;
            Ok((
                result.map(|v| serde_json::to_string(&v).unwrap_or_default()),
                conn,
            ))
        })
    }

    /// Get triage records for an investigation.
    fn get_triage_records(&self, investigation_id: &str) -> PyResult<Vec<TriageRecord>> {
        let inv_id = investigation_id.to_string();
        self.handle.run(|mut conn| async move {
            let reader = crate::state::BlueStateReader::new(inv_id);
            let result = reader.get_triage_records(&mut conn).await?;
            Ok((result, conn))
        })
    }

    /// Get pending tasks for an investigation.
    fn get_pending_tasks(
        &self,
        investigation_id: &str,
    ) -> PyResult<std::collections::HashMap<String, BlueTaskInfo>> {
        let inv_id = investigation_id.to_string();
        self.handle.run(|mut conn| async move {
            let reader = crate::state::BlueStateReader::new(inv_id);
            let result = reader.get_pending_tasks(&mut conn).await?;
            Ok((result, conn))
        })
    }

    /// Get completed tasks for an investigation.
    fn get_completed_tasks(
        &self,
        investigation_id: &str,
    ) -> PyResult<std::collections::HashMap<String, BlueTaskInfo>> {
        let inv_id = investigation_id.to_string();
        self.handle.run(|mut conn| async move {
            let reader = crate::state::BlueStateReader::new(inv_id);
            let result = reader.get_completed_tasks(&mut conn).await?;
            Ok((result, conn))
        })
    }

    /// List all investigation IDs.
    fn list_investigations(&self) -> PyResult<Vec<String>> {
        self.handle.run(|mut conn| async move {
            let result = crate::state::list_investigation_ids(&mut conn).await?;
            Ok((result, conn))
        })
    }

    /// Resolve the latest investigation ID, preferring running investigations.
    fn resolve_latest_investigation(&self) -> PyResult<Option<String>> {
        self.handle.run(|mut conn| async move {
            let result = crate::state::resolve_latest_investigation(&mut conn).await?;
            Ok((result, conn))
        })
    }

    /// Check if an investigation is currently running (has an active lock).
    fn is_running(&self, investigation_id: &str) -> PyResult<bool> {
        let inv_id = investigation_id.to_string();
        self.handle.run(|mut conn| async move {
            let reader = crate::state::BlueStateReader::new(inv_id);
            let result = reader.is_running(&mut conn).await?;
            Ok((result, conn))
        })
    }

    /// Delete an investigation and all associated Redis keys. Returns number of keys deleted.
    fn delete_investigation(&self, investigation_id: &str) -> PyResult<usize> {
        let inv_id = investigation_id.to_string();
        self.handle.run(|mut conn| async move {
            let result = crate::state::delete_investigation(&mut conn, &inv_id).await?;
            Ok((result, conn))
        })
    }
}

// ============================================================================
// Module registration
// ============================================================================

/// The ares_core Python module.
#[pymodule]
fn ares_core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Register all pyclass model types
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

    // Blue team model types
    m.add_class::<PyramidLevel>()?;
    m.add_class::<InvestigationStage>()?;
    m.add_class::<TriageDecision>()?;
    m.add_class::<Evidence>()?;
    m.add_class::<TimelineEvent>()?;
    m.add_class::<BlueTaskInfo>()?;
    m.add_class::<TriageRecord>()?;
    m.add_class::<SharedBlueTeamState>()?;

    // Register backend classes
    m.add_class::<PyRedisStateBackend>()?;
    m.add_class::<PyBlueStateReader>()?;
    m.add_class::<PyTaskQueue>()?;

    // Register helper functions
    m.add_function(wrap_pyfunction!(parse_credential, m)?)?;
    m.add_function(wrap_pyfunction!(parse_hash, m)?)?;
    m.add_function(wrap_pyfunction!(parse_host, m)?)?;
    m.add_function(wrap_pyfunction!(parse_target, m)?)?;
    m.add_function(wrap_pyfunction!(parse_vulnerability, m)?)?;
    m.add_function(wrap_pyfunction!(parse_task_info, m)?)?;
    m.add_function(wrap_pyfunction!(parse_task_result, m)?)?;

    // Parsing functions
    m.add_function(wrap_pyfunction!(py_parse_secretsdump, m)?)?;
    m.add_function(wrap_pyfunction!(py_extract_kerberos_hashes, m)?)?;
    m.add_function(wrap_pyfunction!(py_extract_ntlm_hashes, m)?)?;
    m.add_function(wrap_pyfunction!(py_extract_hosts, m)?)?;
    m.add_function(wrap_pyfunction!(py_extract_delegations, m)?)?;
    m.add_function(wrap_pyfunction!(py_extract_domain_sid, m)?)?;
    m.add_function(wrap_pyfunction!(py_extract_shares, m)?)?;

    Ok(())
}
