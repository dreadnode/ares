//! Forward-time state capture — extracts the prior state a faithful revert
//! needs and that is only observable at mutation time, out of the tool's own
//! output. Stored on [`MutationRecord::hint`](super::journal::MutationRecord).
//!
//! Only post-hoc captures (readable from the forward tool's stdout) live here.
//! Captures that require a read *before* the write (original UPN / attribute
//! value) belong in the executor itself and are out of scope for this pass.

use serde_json::{json, Value};

/// Whether a mutating call actually changed target state.
///
/// A zero exit code only proves the tool ran. Several mutating tools are
/// "make it so" operations that succeed loudly while changing nothing: noPac
/// aborts before creating its machine account, `sp_configure` reports
/// `changed from 1 to 1` when the option was already set, and rbcd.py logs
/// `Not modifying the delegation rights` when the SID is already delegated.
///
/// Journaling those produces a record of a mutation that never happened, and
/// teardown then either reverts state we did not create — deleting a
/// lab-provisioned setting — or reports it as un-revertible residue. Both were
/// observed live before this gate existed.
///
/// Tools with no known no-op signature return `true`: the default must be to
/// journal, so a mutation is never silently dropped from the revert plan.
pub fn mutation_took_effect(tool: &str, output: &str) -> bool {
    match tool {
        "nopac" => scrape_created_computer(output).is_some(),
        "mssql_enable_xp_cmdshell" | "mssql_linked_enable_xpcmdshell" => {
            !output.contains("changed from 1 to 1")
        }
        "rbcd_write" => {
            // impacket-rbcd exits 0 even when it wrote nothing: an unresolvable
            // -delegate-to/-delegate-from bails out of write() early, and an
            // already-present ACE is left alone. Both would otherwise journal a
            // mutation that never happened, which teardown then "reverts".
            let lower = output.to_lowercase();
            !lower.contains("not modifying the delegation rights")
                && !lower.contains("can already impersonate")
                && !lower.contains("does not exist!")
                && !lower.contains("user not found in ldap")
        }
        _ => true,
    }
}

/// Extract a cleanup hint from a successful mutating call's output, if any.
pub fn hint_for(tool: &str, args: &Value, output: &str) -> Option<Value> {
    match tool {
        "pywhisker" => {
            // The DeviceID needed to remove the Key Credential is only minted
            // by the add action and printed to stdout.
            let action = args.get("action").and_then(Value::as_str).unwrap_or("add");
            if action != "add" {
                return None;
            }
            scrape_device_id(output).map(|id| json!({ "device_id": id }))
        }
        "nopac" => {
            // noPac mints a random machine account whose name is only in stdout;
            // capture it so teardown can delete the orphaned computer.
            scrape_created_computer(output).map(|name| json!({ "created_computer": name }))
        }
        _ => None,
    }
}

/// Pull the machine-account name noPac created from lines like
/// `[*] MachineAccount "WIN-3MG3G0LEUAD$" password = …` or
/// `[*] Adding Computer Account "WIN-…$"`. Returns the sAMAccountName (`…$`).
fn scrape_created_computer(output: &str) -> Option<String> {
    for marker in ["MachineAccount \"", "Computer Account \""] {
        if let Some(i) = output.find(marker) {
            let rest = &output[i + marker.len()..];
            if let Some(end) = rest.find('"') {
                let name = rest[..end].trim();
                if name.len() > 1 && name.ends_with('$') {
                    return Some(name.to_string());
                }
            }
        }
    }
    None
}

/// Pull the DeviceID GUID that pywhisker prints after adding a Key Credential
/// (e.g. `[+] ... DeviceID: 1a2b3c4d-....`).
fn scrape_device_id(output: &str) -> Option<String> {
    let idx = output.find("DeviceID:")?;
    let rest = &output[idx + "DeviceID:".len()..];
    let token = rest.split_whitespace().next()?.trim();
    if token.is_empty() {
        None
    } else {
        Some(token.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xp_cmdshell_already_enabled_is_not_a_mutation() {
        // sp_configure reports success either way; only the from/to pair says
        // whether anything changed. GOAD ships xp_cmdshell on, so this is the
        // common case, and journaling it invites teardown to disable a
        // provisioned vulnerability.
        let noop = "Configuration option 'xp_cmdshell' changed from 1 to 1. Run RECONFIGURE.";
        assert!(!mutation_took_effect("mssql_enable_xp_cmdshell", noop));

        let real = "Configuration option 'xp_cmdshell' changed from 0 to 1. Run RECONFIGURE.";
        assert!(mutation_took_effect("mssql_enable_xp_cmdshell", real));
    }

    #[test]
    fn rbcd_write_that_changed_nothing_is_not_a_mutation() {
        let noop = "[*] alice$ can already impersonate users on dc01$\n\
                    [*] Not modifying the delegation rights.";
        assert!(!mutation_took_effect("rbcd_write", noop));

        let real = "[*] Delegation rights modified successfully!";
        assert!(mutation_took_effect("rbcd_write", real));
    }

    /// Verbatim output from impacket-rbcd 0.13.0.dev0 when `-delegate-from`
    /// cannot be resolved. It exits 0, so without this the orchestrator
    /// journals a delegation entry that was never written and teardown then
    /// reports having reverted it.
    #[test]
    fn rbcd_write_with_an_unresolvable_principal_is_not_a_mutation() {
        let unresolved =
            "[-] User not found in LDAP: S-1-5-21-412342169-2221029212-88264412-1010\n\
                          [-] Account to escalate does not exist! \
                          (forgot \"$\" for a computer account? wrong domain?)";
        assert!(!mutation_took_effect("rbcd_write", unresolved));

        let bad_target = "[-] Account to modify does not exist! \
                          (forgot \"$\" for a computer account? wrong domain?)";
        assert!(!mutation_took_effect("rbcd_write", bad_target));
    }

    #[test]
    fn nopac_without_a_created_account_is_not_a_mutation() {
        // Observed live: noPac reports success having created nothing, which
        // journaled a phantom entry teardown then flagged as NEEDS-CAPTURE
        // residue that did not exist.
        assert!(!mutation_took_effect(
            "nopac",
            "[-] Cannot exploit, quota reached"
        ));
        assert!(mutation_took_effect(
            "nopac",
            "[*] Adding Computer Account \"WIN-ABCDEF12$\""
        ));
    }

    #[test]
    fn tools_without_a_known_noop_signature_are_always_journaled() {
        // The default must be to journal: dropping a real mutation from the
        // revert plan is worse than journaling one that changed nothing.
        assert!(mutation_took_effect("add_computer", "anything at all"));
        assert!(mutation_took_effect("dacl_edit", ""));
    }

    #[test]
    fn captures_pywhisker_device_id_on_add() {
        let out = "[*] Searching for the target account\n\
                   [+] KeyCredential generated with DeviceID: 4b1c9f2a-1234-4a2b-9c3d-abcdef012345\n\
                   [*] Saving to disk";
        let hint = hint_for("pywhisker", &json!({ "action": "add" }), out).unwrap();
        assert_eq!(
            hint["device_id"],
            json!("4b1c9f2a-1234-4a2b-9c3d-abcdef012345")
        );
    }

    #[test]
    fn no_hint_for_pywhisker_remove() {
        assert!(hint_for("pywhisker", &json!({ "action": "remove" }), "DeviceID: x").is_none());
    }

    #[test]
    fn no_hint_when_device_id_absent() {
        assert!(hint_for("pywhisker", &json!({ "action": "add" }), "no id here").is_none());
    }

    #[test]
    fn no_hint_for_other_tools() {
        assert!(hint_for("rbcd_write", &json!({}), "DeviceID: x").is_none());
    }

    #[test]
    fn captures_nopac_created_computer() {
        let out = "[*] Selected Target dc01\n\
                   [*] MachineAccount \"WIN-3MG3G0LEUAD$\" password = aB3xY...\n\
                   [*] Successfully added";
        let hint = hint_for("nopac", &json!({}), out).unwrap();
        assert_eq!(hint["created_computer"], json!("WIN-3MG3G0LEUAD$"));
    }

    #[test]
    fn captures_nopac_via_computer_account_marker() {
        let out = "[*] Adding Computer Account \"WIN-ABCDEF12$\"\n[*] done";
        let hint = hint_for("nopac", &json!({}), out).unwrap();
        assert_eq!(hint["created_computer"], json!("WIN-ABCDEF12$"));
    }

    #[test]
    fn no_nopac_hint_when_name_absent() {
        assert!(hint_for("nopac", &json!({}), "[*] failed to add").is_none());
    }
}
