//! Undo registry — maps each journaled mutation to its inverse plan and a
//! reversibility class. The teardown engine consumes an [`UndoPlan`] to (a)
//! print what *would* happen (`--dry-run`) and (b) dispatch the inverse plus a
//! read-back validation probe.
//!
//! Inverse construction is deliberately uniform: for action-parameterized tools
//! (pywhisker, dacl_edit, addspn, and the ones given an `action` branch) the
//! reverse is the *same* forward arguments with the `action` key overridden, so
//! all targeting/auth keys carry over untouched.
//!
//! A mutation only earns [`Reversibility::Clean`] when the journalled call
//! proves the prior state. An idempotent "make it so" call does not: it records
//! that we asked, not that the setting was off beforehand, so reverting it can
//! erase configuration the range shipped with rather than our own change.

use serde_json::{json, Value};

use super::journal::MutationRecord;

/// How faithfully a mutation can be reversed automatically.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reversibility {
    /// Inverse is a single tool call built from the forward args; read-back
    /// can confirm it. No forward-time capture needed.
    Clean,
    /// Reversible only with state captured at forward time (pywhisker DeviceID,
    /// original UPN/attribute, saved-template path). Blocked until that
    /// capture lands in `record.hint`.
    NeedsCapture,
    /// Partially reversible; leaves residue that needs an out-of-band scrub
    /// (AdminSDHolder SDProp propagation, GPO SYSVOL+LDAP artifacts).
    Hard,
    /// No faithful inverse (a reset password's original plaintext is unknowable).
    Impossible,
    /// Not a target mutation we know how to reverse.
    Unsupported,
}

impl Reversibility {
    pub fn label(self) -> &'static str {
        match self {
            Reversibility::Clean => "CLEAN",
            Reversibility::NeedsCapture => "NEEDS-CAPTURE",
            Reversibility::Hard => "HARD",
            Reversibility::Impossible => "IMPOSSIBLE",
            Reversibility::Unsupported => "UNSUPPORTED",
        }
    }
}

/// A read-back probe that confirms a revert actually took effect. `tool` +
/// `args` are dispatched, then `expect_absent` (a needle expected to be GONE
/// from the output on success) is checked. Kept intentionally simple for v1;
/// per-tool structured validators can replace the substring check later.
#[derive(Debug, Clone)]
pub struct ValidateProbe {
    pub tool: String,
    pub args: Value,
    pub expect_absent: Option<String>,
}

/// The plan for reversing one journaled mutation.
#[derive(Debug, Clone)]
pub struct UndoPlan {
    pub class: Reversibility,
    /// Inverse tool + args, when one can be built now. `None` when
    /// `NeedsCapture`/`Hard`/`Impossible`/`Unsupported` block automatic revert.
    pub inverse: Option<(String, Value)>,
    /// Independent read-back probe run after a successful revert.
    pub validate: Option<ValidateProbe>,
    /// Human-readable description of the intended reversal.
    pub note: String,
}

impl UndoPlan {
    fn manual(class: Reversibility, note: impl Into<String>) -> Self {
        Self {
            class,
            inverse: None,
            validate: None,
            note: note.into(),
        }
    }
}

/// Clone forward args and override a single key (typically `action`).
fn with_override(args: &Value, key: &str, val: &str) -> Value {
    let mut m = args.as_object().cloned().unwrap_or_default();
    m.insert(key.to_string(), json!(val));
    Value::Object(m)
}

/// Non-empty string field from an argument object.
fn astr<'a>(args: &'a Value, key: &str) -> Option<&'a str> {
    args.get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
}

/// Canonicalize a SID argument for substring matching against rendered output.
///
/// bloodyAD renders a security descriptor as SDDL, where each ACE ends in the
/// literal `S-1-5-21-…` account SID (there is no well-known-SID abbreviation
/// table — only `WELLKNOWN_GUID`), so a raw SID needle does match. What does
/// not match is a SID the agent decorated: live journals contain the same
/// principal passed both as `…-1163` and `…-1163$`. A trailing `$` can never
/// appear in the SDDL, so the needle is absent on the first read and the probe
/// reports the revert verified without having checked anything.
fn normalize_sid(sid: &str) -> String {
    sid.trim().trim_end_matches('$').to_ascii_uppercase()
}

/// Build a `bloodyad_get_object` read-back probe that reuses the forward call's
/// connection/auth keys. `expect_absent` is the needle that must be GONE from
/// the read output once the mutation is reversed.
fn get_object_probe(
    forward: &Value,
    target: &str,
    attr: &str,
    expect_absent: &str,
) -> ValidateProbe {
    let mut m = serde_json::Map::new();
    for k in ["domain", "dc_ip", "username", "ticket_path", "hash"] {
        if let Some(v) = forward.get(k) {
            m.insert(k.to_string(), v.clone());
        }
    }
    m.insert("target".into(), json!(target));
    m.insert("attr".into(), json!(attr));
    ValidateProbe {
        tool: "bloodyad_get_object".into(),
        args: Value::Object(m),
        expect_absent: Some(expect_absent.to_string()),
    }
}

/// pywhisker reverses cleanly only when the add's DeviceID was captured into
/// the journal hint; otherwise it is blocked as needs-capture.
fn pywhisker_plan(record: &MutationRecord) -> UndoPlan {
    let device_id = record
        .hint
        .as_ref()
        .and_then(|h| h.get("device_id"))
        .and_then(Value::as_str);
    match device_id {
        Some(did) => {
            let mut args = with_override(&record.args, "action", "remove");
            if let Some(o) = args.as_object_mut() {
                o.insert("device_id".into(), json!(did));
            }
            UndoPlan {
                class: Reversibility::Clean,
                inverse: Some(("pywhisker".into(), args)),
                validate: None,
                note: "remove the KeyCredential (msDS-KeyCredentialLink) by captured DeviceID"
                    .into(),
            }
        }
        None => UndoPlan::manual(
            Reversibility::NeedsCapture,
            "remove the KeyCredential — DeviceID was not captured from the add output",
        ),
    }
}

/// noPac creates a random `WIN-…$` machine account. It reverses cleanly only
/// when that name was scraped into the journal hint; otherwise it is blocked as
/// needs-capture. The inverse deletes the account via `add_computer -delete`
/// using noPac's own creds (the creator can delete what it made).
fn nopac_plan(record: &MutationRecord) -> UndoPlan {
    let sam = record
        .hint
        .as_ref()
        .and_then(|h| h.get("created_computer"))
        .and_then(Value::as_str);
    match sam {
        Some(sam) => {
            let a = &record.args;
            let mut m = serde_json::Map::new();
            for k in ["domain", "username", "dc_ip", "ticket_path", "hash"] {
                if let Some(v) = a.get(k) {
                    m.insert(k.to_string(), v.clone());
                }
            }
            // impacket-addcomputer's -computer-name is the bare name (no `$`).
            m.insert("computer_name".into(), json!(sam.trim_end_matches('$')));
            m.insert("action".into(), json!("delete"));
            UndoPlan {
                class: Reversibility::Clean,
                inverse: Some(("add_computer".into(), Value::Object(m))),
                validate: Some(get_object_probe(a, sam, "sAMAccountName", sam)),
                note: format!("delete the machine account noPac created ({sam})"),
            }
        }
        None => UndoPlan::manual(
            Reversibility::NeedsCapture,
            "delete the machine account this created — needs the account name from tool output",
        ),
    }
}

/// `add_computer` mints its own account name, so the forward args do not name
/// the object created; the name comes from the journal hint scraped out of
/// impacket's success banner. The inverse flips the action onto the forward
/// targeting args — auth is not among them, since the journal strips secrets and
/// teardown's `inject_auth` resolves fresh material at revert time.
///
/// Without a hint the plan is blocked rather than guessed: an action-flip on
/// args carrying a stale `computer_name` would point a domain-admin delete at
/// an object this operation never created.
fn add_computer_plan(record: &MutationRecord) -> UndoPlan {
    let a = &record.args;
    let sam = record
        .hint
        .as_ref()
        .and_then(|h| h.get("created_computer"))
        .and_then(Value::as_str);
    match sam {
        Some(sam) => {
            let bare = sam.trim_end_matches('$');
            let mut args = with_override(a, "action", "delete");
            if let Some(m) = args.as_object_mut() {
                m.insert("computer_name".into(), json!(bare));
                m.remove("computer_password");
            }
            UndoPlan {
                class: Reversibility::Clean,
                inverse: Some(("add_computer".into(), args)),
                // After delete, `get object <sam>` should no longer return the
                // account — its name is absent from the read output.
                validate: Some(get_object_probe(a, sam, "sAMAccountName", bare)),
                note: format!("delete the created machine account ({sam})"),
            }
        }
        None => UndoPlan::manual(
            Reversibility::NeedsCapture,
            "delete the created machine account — needs the account name from tool output",
        ),
    }
}

/// Restore a reset account to the password the range provisioned it with.
///
/// The forward call's `new_password` is never journaled (it is a
/// `CREDENTIAL_KEYS` member and gets stripped), and it would be the wrong value
/// to replay anyway — the goal is the *pre-op* password, which only the range's
/// own lab config knows. With `ARES_LAB_BASELINE_CONFIG` pointed at it the
/// reset becomes `Clean`: re-dispatch the same tool with the provisioned value
/// and the account is exactly as the range built it.
///
/// Without that config there is still no inverse, so the mutation keeps its old
/// `Impossible` class and teardown reports it for a manual restore.
fn set_password_plan(record: &MutationRecord) -> UndoPlan {
    let a = &record.args;
    let Some(target) = astr(a, "target_user") else {
        return UndoPlan::manual(
            Reversibility::Impossible,
            "password reset with no journaled target_user — cannot identify the account to restore",
        );
    };
    let domain = astr(a, "domain").or(record.domain.as_deref()).unwrap_or("");
    let sam = target.rsplit(['\\', '/']).next().unwrap_or(target);
    let sam = sam.split('@').next().unwrap_or(sam);

    match super::baseline::provisioned_password(domain, sam) {
        Some(original) => UndoPlan {
            class: Reversibility::Clean,
            inverse: Some((
                "bloodyad_set_password".into(),
                with_override(a, "new_password", &original),
            )),
            validate: None,
            note: format!("restore {sam}'s range-provisioned password"),
        },
        None => UndoPlan::manual(
            Reversibility::Impossible,
            format!(
                "original plaintext for {sam}@{domain} is unknown — set {} to the range's lab \
                 config to make this restorable",
                super::baseline::BASELINE_CONFIG_ENV
            ),
        ),
    }
}

/// Build the inverse plan for a journaled mutation.
pub fn undo_plan(record: &MutationRecord) -> UndoPlan {
    let a = &record.args;
    match record.tool.as_str() {
        // CLEAN: action-flip on the same forward args
        "add_computer" => add_computer_plan(record),
        "rbcd_write" => UndoPlan {
            class: Reversibility::Clean,
            inverse: Some(("rbcd_write".into(), with_override(a, "action", "remove"))),
            validate: astr(a, "target_computer").zip(astr(a, "attacker_sid")).map(
                |(target, sid)| {
                    get_object_probe(
                        a,
                        target,
                        "msDS-AllowedToActOnBehalfOfOtherIdentity",
                        &normalize_sid(sid),
                    )
                },
            ),
            note: "remove the RBCD delegation entry (msDS-AllowedToActOnBehalfOfOtherIdentity). \
                   rbcd.py write and remove are both read-modify-write scoped to the exact SID \
                   (wiping the attribute is `-action flush`, which is never dispatched), so \
                   unrelated ACEs survive the revert. Clean rests on one further premise: the \
                   documented chain is add_computer -> rbcd_write, so attacker_sid is a machine \
                   account this operation just created and no pre-existing ACE can reference it. \
                   A write naming an already-delegated SID no-ops while still being journalled, \
                   and the inverse would then strip an ACE we did not create. Note the revert is \
                   not byte-for-byte: `-action remove` re-writes an empty descriptor \
                   (`O:S-1-5-32-544D:`) where the attribute was previously absent — inert, since \
                   an empty DACL delegates to nobody, but it is a detectable artifact"
                .into(),
        },
        // NOT auto-reverted: same DACL read-modify-write hazard as
        // `bloodyad_add_genericall` — `dacledit.py -action write` does not fail
        // on an ACE that already exists, and `-action remove` deletes every ACE
        // matching principal+rights, ours and the range's alike.
        "dacl_edit" => UndoPlan::manual(
            Reversibility::NeedsCapture,
            "remove the added ACE — `dacledit -action write` no-ops when the ACE already exists, \
             so the matching remove can strip a pre-existing (lab-provisioned) ACE; needs a \
             read-before-write capture of the target DACL",
        ),
        "bloodyad_add_group_member" => UndoPlan {
            class: Reversibility::Clean,
            inverse: Some((
                "bloodyad_add_group_member".into(),
                with_override(a, "action", "remove"),
            )),
            validate: astr(a, "group").zip(astr(a, "target_user")).map(|(group, user)| {
                // After remove, the member list of the group must not contain
                // the target user.
                get_object_probe(a, group, "member", user)
            }),
            note: "remove the added group member".into(),
        },
        // NOT auto-reverted: bloodyAD's `add genericAll` is a read-modify-write
        // of the whole DACL (getSD → addRight → write back), so it succeeds
        // silently when the trustee already holds rights. The inverse strips
        // every ACE matching that trustee, and the lab provisions the very
        // edges this tool is pointed at. Reverting an add that was a no-op
        // therefore deletes a provisioned attack path.
        "bloodyad_add_genericall" => UndoPlan::manual(
            Reversibility::NeedsCapture,
            "remove the GenericAll ACE — the add is a DACL read-modify-write that no-ops when \
             the right already exists, so an unconditional remove can strip a pre-existing \
             (lab-provisioned) ACE; needs a read-before-write capture of the target DACL",
        ),
        "addspn" => UndoPlan {
            class: Reversibility::Clean,
            inverse: Some(("addspn".into(), with_override(a, "action", "remove"))),
            validate: None,
            note: "remove the added SPN".into(),
        },
        // NOT auto-reverted: `sp_configure 'xp_cmdshell',1` is idempotent, so a
        // journalled call proves only that we asked — not that it was off
        // beforehand. GOAD provisions the setting ON as the MSSQL vulnerability
        // (`ansible/roles/mssql/tasks/config.yml`), so disabling it deletes a
        // lab-provisioned weakness instead of reverting our own change. That is
        // exactly the "revert drifts the range" failure this module exists to
        // avoid, and it happened live before this was reclassified.
        "mssql_enable_xp_cmdshell" => UndoPlan::manual(
            Reversibility::NeedsCapture,
            "xp_cmdshell may already have been enabled before the operation (GOAD ships it on); \
             disabling it unconditionally removes a provisioned vulnerability — needs a \
             read-before-write capture of sys.configurations.value_in_use",
        ),

        // HARD: reversible core but leaves residue needing a scrub
        // No clean tool inverse: the deployed bloodyAD exposes no `aclEntry`
        // remove (verified on-box), and SDProp has already propagated copies
        // of the ACE to every protected group — those must be scrubbed by hand.
        "adminsd_holder_add_ace" => UndoPlan::manual(
            Reversibility::Hard,
            "AdminSDHolder ACE — no clean tool inverse (deployed bloodyAD has no `remove aclEntry`), \
             and SDProp has already propagated copies to protected groups (Domain Admins, …); \
             manual scrub required",
        ),
        "pygpoabuse_immediate_task" | "sharpgpoabuse" => UndoPlan::manual(
            Reversibility::Hard,
            "no tool inverse — requires scripted SYSVOL (ScheduledTasks.xml) + LDAP \
             (gPCMachineExtensionNames, versionNumber) scrub; task may already have run as SYSTEM",
        ),
        "certipy_template_esc4" => UndoPlan::manual(
            Reversibility::Hard,
            "restore the certificate template from the -save-old JSON (needs the captured \
             template-config path)",
        ),

        // NEEDS-CAPTURE: blocked until forward-time state is journaled
        "pywhisker" => pywhisker_plan(record),
        "bloodyad_set_object_attr" => UndoPlan::manual(
            Reversibility::NeedsCapture,
            "restore the original attribute value — needs a read-before-write capture",
        ),
        "certipy_account_update" => UndoPlan::manual(
            Reversibility::NeedsCapture,
            "restore the original userPrincipalName — needs a read-before-write capture",
        ),
        "certipy_ca" => certipy_ca_plan(a),
        "nopac" => nopac_plan(record),
        "bloodyad_set_password" => set_password_plan(record),

        _ => UndoPlan::manual(
            Reversibility::Unsupported,
            "no known inverse for this tool",
        ),
    }
}

/// `certipy_ca` covers several sub-actions; only `add-officer` has a clean
/// inverse (`remove-officer`). Others (backup, issue-request) are not target
/// mutations we auto-revert.
fn certipy_ca_plan(a: &Value) -> UndoPlan {
    let action = a
        .get("action")
        .and_then(Value::as_str)
        .or_else(|| a.get("ca_action").and_then(Value::as_str))
        .unwrap_or("");
    if action.contains("add-officer") || a.get("add_officer").is_some() {
        // NOT auto-reverted: GOAD provisions `adcs_esc7`, which *is* officer /
        // ManageCA rights on the CA. Adding an officer that already holds the
        // role does not fail, so `remove-officer` can revoke a right the range
        // shipped with rather than the one we added.
        UndoPlan::manual(
            Reversibility::NeedsCapture,
            "remove the CA officer — adding an existing officer does not fail, and the range \
             provisions ESC7 officer rights, so an unconditional remove can revoke a \
             lab-provisioned role; needs a read-before-write capture of the CA's officer list",
        )
    } else {
        UndoPlan::manual(
            Reversibility::Unsupported,
            "certipy_ca sub-action is not an auto-revertible mutation",
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn rec(tool: &str, args: Value) -> MutationRecord {
        MutationRecord::from_call("privesc", "t", tool, &args)
    }

    #[test]
    fn rbcd_write_reverses_with_action_remove() {
        let p = undo_plan(&rec(
            "rbcd_write",
            json!({ "target_ip": "192.168.58.240", "delegate_to": "dc01$", "action": "write" }),
        ));
        assert_eq!(p.class, Reversibility::Clean);
        let (tool, args) = p.inverse.unwrap();
        assert_eq!(tool, "rbcd_write");
        assert_eq!(args["action"], json!("remove"));
        // targeting keys carried over
        assert_eq!(args["delegate_to"], json!("dc01$"));
    }

    /// An unconditional "remove" inverse is only safe when the forward "add"
    /// would have FAILED had the state already existed. Where the add silently
    /// no-ops, the revert cannot tell our change from the range's own
    /// configuration and strips a provisioned attack path.
    #[test]
    fn dacl_and_officer_grants_are_not_auto_reverted() {
        for (tool, args) in [
            (
                "bloodyad_add_genericall",
                json!({ "target_dn": "CN=Domain Admins,DC=contoso,DC=local", "principal": "alice" }),
            ),
            (
                "dacl_edit",
                json!({ "target_dn": "CN=bob,DC=contoso,DC=local", "principal": "alice", "rights": "FullControl" }),
            ),
            (
                "certipy_ca",
                json!({ "action": "add-officer", "ca": "contoso-CA" }),
            ),
        ] {
            let p = undo_plan(&rec(tool, args));
            assert_eq!(
                p.class,
                Reversibility::NeedsCapture,
                "{tool} must not auto-revert without knowing the prior state"
            );
            assert!(p.inverse.is_none(), "{tool} must dispatch no inverse");
        }
    }

    /// The counter-case: LDAP `Change.ADD` on an existing group member returns
    /// `attributeOrValueExists`, so the tool errors and the mutation is never
    /// journalled. A journalled add therefore proves we created the membership.
    #[test]
    fn group_member_add_stays_cleanly_reversible() {
        let p = undo_plan(&rec(
            "bloodyad_add_group_member",
            json!({ "group": "Domain Admins", "target_user": "alice" }),
        ));
        assert_eq!(p.class, Reversibility::Clean);
        let (tool, args) = p.inverse.expect("membership we added must be removed");
        assert_eq!(tool, "bloodyad_add_group_member");
        assert_eq!(args["action"], json!("remove"));
    }

    #[test]
    fn xp_cmdshell_is_never_auto_disabled() {
        // GOAD ships xp_cmdshell enabled as the MSSQL vulnerability, and
        // `sp_configure ...,1` is idempotent — so a journalled enable does not
        // prove it was off beforehand. Auto-disabling deleted a provisioned
        // weakness from a live range; it must stay blocked until a
        // read-before-write capture exists.
        let p = undo_plan(&rec(
            "mssql_enable_xp_cmdshell",
            json!({ "target": "192.168.58.30", "username": "sa" }),
        ));
        assert_eq!(p.class, Reversibility::NeedsCapture);
        assert!(
            p.inverse.is_none(),
            "must not dispatch a disable without knowing the prior state"
        );
        assert!(p.validate.is_none());
    }

    #[test]
    fn nopac_is_needs_capture_without_hint() {
        let p = undo_plan(&rec("nopac", json!({ "domain": "contoso.local" })));
        assert_eq!(p.class, Reversibility::NeedsCapture);
        assert!(p.inverse.is_none());
    }

    #[test]
    fn nopac_is_clean_with_captured_computer_name() {
        let mut r = rec(
            "nopac",
            json!({ "domain": "contoso.local", "username": "alice", "dc_ip": "192.168.58.240" }),
        );
        r.hint = Some(json!({ "created_computer": "WIN-ABC123$" }));
        let p = undo_plan(&r);
        assert_eq!(p.class, Reversibility::Clean);
        let (tool, args) = p.inverse.unwrap();
        assert_eq!(tool, "add_computer");
        assert_eq!(args["action"], json!("delete"));
        // computer_name is the bare name (no trailing `$`).
        assert_eq!(args["computer_name"], json!("WIN-ABC123"));
        assert_eq!(args["username"], json!("alice"));
        // validation probe reads back the sAMAccountName (with `$`).
        assert_eq!(
            p.validate.unwrap().expect_absent.as_deref(),
            Some("WIN-ABC123$")
        );
    }

    /// The add path mints its own name, so the forward args never name the
    /// object created. Without the captured name there is nothing safe to
    /// delete — guessing points a domain-admin delete at another object.
    #[test]
    fn add_computer_is_needs_capture_without_hint() {
        let p = undo_plan(&rec(
            "add_computer",
            json!({ "domain": "contoso.local", "username": "alice", "dc_ip": "192.168.58.240" }),
        ));
        assert_eq!(p.class, Reversibility::NeedsCapture);
        assert!(p.inverse.is_none());
        assert!(p.validate.is_none());
    }

    #[test]
    fn add_computer_is_clean_with_captured_name() {
        let mut r = rec(
            "add_computer",
            json!({
                "domain": "contoso.local",
                "username": "alice",
                "password": "P@ssw0rd!",
                "dc_ip": "192.168.58.240",
            }),
        );
        r.hint = Some(json!({ "created_computer": "ARES-1A2B3C4D$" }));
        let p = undo_plan(&r);
        assert_eq!(p.class, Reversibility::Clean);
        let (tool, args) = p.inverse.expect("an account we created must be deleted");
        assert_eq!(tool, "add_computer");
        assert_eq!(args["action"], json!("delete"));
        // impacket-addcomputer takes the bare name and appends `$` itself.
        assert_eq!(args["computer_name"], json!("ARES-1A2B3C4D"));
        // Targeting args carry over; the journal strips secrets, and teardown's
        // inject_auth resolves fresh material at revert time.
        assert_eq!(args["username"], json!("alice"));
        assert_eq!(args["dc_ip"], json!("192.168.58.240"));
        assert!(args.get("password").is_none());
        // The bare name is the stricter needle — it is a substring of the `$`
        // form, so it still matches if the read renders the account either way.
        assert_eq!(
            p.validate.unwrap().expect_absent.as_deref(),
            Some("ARES-1A2B3C4D")
        );
    }

    /// The captured name must beat anything left in the forward args. An agent
    /// that asked for `ws01` gets `ARES-…$` instead; deleting `ws01$` would
    /// destroy a lab host account this operation never created — and teardown
    /// authenticates as a domain admin, so it has the rights to succeed.
    #[test]
    fn add_computer_delete_ignores_a_stale_name_in_the_forward_args() {
        let mut r = rec(
            "add_computer",
            json!({
                "domain": "contoso.local",
                "username": "alice",
                "dc_ip": "192.168.58.240",
                "computer_name": "ws01",
                "computer_password": "Requested123!",
            }),
        );
        r.hint = Some(json!({ "created_computer": "ARES-1A2B3C4D$" }));
        let (_, args) = undo_plan(&r).inverse.expect("clean plan");
        assert_eq!(args["computer_name"], json!("ARES-1A2B3C4D"));
        // A delete takes no -computer-pass; carrying one forward is noise that
        // the executor would reject as an unexpected flag pairing.
        assert!(args.get("computer_password").is_none());
    }

    /// End-to-end contract for the minted machine account, across the three
    /// crates that have to agree on its identity: the tool mints it, the parser
    /// recovers it from impacket's banner, capture journals it, and teardown
    /// deletes that exact account. A mismatch anywhere either loses the
    /// credential (breaking the RBCD chain) or aims the delete elsewhere.
    #[test]
    fn minted_machine_account_survives_create_parse_journal_delete() {
        fn flag_value<'a>(argv: &'a [String], flag: &str) -> Option<&'a str> {
            let idx = argv.iter().position(|a| a == flag)?;
            argv.get(idx + 1).map(String::as_str)
        }

        let forward = json!({
            "domain": "contoso.local",
            "username": "alice",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.240",
        });

        // 1. The tool mints the identity; the agent supplied none.
        let cmd = ares_tools::privesc::build_add_computer(&forward).unwrap();
        let argv = cmd.args_for_test();
        let minted = flag_value(argv, "-computer-name").expect("minted name");
        let minted_pass = flag_value(argv, "-computer-pass").expect("minted password");

        // 2. impacket echoes both back, appending the `$` itself.
        let banner = format!(
            "[*] Successfully added machine account {minted}$ with password {minted_pass}."
        );

        // 3. The credential lands in state under the minted name, so a later
        //    rbcd_write can resolve the principal.
        let creds = ares_tools::parsers::parse_add_computer(&banner, &forward);
        assert_eq!(creds[0]["username"], json!(format!("{minted}$")));
        assert_eq!(creds[0]["password"], json!(minted_pass));

        // 4. Capture journals what was created.
        let hint = super::super::capture::hint_for("add_computer", &forward, &banner)
            .expect("created account must be journalled");
        assert_eq!(hint["created_computer"], json!(format!("{minted}$")));

        // 5. Teardown targets that same account.
        let mut r = rec("add_computer", forward);
        r.hint = Some(hint);
        let (tool, mut inverse) = undo_plan(&r).inverse.expect("clean plan");
        assert_eq!(tool, "add_computer");
        assert_eq!(inverse["computer_name"], json!(minted));

        // 6. The delete command really names it. inject_auth resupplies the
        //    secret the journal stripped.
        inverse["password"] = json!("P@ssw0rd!");
        let del = ares_tools::privesc::build_add_computer(&inverse).unwrap();
        let del_argv = del.args_for_test();
        assert_eq!(flag_value(del_argv, "-computer-name"), Some(minted));
        assert!(del_argv.iter().any(|a| a == "-delete"));
    }

    /// With no lab config configured there is still nothing to restore *to*,
    /// so the mutation keeps the class it had before baseline lookup existed.
    #[test]
    fn password_reset_is_impossible_without_a_lab_baseline() {
        let p = undo_plan(&rec(
            "bloodyad_set_password",
            json!({ "target_user": "alice", "domain": "contoso.local" }),
        ));
        assert_eq!(p.class, Reversibility::Impossible);
        assert!(p.inverse.is_none());
        assert!(p.note.contains(super::super::baseline::BASELINE_CONFIG_ENV));
    }

    /// A reset the journal cannot attribute to an account names nothing to
    /// restore — it must not fall through to some other record's target.
    #[test]
    fn password_reset_without_a_target_user_is_impossible() {
        let p = undo_plan(&rec(
            "bloodyad_set_password",
            json!({ "domain": "contoso.local" }),
        ));
        assert_eq!(p.class, Reversibility::Impossible);
        assert!(p.inverse.is_none());
    }

    #[test]
    fn adminsdholder_is_hard_with_no_auto_inverse() {
        // Deployed bloodyAD has no `remove aclEntry`; SDProp propagation is
        // manual regardless — so we must NOT claim an automatic inverse.
        let p = undo_plan(&rec(
            "adminsd_holder_add_ace",
            json!({ "principal": "alice" }),
        ));
        assert_eq!(p.class, Reversibility::Hard);
        assert!(p.inverse.is_none());
    }

    #[test]
    fn certipy_ca_non_officer_actions_stay_unsupported() {
        let p = undo_plan(&rec(
            "certipy_ca",
            json!({ "action": "backup", "ca": "contoso-CA" }),
        ));
        assert_eq!(p.class, Reversibility::Unsupported);
        assert!(p.inverse.is_none());
    }

    #[test]
    fn unknown_tool_is_unsupported() {
        let p = undo_plan(&rec("nmap_scan", json!({})));
        assert_eq!(p.class, Reversibility::Unsupported);
    }

    #[test]
    fn rbcd_write_carries_a_readback_probe() {
        let p = undo_plan(&rec(
            "rbcd_write",
            json!({ "target_computer": "dc01$", "attacker_sid": "S-1-5-21-1-2-3-1105",
                    "domain": "contoso.local", "dc_ip": "192.168.58.240", "username": "alice" }),
        ));
        let probe = p
            .validate
            .expect("rbcd revert should have a read-back probe");
        assert_eq!(probe.tool, "bloodyad_get_object");
        assert_eq!(probe.args["target"], json!("dc01$"));
        assert_eq!(probe.expect_absent.as_deref(), Some("S-1-5-21-1-2-3-1105"));
    }

    /// Live journals carry the same principal as both `…-1105` and `…-1105$`.
    /// The `$` form can never appear in bloodyAD's SDDL rendering, so an
    /// un-normalized needle is absent on the first read and the probe reports
    /// a revert verified without having checked anything.
    #[test]
    fn rbcd_probe_needle_is_normalized_so_it_can_actually_match() {
        let p = undo_plan(&rec(
            "rbcd_write",
            json!({ "target_computer": "dc01$", "attacker_sid": "s-1-5-21-1-2-3-1105$ ",
                    "domain": "contoso.local", "dc_ip": "192.168.58.240", "username": "alice" }),
        ));
        let probe = p
            .validate
            .expect("rbcd revert should have a read-back probe");
        assert_eq!(
            probe.expect_absent.as_deref(),
            Some("S-1-5-21-1-2-3-1105"),
            "a decorated SID must be canonicalized or the probe silently always passes"
        );
    }

    #[test]
    fn normalize_sid_strips_decoration_without_mangling_a_clean_sid() {
        assert_eq!(normalize_sid("S-1-5-21-1-2-3-1105"), "S-1-5-21-1-2-3-1105");
        assert_eq!(
            normalize_sid(" s-1-5-21-1-2-3-1105$"),
            "S-1-5-21-1-2-3-1105"
        );
    }

    #[test]
    fn pywhisker_is_needs_capture_without_hint() {
        let p = undo_plan(&rec(
            "pywhisker",
            json!({ "target_samaccountname": "dc01$" }),
        ));
        assert_eq!(p.class, Reversibility::NeedsCapture);
        assert!(p.inverse.is_none());
    }

    #[test]
    fn pywhisker_is_clean_with_captured_device_id() {
        let mut r = rec(
            "pywhisker",
            json!({ "target_samaccountname": "dc01$", "action": "add" }),
        );
        r.hint = Some(json!({ "device_id": "GUID-123" }));
        let p = undo_plan(&r);
        assert_eq!(p.class, Reversibility::Clean);
        let (tool, args) = p.inverse.unwrap();
        assert_eq!(tool, "pywhisker");
        assert_eq!(args["action"], json!("remove"));
        assert_eq!(args["device_id"], json!("GUID-123"));
    }
}
