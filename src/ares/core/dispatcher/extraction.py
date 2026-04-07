"""Output extraction utilities for parsing tool output.

This module provides standalone functions for extracting structured data
from tool command output (netexec, Impacket, etc.). These are used by
the RedTeamDispatcher to process task results.

All functions are pure (no side effects) and can be tested independently.

When the native ``ares_core`` Rust extension is available (built via maturin),
host and share parsing is delegated to compiled Rust regex for ~10-50x speedup.
The Python fallback is kept for environments where the extension is not installed.
"""

from __future__ import annotations

import re
from typing import Any

from ares.core.models import Host, Share

# ---------------------------------------------------------------------------
# Try to import the Rust extension for high-performance parsing
# ---------------------------------------------------------------------------
try:
    import ares_core as _rust  # type: ignore[import-untyped]

    _HAS_RUST = True
except ImportError:
    _HAS_RUST = False


def extract_hosts_from_output(output: str) -> list[Host]:
    """Extract hosts from netexec SMB output.

    Parses output like:
        SMB  192.168.58.10  445  DC01  [*] Windows 10.0 Build... (name:DC01) (domain:CONTOSO.LOCAL)

    Args:
        output: Raw command output containing SMB scan results.

    Returns:
        List of Host objects with IP, hostname, and OS info.
    """
    if not output:
        return []

    if _HAS_RUST:
        return _rust_extract_hosts(output)

    return _py_extract_hosts(output)


def _rust_extract_hosts(output: str) -> list[Host]:
    """Delegate host extraction to the Rust extension."""
    hosts: list[Host] = []
    seen: set[str] = set()
    for h in _rust.py_extract_hosts(output):
        ip = h["ip"]
        if ip in seen:
            continue
        seen.add(ip)
        hostname = h.get("hostname", "")
        domain = h.get("domain", "")
        # Construct FQDN if domain is present and hostname isn't already qualified
        if domain and hostname and not hostname.lower().endswith(domain.lower()):
            hostname = f"{hostname.lower()}.{domain}"
        hosts.append(
            Host(
                ip=ip,
                hostname=hostname,
                os=h.get("os", ""),
                roles=[],
                services=[],
            )
        )
    return hosts


def _py_extract_hosts(output: str) -> list[Host]:
    """Python fallback for host extraction."""
    hosts: list[Host] = []
    seen: set[str] = set()

    for line in output.splitlines():
        stripped = line.strip()
        if not stripped:
            continue

        smb_match = re.search(
            r"SMB\s+(\d{1,3}(?:\.\d{1,3}){3})\s+\d+\s+([A-Za-z0-9_.-]+)\s+\[\*\]\s+(.+)",
            stripped,
        )
        if not smb_match:
            continue

        ip = smb_match.group(1)
        host_col = smb_match.group(2)
        details = smb_match.group(3)

        name_match = re.search(r"\(name:([^)]+)\)", details)
        domain_match = re.search(r"\(domain:([^)]+)\)", details)

        domain = domain_match.group(1) if domain_match else ""
        hostname = name_match.group(1) if name_match else host_col

        if domain and hostname and not hostname.lower().endswith(domain.lower()):
            hostname = f"{hostname.lower()}.{domain}"

        os_match = re.search(r"^\s*([^(]+?)\s+\(name:", details)
        os_name = os_match.group(1).strip() if os_match else "Unknown"

        if ip in seen:
            continue
        seen.add(ip)

        hosts.append(
            Host(
                ip=ip,
                hostname=hostname,
                os=os_name,
                roles=[],
                services=[],
            )
        )

    return hosts


def extract_users_from_output(output: str) -> list[str]:
    """Extract usernames from various tool output formats.

    Parses patterns like:
        - user:[username]
        - Account: username
        - sAMAccountName: username
        - SMB host ... username timestamp

    Args:
        output: Raw command output containing user information.

    Returns:
        List of unique usernames extracted from output.
    """
    if not output:
        return []

    users: list[str] = []
    seen: set[str] = set()

    for line in output.splitlines():
        stripped = line.strip()
        if not stripped:
            continue

        # Match user:[username] pattern (common in many tools)
        for match in re.findall(r"user:\[([^\]]+)\]", stripped, re.IGNORECASE):
            user = match.strip()
            if user and user not in seen:
                users.append(user)
                seen.add(user)

        # Match Account: username pattern
        account_match = re.search(r"Account:\s*([A-Za-z0-9_.-]+)", stripped)
        if account_match:
            user = account_match.group(1).strip()
            if user and user not in seen:
                users.append(user)
                seen.add(user)

        # Match sAMAccountName: username pattern
        sam_match = re.search(r"samaccountname:\s*([A-Za-z0-9_.-]+)", stripped, re.IGNORECASE)
        if sam_match:
            user = sam_match.group(1).strip()
            if user and user not in seen:
                users.append(user)
                seen.add(user)

        # Match SMB output with timestamp (user enumeration results)
        smb_match = re.search(
            r"SMB\s+\S+\s+\d+\s+\S+\s+([A-Za-z0-9_.-]+)\s+\d{4}-\d{2}-\d{2}",
            stripped,
        )
        if smb_match:
            user = smb_match.group(1).strip()
            if user and user not in seen:
                users.append(user)
                seen.add(user)

    return users


def extract_plaintext_passwords_from_output(output: str) -> list[tuple[str, str, str]]:
    """Extract username/password pairs from tool output.

    Parses patterns containing "Password:" field along with associated usernames,
    as well as LSA DefaultPassword entries from secretsdump output.

    Args:
        output: Raw command output containing credential information.

    Returns:
        List of (username, password, domain) tuples. Domain may be empty string.
    """
    if not output:
        return []

    creds: list[tuple[str, str, str]] = []
    seen: set[tuple[str, str, str]] = set()

    # Extract from LDAP entries (handles password before username case)
    if "\ndn:" in output or output.strip().lower().startswith("dn:"):
        for username, password in _extract_passwords_from_ldap_entries(output):
            key = (username.lower(), password, "")
            if key not in seen:
                seen.add(key)
                creds.append((username, password, ""))

    # Extract from line-based formats (netexec, LSA, etc.)
    for username, password, domain in _extract_passwords_line_by_line(output):
        key = (username.lower(), password, domain.lower())
        if key not in seen:
            seen.add(key)
            creds.append((username, password, domain))

    return creds


def _extract_passwords_from_ldap_entries(output: str) -> list[tuple[str, str]]:
    """Extract credentials from LDAP-formatted output.

    LDAP entries start with 'dn:' and can have password (in description)
    appear before sAMAccountName. We must parse each entry as a complete
    unit to correctly associate passwords with usernames.
    """
    creds: list[tuple[str, str]] = []

    # Split into LDAP entries (each starts with dn:)
    entries = re.split(r"(?=^dn:)", output, flags=re.MULTILINE | re.IGNORECASE)

    for entry in entries:
        if not entry.strip():
            continue

        # Extract username from sAMAccountName
        username = ""
        sam_match = re.search(r"samaccountname:\s*([A-Za-z0-9_.-]+)", entry, re.IGNORECASE)
        if sam_match:
            username = sam_match.group(1).strip()

        # Extract password from description or other fields
        password = ""  # nosec B105 - initialization, not hardcoded password
        pass_match = re.search(r"Password\s*:\s*([^\s()]+)", entry, re.IGNORECASE)
        if pass_match:
            password = pass_match.group(1).strip().rstrip(".,;:()")

        if username and password:
            # Filter out invalid entries
            if "/" in username or "\\" in username or username.endswith(".txt"):
                continue
            if "/" in password or "\\" in password or password.endswith(".txt"):
                continue
            creds.append((username, password))

    return creds


def _extract_passwords_line_by_line(output: str) -> list[tuple[str, str, str]]:
    """Extract credentials from line-based output (netexec, LSA, etc.)."""
    creds: list[tuple[str, str, str]] = []
    current_user = ""
    expecting_default_password = False

    for line in output.splitlines():
        stripped = line.strip()
        if not stripped:
            continue

        # Skip LDAP entry markers (handled by _extract_passwords_from_ldap_entries)
        if stripped.lower().startswith("dn:"):
            current_user = ""
            continue

        # Handle LSA DefaultPassword format from secretsdump:
        # [*] DefaultPassword
        # DOMAIN\user:password
        if "[*] DefaultPassword" in stripped:
            expecting_default_password = True
            continue

        if expecting_default_password:
            expecting_default_password = False
            # Parse DOMAIN\user:password format
            lsa_match = re.match(r"^([^\\]+)\\([^:]+):(.+)$", stripped)
            if lsa_match:
                domain = lsa_match.group(1).strip()
                username = lsa_match.group(2).strip()
                password = lsa_match.group(3).strip()
                if username and password:
                    creds.append((username, password, domain))
            continue

        # Track current user from various patterns
        user_match = re.search(r"user:\[([^\]]+)\]", stripped, re.IGNORECASE)
        if user_match:
            current_user = user_match.group(1).strip()

        account_match = re.search(r"Account:\s*([A-Za-z0-9_.-]+)", stripped)
        if account_match:
            current_user = account_match.group(1).strip()

        sam_match = re.search(r"samaccountname:\s*([A-Za-z0-9_.-]+)", stripped, re.IGNORECASE)
        if sam_match:
            current_user = sam_match.group(1).strip()

        # Skip lines without password info
        if "password" not in stripped.lower():
            continue

        pass_match = re.search(r"Password\s*:\s*([^\s\)]+)", stripped, re.IGNORECASE)
        if not pass_match:
            continue

        password = pass_match.group(1).strip()
        username = ""

        # Try to extract username from same line
        smb_match = re.search(
            r"SMB\s+\S+\s+\d+\s+\S+\s+([A-Za-z0-9_.-]+)\s+\d{4}-\d{2}-\d{2}.*Password\s*:\s*",
            stripped,
        )
        if smb_match:
            username = smb_match.group(1).strip()

        # Only fall back to current_user for non-LDAP lines
        if not username and current_user:
            username = current_user

        if not username:
            continue

        # Filter out invalid entries
        if "/" in username or "\\" in username or username.endswith(".txt"):
            continue
        if "/" in password or "\\" in password or password.endswith(".txt"):
            continue

        creds.append((username, password, ""))

    return creds


def extract_shares_from_output(output: str, default_host: str = "") -> list[Share]:
    """Extract shares from netexec --shares output.

    Parses output like:
        SMB  192.168.58.10  445  DC01  Share     Permissions  Comment
        SMB  192.168.58.10  445  DC01  -----     -----------  -------
        SMB  192.168.58.10  445  DC01  ADMIN$    READ,WRITE   Remote Admin
        SMB  192.168.58.10  445  DC01  C$        READ,WRITE   Default share

    Args:
        output: Raw netexec --shares output.
        default_host: Default host if not parsed from output.

    Returns:
        List of Share objects with host, name, permissions, and comment.
    """
    if not output:
        return []

    if _HAS_RUST:
        return _rust_extract_shares(output)

    return _py_extract_shares(output, default_host)


def _rust_extract_shares(output: str) -> list[Share]:
    """Delegate share extraction to the Rust extension."""
    return [
        Share(
            host=s["host"],
            name=s["name"],
            permissions=s.get("permissions", ""),
            comment=s.get("comment", ""),
        )
        for s in _rust.py_extract_shares(output)
    ]


def _py_extract_shares(output: str, default_host: str = "") -> list[Share]:
    """Python fallback for share extraction."""
    shares: list[Share] = []
    seen: set[tuple[str, str]] = set()
    in_table = False
    current_host = default_host

    for line in output.splitlines():
        stripped = line.strip()
        if not stripped:
            continue

        # Parse host from SMB line prefix: "SMB  192.168.58.1  445  HOSTNAME  ..."
        if stripped.startswith("SMB"):
            smb_match = re.match(r"^SMB\s+(\d+\.\d+\.\d+\.\d+)\s+", stripped)
            if smb_match:
                current_host = smb_match.group(1)

            # Strip SMB prefix to get body
            body = re.sub(r"^SMB\s+\S+\s+\d+\s+\S+\s+", "", stripped).strip()
            if not body:
                continue

            lower = body.lower()

            if lower.startswith("share") and "permission" in lower:
                in_table = True
                continue

            if in_table and set(body) <= {"-", " "}:
                continue

            if in_table and (body.startswith("[") or lower.startswith("smb")):
                in_table = False
                continue

            if not in_table:
                continue

            parts = body.split(None, 2)
            if not parts:
                continue

            name = parts[0].strip()
            if not name or name.lower() == "share":
                continue

            # Validate permissions - netexec only outputs READ, WRITE, or READ,WRITE
            # If parts[1] isn't a valid permission, it's actually the comment
            # (happens when share has no permissions, e.g., "ADMIN$  Remote Admin")
            valid_perms = {"read", "write", "read,write", "write,read"}
            raw_perm = parts[1].strip().lower() if len(parts) > 1 else ""

            if raw_perm in valid_perms:
                permissions = parts[1].strip().upper()
                comment = parts[2].strip() if len(parts) > 2 else ""
            else:
                # No valid permission - parts[1:] is actually the comment
                permissions = ""
                comment = " ".join(parts[1:]).strip() if len(parts) > 1 else ""

            key = (current_host.lower(), name.lower())
            if key in seen:
                continue

            seen.add(key)
            shares.append(
                Share(
                    host=current_host,
                    name=name,
                    permissions=permissions,
                    comment=comment,
                )
            )

    return shares


def extract_ticket_path_from_output(output: str) -> str:
    """Extract Kerberos ticket path from getST.py output.

    Parses output like:
        [*] Saving ticket in administrator@cifs_dc01.contoso.local@CONTOSO.LOCAL.ccache

    Args:
        output: Raw getST.py output.

    Returns:
        Path to the saved ticket file, or empty string if not found.
    """
    if not output:
        return ""

    for line in output.splitlines():
        if "Saving ticket in" in line:
            match = re.search(r"Saving ticket in\s+(\S+)", line)
            if match:
                return match.group(1)

    return ""


def extract_host_from_spn(spn: str) -> str | None:
    """Extract hostname from a Service Principal Name (SPN).

    Args:
        spn: SPN like "cifs/dc01.contoso.local" or "MSSQLSvc/sql01:1433"

    Returns:
        Hostname portion of the SPN, or None if not parseable.
    """
    if not spn or "/" not in spn:
        return None

    # Split on / and take the service target
    parts = spn.split("/", 1)
    if len(parts) < 2:
        return None

    target = parts[1]

    # Remove port if present (e.g., MSSQLSvc/sql01:1433)
    if ":" in target:
        target = target.split(":")[0]

    return target or None


# ---------------------------------------------------------------------------
# Rust-accelerated parsing functions for secretsdump, hashes, delegations
# ---------------------------------------------------------------------------


def extract_secretsdump_hashes(output: str) -> list[dict[str, Any]]:
    """Extract NTLM hashes from secretsdump output using Rust when available.

    Returns:
        List of dicts with keys: username, domain, rid, lm_hash, nt_hash,
        hash_value, is_krbtgt, is_administrator, is_machine_account.
    """
    if not output:
        return []
    if _HAS_RUST:
        return list(_rust.py_parse_secretsdump(output))
    return _py_extract_secretsdump_hashes(output)


def _py_extract_secretsdump_hashes(output: str) -> list[dict[str, Any]]:
    """Python fallback for secretsdump hash extraction."""
    results: list[dict[str, Any]] = []
    empty_nt = "31d6cfe0d16ae931b73c59d7e0c089c0"
    # Pattern: [domain\]user:rid:lm_hash:nt_hash:::
    pattern = re.compile(
        r"^(?:([^\\:\s]+)\\)?([^:\\]+):(\d+):([a-fA-F0-9]{32}):([a-fA-F0-9]{32}):::",
    )
    for line in output.splitlines():
        m = pattern.match(line.strip())
        if not m:
            continue
        domain = (m.group(1) or "").lower()
        username = m.group(2)
        rid = int(m.group(3))
        lm_hash = m.group(4).lower()
        nt_hash = m.group(5).lower()
        if nt_hash == empty_nt:
            continue
        results.append(
            {
                "username": username,
                "domain": domain,
                "rid": rid,
                "lm_hash": lm_hash,
                "nt_hash": nt_hash,
                "hash_value": f"{lm_hash}:{nt_hash}",
                "is_krbtgt": rid == 502 or username.lower() == "krbtgt",
                "is_administrator": rid == 500 or username.lower() == "administrator",
                "is_machine_account": username.endswith("$"),
            }
        )
    return results


def extract_kerberos_hashes(output: str) -> list[dict[str, Any]]:
    """Extract Kerberos hashes (TGS/AS-REP) from tool output using Rust when available.

    Returns:
        List of dicts with keys: username, domain, hash_value, hash_type.
    """
    if not output:
        return []
    if _HAS_RUST:
        return list(_rust.py_extract_kerberos_hashes(output))
    return _py_extract_kerberos_hashes(output)


def _py_extract_kerberos_hashes(output: str) -> list[dict[str, Any]]:
    """Python fallback for Kerberos hash extraction."""
    results: list[dict[str, Any]] = []
    tgs_re = re.compile(r"(\$krb5tgs\$\d+\$\*?([^$*]+)\$([^$]+)\$[^\s]+)")
    asrep_re = re.compile(r"(\$krb5asrep\$\d+\$([^@:]+)@([^:]+):[^\s]+)")

    for line in output.splitlines():
        stripped = line.strip()
        m = tgs_re.search(stripped)
        if m:
            results.append(
                {
                    "username": m.group(2),
                    "domain": m.group(3),
                    "hash_value": m.group(1),
                    "hash_type": "TGS",
                }
            )
            continue
        m = asrep_re.search(stripped)
        if m:
            results.append(
                {
                    "username": m.group(2),
                    "domain": m.group(3),
                    "hash_value": m.group(1),
                    "hash_type": "AsRep",
                }
            )
    return results


def extract_ntlm_hashes(output: str) -> list[dict[str, Any]]:
    """Extract NTLM hashes from tool output using Rust when available.

    Returns:
        List of dicts with keys: username, domain, rid, lm_hash, nt_hash,
        hash_value, is_krbtgt, is_administrator, is_machine_account.
    """
    if not output:
        return []
    if _HAS_RUST:
        return list(_rust.py_extract_ntlm_hashes(output))
    return _py_extract_secretsdump_hashes(output)  # Same format


def extract_delegation_entries(output: str) -> list[dict[str, str]]:
    """Extract delegation entries from findDelegation output using Rust when available.

    Returns:
        List of dicts with keys: account, account_type, delegation_type, target_spn.
    """
    if not output:
        return []
    if _HAS_RUST:
        return list(_rust.py_extract_delegations(output))
    return _py_extract_delegations(output)


def _py_extract_delegations(output: str) -> list[dict[str, str]]:
    """Python fallback for delegation extraction."""
    delegations: list[dict[str, str]] = []
    seen: set[str] = set()
    in_table = False

    for line in output.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        lower = stripped.lower()
        if "accountname" in lower and "delegationtype" in lower:
            in_table = True
            continue
        if in_table and set(stripped) <= {"-", " "}:
            continue
        if in_table and stripped.startswith(("[", "Impacket")):
            in_table = False
            continue
        if not in_table:
            continue

        parts = stripped.split()
        if len(parts) < 3:
            continue

        account = parts[0]
        account_type = parts[1]
        delegation_type = ""
        target_spn = ""

        if "unconstrained" in lower:
            delegation_type = "Unconstrained"
        elif "constrained" in lower:
            delegation_type = "Constrained"
        elif "rbcd" in lower:
            delegation_type = "RBCD"
        else:
            continue

        for part in parts:
            if "/" in part and not part.startswith("[") and part not in ("w/", "w/o"):
                slash_idx = part.find("/")
                if slash_idx < len(part) - 1 and part[slash_idx + 1].isalpha():
                    target_spn = part
                    break
        if target_spn == "N/A":
            target_spn = ""

        key = f"{account.lower()}:{delegation_type.lower()}"
        if key in seen:
            continue
        seen.add(key)
        delegations.append(
            {
                "account": account,
                "account_type": account_type,
                "delegation_type": delegation_type,
                "target_spn": target_spn,
            }
        )
    return delegations


def extract_domain_sid(output: str) -> str | None:
    """Extract the first domain SID from output using Rust when available.

    Returns:
        Domain SID string (e.g., S-1-5-21-...) or None if not found.
    """
    if not output:
        return None
    if _HAS_RUST:
        return _rust.py_extract_domain_sid(output)
    m = re.search(r"S-1-5-21-\d+-\d+-\d+", output)
    return m.group(0) if m else None


__all__ = [
    "extract_delegation_entries",
    "extract_domain_sid",
    "extract_host_from_spn",
    "extract_hosts_from_output",
    "extract_kerberos_hashes",
    "extract_ntlm_hashes",
    "extract_plaintext_passwords_from_output",
    "extract_secretsdump_hashes",
    "extract_shares_from_output",
    "extract_ticket_path_from_output",
    "extract_users_from_output",
]
