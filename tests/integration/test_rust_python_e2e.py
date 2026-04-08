"""End-to-end integration tests for the Rust-Python extraction pipeline.

These tests exercise the full path from raw tool output through the Rust
parsing layer (when available) and the Python bridge functions in
``ares.core.dispatcher.extraction``, verifying that structured data
emerges correctly at every stage.

The tests are backend-agnostic: they pass whether the ``ares_core`` Rust
extension is installed or only the pure-Python fallback is present.  When
both exist, both code paths produce identical results -- that invariant is
covered by the unit-level bridge tests; here we focus on realistic,
multi-record inputs and edge cases that only surface at integration scale.
"""

from __future__ import annotations

import time
from typing import Any

import pytest

from ares.core.dispatcher.extraction import (
    extract_delegation_entries,
    extract_hosts_from_output,
    extract_kerberos_hashes,
    extract_secretsdump_hashes,
)

# ---------------------------------------------------------------------------
# Realistic sample data (contoso.local / 192.168.58.x per project conventions)
# ---------------------------------------------------------------------------

REALISTIC_SECRETSDUMP = """\
[*] Dumping Domain Credentials (domain\\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
contoso.local\\Administrator:500:aad3b435b51404eeaad3b435b51404ee:64fbae31cc352fc26af97cbdef151e03:::
contoso.local\\krbtgt:502:aad3b435b51404eeaad3b435b51404ee:313b6f423a71d74c0a1b8a2f43b22d4c:::
contoso.local\\Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
contoso.local\\svc_sql:1234:aad3b435b51404eeaad3b435b51404ee:e52cac67419a9a224a3b108f3fa6cb6d:::
contoso.local\\DC01$:1001:aad3b435b51404eeaad3b435b51404ee:ab4f3c7e21019f4a5b9c8d2e1f0a6b7c:::
contoso.local\\john.doe:1105:aad3b435b51404eeaad3b435b51404ee:5a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d:::
contoso.local\\jane.smith:1106:aad3b435b51404eeaad3b435b51404ee:1f2e3d4c5b6a7f8e9d0c1b2a3f4e5d6c:::
contoso.local\\svc_backup:1250:aad3b435b51404eeaad3b435b51404ee:aa11bb22cc33dd44ee55ff6677889900:::
[*] Kerberos keys grabbed
"""

REALISTIC_NETEXEC_SMB = """\
SMB         192.168.58.10   445    DC01             [*] Windows Server 2019 Standard 17763 x64 (name:DC01) (domain:contoso.local) (signing:True) (SMBv1:True)
SMB         192.168.58.11   445    SRV01            [*] Windows Server 2019 Standard 17763 x64 (name:SRV01) (domain:contoso.local) (signing:False) (SMBv1:True)
SMB         192.168.58.12   445    WEB01            [*] Windows Server 2019 Standard 17763 x64 (name:WEB01) (domain:contoso.local) (signing:False) (SMBv1:False)
SMB         192.168.58.13   445    SQL01            [*] Windows Server 2019 Standard 17763 x64 (name:SQL01) (domain:contoso.local) (signing:False) (SMBv1:False)
SMB         192.168.58.14   445    APP01            [*] Windows Server 2016 Standard 14393 x64 (name:APP01) (domain:contoso.local) (signing:False) (SMBv1:True)
"""

REALISTIC_KERBEROS_COMBINED = """\
[*] Getting TGT for svc_sql
$krb5tgs$23$*svc_sql$contoso.local$MSSQLSvc/sql01.contoso.local:1433*$a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2
$krb5tgs$23$*svc_http$contoso.local$HTTP/web01.contoso.local*$b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3
$krb5asrep$23$svc_nopreauth@contoso.local:c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4
$krb5asrep$23$old_admin@contoso.local:d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5
"""

REALISTIC_DELEGATION = """\
Impacket v0.12.0.dev1 - Copyright Fortra, LLC and its affiliated companies

AccountName     AccountType    DelegationType                    DelegationRightsTo
-----------     -----------    ----------------                  ------------------
svc_sql         user           Constrained                       MSSQLSvc/sql01.contoso.local:1433
svc_http        user           Constrained                       HTTP/web01.contoso.local
WEB01$          computer       Unconstrained                     N/A
APP01$          computer       RBCD                              cifs/dc01.contoso.local
SRV01$          computer       Constrained                       cifs/dc01.contoso.local
"""


class TestEndToEndPipeline:
    """End-to-end tests that push realistic AD pentest output through the
    full Rust parsing -> Python bridge -> extraction pipeline."""

    # ------------------------------------------------------------------
    # 1. Secretsdump pipeline
    # ------------------------------------------------------------------
    def test_full_secretsdump_pipeline(self) -> None:
        """Feed realistic secretsdump output through extract_secretsdump_hashes
        and verify structured data is correct."""
        hashes = extract_secretsdump_hashes(REALISTIC_SECRETSDUMP)

        # Guest has empty NT hash and must be filtered out
        usernames = {h["username"].lower() for h in hashes}
        assert "guest" not in usernames

        # All real accounts must be present
        for expected in (
            "administrator",
            "krbtgt",
            "svc_sql",
            "dc01$",
            "john.doe",
            "jane.smith",
            "svc_backup",
        ):
            assert expected in usernames, f"Missing user: {expected}"

        by_user: dict[str, dict[str, Any]] = {h["username"].lower(): h for h in hashes}

        # Administrator flags
        admin = by_user["administrator"]
        assert admin["is_administrator"] is True
        assert admin["is_krbtgt"] is False
        assert admin["is_machine_account"] is False
        assert admin["lm_hash"] == "aad3b435b51404eeaad3b435b51404ee"
        assert admin["nt_hash"] == "64fbae31cc352fc26af97cbdef151e03"
        assert admin["hash_value"] == f"{admin['lm_hash']}:{admin['nt_hash']}"

        # krbtgt flags
        krbtgt = by_user["krbtgt"]
        assert krbtgt["is_krbtgt"] is True
        assert krbtgt["is_administrator"] is False

        # Machine account flag
        dc01 = by_user["dc01$"]
        assert dc01["is_machine_account"] is True

        # Hash value format: each side is 32 hex chars
        for h in hashes:
            lm_part, nt_part = h["hash_value"].split(":")
            assert len(lm_part) == 32
            assert len(nt_part) == 32

    # ------------------------------------------------------------------
    # 2. Netexec host pipeline
    # ------------------------------------------------------------------
    def test_full_netexec_pipeline(self) -> None:
        """Feed realistic netexec SMB output through extract_hosts_from_output
        and verify host objects."""
        hosts = extract_hosts_from_output(REALISTIC_NETEXEC_SMB)

        assert len(hosts) == 5

        by_ip = {h.ip: h for h in hosts}
        expected_ips = [
            "192.168.58.10",
            "192.168.58.11",
            "192.168.58.12",
            "192.168.58.13",
            "192.168.58.14",
        ]
        for ip in expected_ips:
            assert ip in by_ip, f"Missing host IP: {ip}"

        # Hostnames should contain the domain (FQDN construction)
        dc = by_ip["192.168.58.10"]
        assert dc.hostname is not None
        assert "contoso.local" in dc.hostname.lower()

        # Every host should reference the domain
        for host in hosts:
            assert hasattr(host, "ip")
            assert hasattr(host, "hostname")
            # The hostname should be non-empty
            assert host.hostname

    # ------------------------------------------------------------------
    # 3. Kerberos pipeline (TGS + AsRep)
    # ------------------------------------------------------------------
    def test_full_kerberos_pipeline(self) -> None:
        """Feed combined TGS + AsRep output through extract_kerberos_hashes
        and verify both types."""
        hashes = extract_kerberos_hashes(REALISTIC_KERBEROS_COMBINED)

        assert len(hashes) == 4

        types = {h["hash_type"] for h in hashes}
        assert "TGS" in types
        assert "AsRep" in types

        tgs_hashes = [h for h in hashes if h["hash_type"] == "TGS"]
        asrep_hashes = [h for h in hashes if h["hash_type"] == "AsRep"]

        assert len(tgs_hashes) == 2
        assert len(asrep_hashes) == 2

        tgs_users = {h["username"] for h in tgs_hashes}
        assert "svc_sql" in tgs_users
        assert "svc_http" in tgs_users

        asrep_users = {h["username"] for h in asrep_hashes}
        assert "svc_nopreauth" in asrep_users
        assert "old_admin" in asrep_users

        # All hashes should reference contoso.local
        for h in hashes:
            assert h["domain"].lower() == "contoso.local"
            assert h["hash_value"]  # non-empty

    # ------------------------------------------------------------------
    # 4. Delegation pipeline (including RBCD)
    # ------------------------------------------------------------------
    def test_full_delegation_pipeline(self) -> None:
        """Feed delegation output with RBCD through extract_delegation_entries
        and verify types and SPNs."""
        delegations = extract_delegation_entries(REALISTIC_DELEGATION)

        assert len(delegations) >= 4  # at least svc_sql, svc_http, WEB01$, APP01$

        by_account = {d["account"]: d for d in delegations}

        # Constrained delegation
        assert "svc_sql" in by_account
        assert by_account["svc_sql"]["delegation_type"] in ("Constrained", "constrained")
        assert "MSSQLSvc/sql01.contoso.local" in by_account["svc_sql"]["target_spn"]

        assert "svc_http" in by_account
        assert by_account["svc_http"]["delegation_type"] in ("Constrained", "constrained")
        assert "HTTP/web01.contoso.local" in by_account["svc_http"]["target_spn"]

        # Unconstrained delegation
        assert "WEB01$" in by_account
        assert by_account["WEB01$"]["delegation_type"] in ("Unconstrained", "unconstrained")

        # RBCD delegation
        assert "APP01$" in by_account
        assert by_account["APP01$"]["delegation_type"] in ("RBCD", "rbcd")
        assert "cifs/dc01.contoso.local" in by_account["APP01$"]["target_spn"]

        # Account types
        assert by_account["svc_sql"]["account_type"] == "user"
        assert by_account["WEB01$"]["account_type"] == "computer"

    # ------------------------------------------------------------------
    # 5. Pipeline consistency (determinism)
    # ------------------------------------------------------------------
    def test_pipeline_consistency(self) -> None:
        """Run the same input through each extraction function twice and
        assert identical results to verify determinism."""
        # Secretsdump
        sd_a = extract_secretsdump_hashes(REALISTIC_SECRETSDUMP)
        sd_b = extract_secretsdump_hashes(REALISTIC_SECRETSDUMP)
        assert sd_a == sd_b

        # Hosts
        hosts_a = [(h.ip, h.hostname) for h in extract_hosts_from_output(REALISTIC_NETEXEC_SMB)]
        hosts_b = [(h.ip, h.hostname) for h in extract_hosts_from_output(REALISTIC_NETEXEC_SMB)]
        assert hosts_a == hosts_b

        # Kerberos
        kb_a = extract_kerberos_hashes(REALISTIC_KERBEROS_COMBINED)
        kb_b = extract_kerberos_hashes(REALISTIC_KERBEROS_COMBINED)
        assert kb_a == kb_b

        # Delegations
        dl_a = extract_delegation_entries(REALISTIC_DELEGATION)
        dl_b = extract_delegation_entries(REALISTIC_DELEGATION)
        assert dl_a == dl_b

    # ------------------------------------------------------------------
    # 6. Large input performance
    # ------------------------------------------------------------------
    @pytest.mark.slow
    def test_large_input_performance(self) -> None:
        """Generate ~1000 secretsdump entries and verify extraction completes
        in under 5 seconds."""
        lines = [
            "[*] Dumping Domain Credentials (domain\\uid:rid:lmhash:nthash)",
            "[*] Using the DRSUAPI method to get NTDS.DIT secrets",
        ]
        for i in range(1000):
            rid = 2000 + i
            # Generate a unique-ish NT hash per user (not the empty hash)
            nt_hash = f"{i:08x}{i:08x}{i:08x}{i:08x}"[:32].ljust(32, "a")
            lines.append(
                f"contoso.local\\user{i:04d}:{rid}:aad3b435b51404eeaad3b435b51404ee:{nt_hash}:::"
            )
        large_output = "\n".join(lines)

        start = time.time()
        hashes = extract_secretsdump_hashes(large_output)
        elapsed = time.time() - start

        assert len(hashes) == 1000
        assert elapsed < 5.0, f"Extraction of 1000 entries took {elapsed:.2f}s (limit: 5s)"

    # ------------------------------------------------------------------
    # 7. Malformed input resilience
    # ------------------------------------------------------------------
    def test_malformed_input_resilience(self) -> None:
        """Feed malformed inputs and verify no crashes -- only empty or
        partial results."""
        # Binary-like data
        binary_blob = bytes(range(256)).decode("latin-1")
        assert isinstance(extract_secretsdump_hashes(binary_blob), list)
        assert isinstance(extract_hosts_from_output(binary_blob), list)
        assert isinstance(extract_kerberos_hashes(binary_blob), list)
        assert isinstance(extract_delegation_entries(binary_blob), list)

        # Extremely long single line (100 KB of 'A')
        long_line = "A" * 100_000
        assert isinstance(extract_secretsdump_hashes(long_line), list)
        assert isinstance(extract_hosts_from_output(long_line), list)
        assert isinstance(extract_kerberos_hashes(long_line), list)
        assert isinstance(extract_delegation_entries(long_line), list)

        # Null bytes interleaved with valid-ish data
        null_input = "contoso.local\\Admin\x00istrator:500:aad3\x00b435:ffff\x00ffff:::\n"
        assert isinstance(extract_secretsdump_hashes(null_input), list)

        # Mixed encoding: valid line followed by garbage
        mixed = (
            "contoso.local\\Administrator:500"
            ":aad3b435b51404eeaad3b435b51404ee"
            ":64fbae31cc352fc26af97cbdef151e03:::\n"
            "\xff\xfe\xfd\xfc\xfb\xfa\n"
            "not a valid line at all\n"
        )
        result = extract_secretsdump_hashes(mixed)
        assert isinstance(result, list)
        # The valid Administrator line should still parse
        usernames = {h["username"].lower() for h in result}
        assert "administrator" in usernames

        # Completely empty and whitespace-only
        assert extract_secretsdump_hashes("") == []
        assert extract_secretsdump_hashes("   \n\n  \t  \n") == []
        assert extract_hosts_from_output("") == []
        assert extract_kerberos_hashes("") == []
        assert extract_delegation_entries("") == []
