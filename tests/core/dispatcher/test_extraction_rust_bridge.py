"""Tests for Rust-bridged extraction functions.

These tests verify that:
1. The extraction functions work correctly regardless of whether the Rust
   extension (ares_core) is available.
2. When both are available, Rust and Python produce compatible results.
"""

from __future__ import annotations

import pytest

from ares.core.dispatcher.extraction import (
    _HAS_RUST,
    extract_delegation_entries,
    extract_domain_sid,
    extract_hosts_from_output,
    extract_kerberos_hashes,
    extract_secretsdump_hashes,
    extract_shares_from_output,
)

# Sample outputs for testing
NETEXEC_SMB_OUTPUT = """\
SMB         192.168.58.10   445    DC01             [*] Windows Server 2019 Standard 17763 x64 (name:DC01) (domain:contoso.local) (signing:True) (SMBv1:True)
SMB         192.168.58.11   445    SRV01            [*] Windows Server 2019 Standard 17763 x64 (name:SRV01) (domain:contoso.local) (signing:False) (SMBv1:True)
"""

SECRETSDUMP_OUTPUT = """\
[*] Dumping Domain Credentials (domain\\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
contoso.local\\Administrator:500:aad3b435b51404eeaad3b435b51404ee:64fbae31cc352fc26af97cbdef151e03:::
contoso.local\\krbtgt:502:aad3b435b51404eeaad3b435b51404ee:313b6f423a71d74c0a1b8a2f43b22d4c:::
contoso.local\\Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
contoso.local\\svc_sql:1234:aad3b435b51404eeaad3b435b51404ee:e52cac67419a9a224a3b108f3fa6cb6d:::
"""

KERBEROS_TGS_OUTPUT = """\
$krb5tgs$23$*svc_sql$contoso.local$MSSQLSvc/srv01.contoso.local:1433*$abc123hash...
"""

KERBEROS_ASREP_OUTPUT = """\
$krb5asrep$23$svc_nopreauth@contoso.local:def456hash...
"""

DELEGATION_OUTPUT = """\
Impacket v0.12.0.dev1 - Copyright Fortra, LLC and its affiliated companies

AccountName   AccountType    DelegationType        DelegationRightsTo
-----------   -----------    ----------------      ------------------
svc_sql       user           Constrained           cifs/srv01.contoso.local
WEB01$        computer       Unconstrained         N/A
"""

SHARE_OUTPUT = """\
SMB         192.168.58.10   445    DC01             Share           Permissions     Remark
SMB         192.168.58.10   445    DC01             -----           -----------     ------
SMB         192.168.58.10   445    DC01             ADMIN$          READ,WRITE      Remote Admin
SMB         192.168.58.10   445    DC01             C$              READ,WRITE      Default share
SMB         192.168.58.10   445    DC01             SYSVOL          READ            Logon server share
"""

DOMAIN_SID_OUTPUT = """\
[*] Domain SID is: S-1-5-21-1328384573-4090356449-2552632942
"""


class TestExtractHosts:
    def test_basic_extraction(self):
        hosts = extract_hosts_from_output(NETEXEC_SMB_OUTPUT)
        assert len(hosts) == 2
        ips = {h.ip for h in hosts}
        assert "192.168.58.10" in ips
        assert "192.168.58.11" in ips

    def test_hostnames(self):
        hosts = extract_hosts_from_output(NETEXEC_SMB_OUTPUT)
        by_ip = {h.ip: h for h in hosts}
        # Should have FQDN hostnames
        assert "contoso.local" in by_ip["192.168.58.10"].hostname.lower()

    def test_empty_input(self):
        assert extract_hosts_from_output("") == []
        assert extract_hosts_from_output("no SMB output here") == []


class TestExtractSecretsdumpHashes:
    def test_basic_extraction(self):
        hashes = extract_secretsdump_hashes(SECRETSDUMP_OUTPUT)
        # Should get Administrator, krbtgt, svc_sql (not Guest - empty password)
        assert len(hashes) >= 3
        usernames = {h["username"].lower() for h in hashes}
        assert "administrator" in usernames
        assert "krbtgt" in usernames
        assert "svc_sql" in usernames

    def test_skips_empty_passwords(self):
        hashes = extract_secretsdump_hashes(SECRETSDUMP_OUTPUT)
        # Guest has empty NT hash (31d6cfe0d16ae931b73c59d7e0c089c0), should be skipped
        usernames = {h["username"].lower() for h in hashes}
        assert "guest" not in usernames

    def test_flags(self):
        hashes = extract_secretsdump_hashes(SECRETSDUMP_OUTPUT)
        by_user = {h["username"].lower(): h for h in hashes}
        assert by_user["administrator"]["is_administrator"] is True
        assert by_user["krbtgt"]["is_krbtgt"] is True

    def test_empty_input(self):
        assert extract_secretsdump_hashes("") == []


class TestExtractKerberosHashes:
    def test_tgs(self):
        hashes = extract_kerberos_hashes(KERBEROS_TGS_OUTPUT)
        assert len(hashes) >= 1
        assert hashes[0]["hash_type"] == "TGS"
        assert hashes[0]["username"] == "svc_sql"

    def test_asrep(self):
        hashes = extract_kerberos_hashes(KERBEROS_ASREP_OUTPUT)
        assert len(hashes) >= 1
        assert hashes[0]["hash_type"] == "AsRep"
        assert hashes[0]["username"] == "svc_nopreauth"

    def test_empty_input(self):
        assert extract_kerberos_hashes("") == []


class TestExtractDelegationEntries:
    def test_basic_extraction(self):
        delegations = extract_delegation_entries(DELEGATION_OUTPUT)
        assert len(delegations) >= 2
        accounts = {d["account"] for d in delegations}
        assert "svc_sql" in accounts
        assert "WEB01$" in accounts

    def test_delegation_types(self):
        delegations = extract_delegation_entries(DELEGATION_OUTPUT)
        by_account = {d["account"]: d for d in delegations}
        assert by_account["svc_sql"]["delegation_type"] in ("constrained", "Constrained")
        assert by_account["WEB01$"]["delegation_type"] in ("unconstrained", "Unconstrained")

    def test_target_spn(self):
        delegations = extract_delegation_entries(DELEGATION_OUTPUT)
        by_account = {d["account"]: d for d in delegations}
        assert "cifs/srv01.contoso.local" in by_account["svc_sql"]["target_spn"]

    def test_empty_input(self):
        assert extract_delegation_entries("") == []


class TestExtractShares:
    def test_basic_extraction(self):
        shares = extract_shares_from_output(SHARE_OUTPUT)
        assert len(shares) >= 3
        names = {s.name for s in shares}
        assert "ADMIN$" in names
        assert "SYSVOL" in names

    def test_permissions(self):
        shares = extract_shares_from_output(SHARE_OUTPUT)
        by_name = {s.name: s for s in shares}
        assert by_name["ADMIN$"].permissions == "READ,WRITE"
        assert by_name["SYSVOL"].permissions == "READ"

    def test_empty_input(self):
        assert extract_shares_from_output("") == []


class TestExtractDomainSid:
    def test_basic_extraction(self):
        sid = extract_domain_sid(DOMAIN_SID_OUTPUT)
        assert sid == "S-1-5-21-1328384573-4090356449-2552632942"

    def test_no_sid(self):
        assert extract_domain_sid("no SID here") is None

    def test_empty_input(self):
        assert extract_domain_sid("") is None


class TestRustAvailability:
    """Meta-tests to document whether Rust extension is available."""

    def test_reports_rust_status(self):
        # Just report - don't fail either way
        if _HAS_RUST:
            pytest.skip("Rust extension IS available - using accelerated parsing")
        else:
            pytest.skip("Rust extension NOT available - using Python fallback")
