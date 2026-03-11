"""Tests for RECON agent toolset configuration.

This test module verifies that the capability-based tool configuration
works correctly for the RECON role.
"""

from __future__ import annotations

from ares.core.capability_registry import get_enabled_tools
from ares.core.config import get_agent_config
from ares.core.factories.red_agents import ALL_TOOLSETS
from ares.tools.red import (
    BloodHoundTools,
    CredentialDiscoveryTools,
    NetworkEnumerationTools,
)


class TestReconRoleCapabilities:
    """Tests for RECON role capability configuration."""

    def test_recon_config_has_capabilities(self):
        """RECON config should have capabilities defined."""
        config = get_agent_config("recon")
        assert len(config.capabilities) > 0

    def test_recon_capabilities_include_nmap(self):
        """RECON capabilities should include nmap."""
        config = get_agent_config("recon")
        # Check if nmap or network scanning capability is present
        assert "nmap" in config.capabilities

    def test_recon_capabilities_include_bloodhound(self):
        """RECON capabilities should include bloodhound-python."""
        config = get_agent_config("recon")
        assert "bloodhound-python" in config.capabilities

    def test_recon_capabilities_map_to_tools(self):
        """RECON capabilities should map to expected tool methods."""
        config = get_agent_config("recon")
        enabled = get_enabled_tools(set(config.capabilities))

        # Should have network scanning tools
        assert "nmap_scan" in enabled
        assert "run_bloodhound" in enabled


class TestToolsetClassesAvailable:
    """Tests that required toolset classes are in ALL_TOOLSETS."""

    def test_network_enumeration_in_all_toolsets(self):
        """NetworkEnumerationTools should be in ALL_TOOLSETS."""
        assert NetworkEnumerationTools in ALL_TOOLSETS

    def test_bloodhound_in_all_toolsets(self):
        """BloodHoundTools should be in ALL_TOOLSETS."""
        assert BloodHoundTools in ALL_TOOLSETS

    def test_credential_discovery_in_all_toolsets(self):
        """CredentialDiscoveryTools should be in ALL_TOOLSETS."""
        assert CredentialDiscoveryTools in ALL_TOOLSETS


class TestCredentialDiscoveryTools:
    """Tests for CredentialDiscoveryTools functionality."""

    def test_credential_discovery_has_password_spray(self):
        """CredentialDiscoveryTools should have password_spray method."""
        tools = CredentialDiscoveryTools()
        assert hasattr(tools, "password_spray")
        assert callable(tools.password_spray)

    def test_credential_discovery_has_username_as_password(self):
        """CredentialDiscoveryTools should have username_as_password method."""
        tools = CredentialDiscoveryTools()
        assert hasattr(tools, "username_as_password")
        assert callable(tools.username_as_password)

    def test_credential_discovery_has_ldap_search_descriptions(self):
        """CredentialDiscoveryTools should have ldap_search_descriptions method."""
        tools = CredentialDiscoveryTools()
        assert hasattr(tools, "ldap_search_descriptions")
        assert callable(tools.ldap_search_descriptions)

    def test_credential_discovery_has_password_policy(self):
        """CredentialDiscoveryTools should have password_policy method."""
        tools = CredentialDiscoveryTools()
        assert hasattr(tools, "password_policy")
        assert callable(tools.password_policy)

    def test_credential_discovery_has_add_credential(self):
        """CredentialDiscoveryTools should have _add_credential method."""
        tools = CredentialDiscoveryTools()
        assert hasattr(tools, "_add_credential")
        assert callable(tools._add_credential)

    def test_credential_discovery_has_laps_dump(self):
        """CredentialDiscoveryTools should have laps_dump method."""
        tools = CredentialDiscoveryTools()
        assert hasattr(tools, "laps_dump")
        assert callable(tools.laps_dump)


class TestCapabilityToToolMapping:
    """Tests for capability to tool method mapping."""

    def test_nmap_capability_maps_to_nmap_scan(self):
        """nmap capability should map to nmap_scan tool method."""
        enabled = get_enabled_tools({"nmap"})
        assert "nmap_scan" in enabled

    def test_bloodhound_capability_maps_to_run_bloodhound(self):
        """bloodhound-python capability should map to run_bloodhound tool method."""
        enabled = get_enabled_tools({"bloodhound-python"})
        assert "run_bloodhound" in enabled

    def test_netexec_capability_maps_to_smb_tools(self):
        """netexec capability should map to SMB tool methods."""
        enabled = get_enabled_tools({"netexec"})
        assert "smb_sweep" in enabled
        assert "enumerate_users" in enabled
        assert "enumerate_shares" in enabled

    def test_ldapsearch_capability_maps_to_ldap_tools(self):
        """ldapsearch capability should map to LDAP tool methods."""
        enabled = get_enabled_tools({"ldapsearch"})
        assert "ldap_search_descriptions" in enabled
        assert "check_sidhistory" in enabled


class TestNetBIOSHostnameEnrichment:
    """Tests for NetBIOS hostname enrichment in nmap_scan.

    The nmap_scan tool has a Phase 3 that attempts to resolve hostnames
    for hosts that don't have them, using NetBIOS name resolution.
    """

    def test_fqdn_regex_extracts_hostname_from_nmap_report(self):
        """Test that FQDN can be extracted from nmap scan report output."""
        import re

        ip = "192.168.58.10"
        nmap_output = f"Nmap scan report for dc01.contoso.local ({ip})\n"

        fqdn_match = re.search(
            r"Nmap scan report for ([^\s]+)\s+\(" + re.escape(ip) + r"\)",
            nmap_output,
        )

        assert fqdn_match is not None
        assert fqdn_match.group(1) == "dc01.contoso.local"

    def test_fqdn_regex_handles_short_hostname(self):
        """Test FQDN extraction handles short hostnames without domain."""
        import re

        ip = "192.168.58.20"
        nmap_output = f"Nmap scan report for sql01 ({ip})\n"

        fqdn_match = re.search(
            r"Nmap scan report for ([^\s]+)\s+\(" + re.escape(ip) + r"\)",
            nmap_output,
        )

        assert fqdn_match is not None
        assert fqdn_match.group(1) == "sql01"

    def test_netbios_name_regex_extracts_name(self):
        """Test NetBIOS name extraction from nbstat output."""
        import re

        nbstat_output = """
Starting Nmap 7.93 ( https://nmap.org )
Host script results:
| nbstat: NetBIOS name: DC01, NetBIOS user: <unknown>, NetBIOS MAC: 00:0c:29:xx:xx:xx
|_  Names:
|   DC01<00>            Flags: <unique><active>
|   CONTOSO<00>         Flags: <group><active>
"""

        nb_match = re.search(r"nbstat:\s*NetBIOS name:\s*([^,]+)", nbstat_output)

        assert nb_match is not None
        assert nb_match.group(1).strip() == "DC01"

    def test_domain_group_regex_extracts_domain(self):
        """Test domain extraction from NetBIOS Names section.

        The regex from reconnaissance.py matches entries with <00> suffix
        and <group> flag to identify the domain/workgroup name.
        """
        import re

        # Nmap nbstat output format (indented entries under Names section)
        nbstat_output = """
Names:
  DC01<00>              Flags: <unique><active>
  CONTOSO<00>           Flags: <group><active>
  CONTOSO<1c>           Flags: <group><active>
"""

        # The regex from reconnaissance.py expects whitespace-prefixed lines
        domain_match = re.search(
            r"^\s+([A-Z0-9_-]+)<00>\s+Flags:.*<group>",
            nbstat_output,
            re.MULTILINE,
        )

        assert domain_match is not None
        assert domain_match.group(1).strip() == "CONTOSO"

    def test_aws_internal_hostname_detection(self):
        """Test detection of AWS internal hostnames that need enrichment."""
        # AWS EC2 internal hostnames follow pattern: ip-XXX-XXX-XXX-XXX.region.compute.internal
        aws_hostname = "ip-10-0-1-50.us-east-1.compute.internal"

        needs_enrichment = (
            aws_hostname.lower().startswith("ip-") and "compute.internal" in aws_hostname.lower()
        )

        assert needs_enrichment is True

    def test_normal_hostname_does_not_need_enrichment(self):
        """Test that normal hostnames don't trigger enrichment."""
        normal_hostname = "dc01.contoso.local"

        needs_enrichment = (
            normal_hostname.lower().startswith("ip-")
            and "compute.internal" in normal_hostname.lower()
        )

        assert needs_enrichment is False

    def test_empty_hostname_needs_enrichment(self):
        """Test that empty/None hostnames need enrichment."""
        hostname = None

        # Logic from reconnaissance.py
        needs_enrichment = not hostname or (
            hostname.lower().startswith("ip-") and "compute.internal" in hostname.lower()
        )

        assert needs_enrichment is True

    def test_fqdn_construction_from_netbios(self):
        """Test FQDN construction from NetBIOS name and domain."""
        netbios_name = "DC01"
        domain = "contoso.local"  # Full domain from LDAP

        # Logic from reconnaissance.py - uses full domain from LDAP
        fqdn = f"{netbios_name.lower()}.{domain.lower()}"

        assert fqdn == "dc01.contoso.local"


class TestTruncatedDomainCorrection:
    """Tests for correcting truncated domain suffixes from DNS.

    When nmap resolves hostnames via AD DNS, it may return truncated
    domains like "ws01.child.local" instead of the full
    "ws01.child.contoso.local". The code should detect
    and correct these truncated domains using known domains from LDAP.
    """

    def test_truncated_domain_detection(self):
        """Test that truncated domains can be detected."""
        # child.local is truncated, child.contoso.local is correct
        truncated = "child.local"
        full_domain = "child.contoso.local"

        # Check if truncated domain's first label matches known domain
        first_label = truncated.split(".", maxsplit=1)[0]  # "child"
        is_truncated = full_domain.startswith(first_label + ".")

        assert is_truncated is True

    def test_truncated_domain_correction_logic(self):
        """Test the logic for correcting truncated hostnames."""
        hostname = "ws01.child.local"
        known_domains = {"child.contoso.local", "contoso.local", "fabrikam.local"}

        # Extract domain suffix
        parts = hostname.lower().split(".", 1)
        short_name, domain_suffix = parts[0], parts[1]

        # Check if domain_suffix is known
        if domain_suffix not in known_domains:
            # Find matching known domain
            first_label = domain_suffix.split(".")[0]
            for known in known_domains:
                if known.startswith(first_label + ".") and known != domain_suffix:
                    corrected = f"{short_name}.{known}"
                    break
            else:
                corrected = hostname
        else:
            corrected = hostname

        assert corrected == "ws01.child.contoso.local"

    def test_valid_domain_not_corrected(self):
        """Test that valid domains are not incorrectly corrected."""
        hostname = "dc01.contoso.local"
        known_domains = {"child.contoso.local", "contoso.local", "fabrikam.local"}

        parts = hostname.lower().split(".", 1)
        domain_suffix = parts[1]

        # contoso.local IS a known domain, so no correction needed
        assert domain_suffix in known_domains

    def test_no_match_returns_original(self):
        """Test that hostnames with unknown domains are not changed."""
        hostname = "unknown.mystery.local"
        known_domains = {"child.contoso.local", "contoso.local"}

        parts = hostname.lower().split(".", 1)
        _, domain_suffix = parts[0], parts[1]

        # No known domain starts with "mystery."
        first_label = domain_suffix.split(".")[0]
        matches = [k for k in known_domains if k.startswith(first_label + ".")]

        assert len(matches) == 0  # No match found

    def test_child_domain_from_ldap_enables_correction(self):
        """Test that domains discovered from LDAP enable hostname correction.

        When nmap scans a child domain DC, the LDAP banner provides the
        correct child domain (e.g., "child.contoso.local"). This
        should be used to correct truncated hostnames for other hosts
        in the same scan.
        """
        # Simulate discovering domain from LDAP banner
        ldap_domain = "child.contoso.local"
        discovered_domains = set()
        discovered_domains.add(ldap_domain.lower())

        # Now a truncated hostname can be corrected
        hostname = "ws01.child.local"
        parts = hostname.lower().split(".", 1)
        short_name, domain_suffix = parts[0], parts[1]

        first_label = domain_suffix.split(".")[0]
        corrected = None
        for known in discovered_domains:
            if known.startswith(first_label + "."):
                corrected = f"{short_name}.{known}"
                break

        assert corrected == "ws01.child.contoso.local"

    def test_multiple_matching_domains_uses_first(self):
        """Test behavior when multiple domains could match."""
        # Edge case: what if we have both child.contoso.local
        # and child.fabrikam.local? Current logic uses first match.
        hostname = "srv01.child.local"
        known_domains = {"child.contoso.local", "child.fabrikam.local"}

        parts = hostname.lower().split(".", 1)
        _, domain_suffix = parts[0], parts[1]

        first_label = domain_suffix.split(".")[0]
        matches = [k for k in known_domains if k.startswith(first_label + ".")]

        # Should find matches (order not guaranteed due to set)
        assert len(matches) == 2
        # Code will use first match from iteration

    def test_short_hostname_not_affected(self):
        """Test that short hostnames without domain are not affected."""
        hostname = "ws01"

        # No dot means no domain suffix to correct
        has_domain = "." in hostname

        assert has_domain is False


class TestLDAPCredentialExtraction:
    """Tests for LDAP credential extraction edge cases.

    When parsing LDAP output, the password field (often in description)
    can appear BEFORE the sAMAccountName. The extraction logic must
    reset context at entry boundaries to avoid false positives.
    """

    def test_ldap_password_before_samaccountname_no_false_positive(self):
        """Ensure password isn't associated with previous entry's username.

        Bug scenario: LDAP output has description (with password) before
        sAMAccountName. Without proper boundary detection, password would
        be associated with the PREVIOUS user.
        """
        from ares.tools.red.reconnaissance import NetworkEnumerationTools

        # LDAP-style output where password appears before sAMAccountName
        ldap_output = """
dn: CN=Test User,OU=Users,DC=contoso,DC=local
sAMAccountName: testuser
description: Test account

dn: CN=Service Account,OU=Users,DC=contoso,DC=local
description: Password: SecretP@ss123
sAMAccountName: svc_backup
"""
        tools = NetworkEnumerationTools()
        creds = tools._extract_passwords_from_user_enum_output(ldap_output)

        # Should find exactly one credential: svc_backup with SecretP@ss123
        # Should NOT find testuser with SecretP@ss123 (false positive)
        assert len(creds) == 1
        username, password = creds[0]
        assert username == "svc_backup"
        assert password == "SecretP@ss123"  # pragma: allowlist secret

    def test_ldap_entry_boundary_resets_context(self):
        """Test that 'dn:' lines reset the user context.

        Each LDAP entry starts with 'dn:'. The current_user tracker must
        be cleared when crossing entry boundaries.
        """
        from ares.tools.red.reconnaissance import NetworkEnumerationTools

        # Multiple LDAP entries with passwords
        ldap_output = """
dn: CN=User One,OU=Users,DC=contoso,DC=local
sAMAccountName: user_one
description: Password: Pass1

dn: CN=User Two,OU=Users,DC=contoso,DC=local
sAMAccountName: user_two
description: Password: Pass2

dn: CN=User Three,OU=Users,DC=contoso,DC=local
description: Password: Pass3
sAMAccountName: user_three
"""
        tools = NetworkEnumerationTools()
        creds = tools._extract_passwords_from_user_enum_output(ldap_output)

        # Should find three credentials with correct associations
        creds_dict = dict(creds)
        assert len(creds_dict) == 3
        assert creds_dict.get("user_one") == "Pass1"
        assert creds_dict.get("user_two") == "Pass2"
        assert creds_dict.get("user_three") == "Pass3"

    def test_extraction_module_ldap_boundary_handling(self):
        """Test extraction.py also handles LDAP boundaries correctly."""
        from ares.core.dispatcher.extraction import extract_plaintext_passwords_from_output

        # LDAP output with password before sAMAccountName
        ldap_output = """
dn: CN=Admin,OU=Users,DC=contoso,DC=local
sAMAccountName: admin

dn: CN=SQL Service,OU=Service,DC=contoso,DC=local
description: Password: SqlP@ss!
sAMAccountName: sql_svc
"""
        creds = extract_plaintext_passwords_from_output(ldap_output)

        # Should find sql_svc, NOT admin
        assert len(creds) == 1
        username, password, _domain = creds[0]
        assert username == "sql_svc"
        assert password == "SqlP@ss!"  # pragma: allowlist secret
