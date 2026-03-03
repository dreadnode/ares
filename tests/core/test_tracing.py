"""Tests for the tracing module."""

from ares.core.tracing import (
    ROLE_TO_PHASE,
    ROLE_TO_TACTIC,
    TOOL_TO_CATEGORY,
    TOOL_TO_TECHNIQUE,
    create_agent_span_attributes,
    get_tool_category,
    get_tool_mitre_info,
    infer_target_type,
)


class TestToolMitreInfo:
    """Tests for get_tool_mitre_info."""

    def test_known_tool_returns_technique(self):
        """Known tools should return MITRE technique IDs."""
        technique_id, tactic = get_tool_mitre_info("secretsdump")
        assert technique_id == "T1003.006"
        assert tactic == "credential-access"

    def test_kerberoast_returns_technique(self):
        """Kerberoasting tools should map correctly."""
        technique_id, tactic = get_tool_mitre_info("kerberoast")
        assert technique_id == "T1558.003"
        assert tactic == "credential-access"

    def test_lateral_movement_tools(self):
        """Lateral movement tools should map correctly."""
        technique_id, tactic = get_tool_mitre_info("psexec")
        assert technique_id == "T1021.002"
        assert tactic == "lateral-movement"

    def test_discovery_tools(self):
        """Discovery tools should map correctly."""
        technique_id, tactic = get_tool_mitre_info("nmap_scan")
        assert technique_id == "T1046"
        assert tactic == "discovery"

    def test_unknown_tool_returns_none(self):
        """Unknown tools should return None."""
        technique_id, tactic = get_tool_mitre_info("unknown_tool")
        assert technique_id is None
        assert tactic is None


class TestToolCategory:
    """Tests for get_tool_category."""

    def test_lateral_movement_category(self):
        """Lateral movement tools should return LateralMovementTools."""
        assert get_tool_category("psexec") == "LateralMovementTools"
        assert get_tool_category("wmiexec") == "LateralMovementTools"
        assert get_tool_category("evil_winrm") == "LateralMovementTools"

    def test_credential_harvesting_category(self):
        """Credential harvesting tools should return CredentialHarvestingTools."""
        assert get_tool_category("secretsdump") == "CredentialHarvestingTools"
        assert get_tool_category("kerberoast") == "CredentialHarvestingTools"

    def test_network_enumeration_category(self):
        """Network enumeration tools should return NetworkEnumerationTools."""
        assert get_tool_category("nmap_scan") == "NetworkEnumerationTools"
        assert get_tool_category("ldap_domain_dump") == "NetworkEnumerationTools"

    def test_coercion_category(self):
        """Coercion tools should return CoercionTools."""
        assert get_tool_category("petitpotam") == "CoercionTools"
        assert get_tool_category("ntlm_relay") == "CoercionTools"

    def test_unknown_tool_returns_none(self):
        """Unknown tools should return None."""
        assert get_tool_category("unknown_tool") is None

    def test_all_technique_mapped_tools_have_categories(self):
        """All tools in TOOL_TO_TECHNIQUE should ideally have categories."""
        # This is a soft check - we want most tools to have categories
        mapped_count = 0
        for tool in TOOL_TO_TECHNIQUE:
            if tool in TOOL_TO_CATEGORY:
                mapped_count += 1
        # At least 80% of tools should have category mappings
        coverage = mapped_count / len(TOOL_TO_TECHNIQUE)
        assert coverage >= 0.8, f"Only {coverage:.0%} of tools have category mappings"


class TestCreateAgentSpanAttributes:
    """Tests for create_agent_span_attributes."""

    def test_red_team_basic_attributes(self):
        """Red team spans should have proper team attribute."""
        attrs = create_agent_span_attributes("recon", "red")
        assert attrs["attack_team"] == "red"
        assert attrs["agent.role"] == "recon"
        assert attrs["mitre.tactic"] == "discovery"
        assert attrs["attack_phase"] == "reconnaissance"

    def test_blue_team_basic_attributes(self):
        """Blue team spans should have proper team attribute."""
        attrs = create_agent_span_attributes("triage", "blue")
        assert attrs["attack_team"] == "blue"
        assert attrs["agent.role"] == "triage"
        assert attrs["attack_phase"] == "initial-triage"

    def test_tool_name_adds_technique(self):
        """Tool names should add MITRE technique IDs."""
        attrs = create_agent_span_attributes("credential_access", "red", tool_name="secretsdump")
        assert attrs["mitre.technique.id"] == "T1003.006"
        assert attrs["mitre.tactic"] == "credential-access"
        assert attrs["tool.name"] == "secretsdump"

    def test_attack_tool_name_attribute(self):
        """Tool names should set attack_tool_name for Tempo metrics."""
        attrs = create_agent_span_attributes("lateral", "red", tool_name="psexec")
        assert attrs["attack_tool_name"] == "psexec"

    def test_attack_tool_category_attribute(self):
        """Known tools should set attack_tool_category."""
        attrs = create_agent_span_attributes("lateral", "red", tool_name="psexec")
        assert attrs["attack_tool_category"] == "LateralMovementTools"

    def test_attack_tool_category_not_set_for_unknown_tool(self):
        """Unknown tools should not have attack_tool_category."""
        attrs = create_agent_span_attributes("recon", "red", tool_name="unknown_tool")
        assert attrs["attack_tool_name"] == "unknown_tool"
        assert "attack_tool_category" not in attrs

    def test_additional_attrs_merged(self):
        """Additional attributes should be merged."""
        attrs = create_agent_span_attributes(
            "recon", "red", additional_attrs={"custom.attr": "value"}
        )
        assert attrs["custom.attr"] == "value"
        assert attrs["attack_team"] == "red"


class TestInferTargetType:
    """Tests for infer_target_type function."""

    def test_dc_hostname_patterns(self):
        """DC hostname patterns should return domain_controller."""
        assert infer_target_type("dc01") == "domain_controller"
        assert infer_target_type("DC02") == "domain_controller"
        assert infer_target_type("dc01.contoso.local") == "domain_controller"

    def test_sql_hostname_patterns(self):
        """SQL hostname patterns should return sql_server."""
        assert infer_target_type("sql01") == "sql_server"
        assert infer_target_type("mssql") == "sql_server"

    def test_web_hostname_patterns(self):
        """Web hostname patterns should return web_server."""
        assert infer_target_type("web01") == "web_server"
        assert infer_target_type("www") == "web_server"

    def test_workstation_patterns(self):
        """Workstation patterns should return workstation."""
        assert infer_target_type("ws01") == "workstation"
        assert infer_target_type("pc01") == "workstation"

    def test_generic_server(self):
        """Unknown hostnames should return server."""
        assert infer_target_type("somehost") == "server"

    def test_ip_in_dc_set(self):
        """IP in known DC set should return domain_controller."""
        dc_ips = {"192.168.58.10", "192.168.58.20"}
        assert infer_target_type("192.168.58.10", dc_ips) == "domain_controller"
        assert infer_target_type("192.168.58.30", dc_ips) == "server"

    def test_none_returns_none(self):
        """None hostname should return None."""
        assert infer_target_type(None) is None


class TestTargetAttributes:
    """Tests for target_host and target_type in span attributes."""

    def test_target_host_included(self):
        """Target host should be included using OTel destination.address."""
        attrs = create_agent_span_attributes("lateral", "red", target_host="192.168.58.10")
        assert attrs["destination.address"] == "192.168.58.10"

    def test_target_type_included(self):
        """Explicit target type should be included using attack.target.type."""
        attrs = create_agent_span_attributes(
            "lateral", "red", target_host="192.168.58.10", target_type="domain_controller"
        )
        assert attrs["attack.target.type"] == "domain_controller"

    def test_target_type_inferred_from_hostname(self):
        """Target type should be inferred from hostname if not provided."""
        attrs = create_agent_span_attributes("lateral", "red", target_host="dc01.contoso.local")
        assert attrs["attack.target.type"] == "domain_controller"

    def test_target_type_not_overwritten_when_explicit(self):
        """Explicit target type should not be overwritten by inference."""
        attrs = create_agent_span_attributes(
            "lateral", "red", target_host="dc01", target_type="custom_type"
        )
        assert attrs["attack.target.type"] == "custom_type"

    def test_target_user_included(self):
        """Target user should be included using OTel user.name."""
        attrs = create_agent_span_attributes("credential_access", "red", target_user="svc_backup")
        assert attrs["user.name"] == "svc_backup"
        assert attrs["attack.target.type"] == "user"

    def test_target_domain_included(self):
        """Target domain should be included using attack.target.domain."""
        attrs = create_agent_span_attributes(
            "lateral", "red", target_host="dc01.contoso.local", target_domain="contoso.local"
        )
        assert attrs["attack.target.domain"] == "contoso.local"

    def test_target_domain_inferred_from_fqdn(self):
        """Target domain should be inferred from FQDN if not provided."""
        attrs = create_agent_span_attributes("lateral", "red", target_host="dc01.contoso.local")
        assert attrs["attack.target.domain"] == "contoso.local"

    def test_target_domain_not_inferred_from_ip(self):
        """Target domain should not be inferred from IP addresses."""
        attrs = create_agent_span_attributes("lateral", "red", target_host="192.168.58.10")
        assert "attack.target.domain" not in attrs


class TestMitreMappings:
    """Tests for MITRE mappings completeness."""

    def test_all_red_roles_have_tactics(self):
        """All red team roles should have tactic mappings."""
        red_roles = [
            "orchestrator",
            "recon",
            "credential_access",
            "cracker",
            "acl",
            "privesc",
            "lateral",
            "coercion",
        ]
        for role in red_roles:
            assert role in ROLE_TO_TACTIC, f"Role {role} missing from ROLE_TO_TACTIC"
            assert role in ROLE_TO_PHASE, f"Role {role} missing from ROLE_TO_PHASE"

    def test_common_tools_have_mappings(self):
        """Common attack tools should have technique mappings."""
        required_tools = [
            "secretsdump",
            "kerberoast",
            "psexec",
            "nmap_scan",
            "bloodhound_collection",
        ]
        for tool in required_tools:
            assert tool in TOOL_TO_TECHNIQUE, f"Tool {tool} missing from TOOL_TO_TECHNIQUE"


class TestTraceToolCall:
    """Tests for trace_tool_call function."""

    def test_trace_tool_call_success(self):
        """trace_tool_call should create span without raising."""
        from unittest.mock import MagicMock, patch

        from ares.core.tracing import trace_tool_call

        mock_span = MagicMock()
        mock_span.__enter__ = MagicMock(return_value=mock_span)
        mock_span.__exit__ = MagicMock(return_value=False)

        with patch("dreadnode.span", return_value=mock_span) as mock_dn_span:
            # Should not raise
            trace_tool_call("recon", "red", "nmap_scan", is_error=False)

        mock_dn_span.assert_called_once()
        call_kwargs = mock_dn_span.call_args[1]
        assert "tool.nmap_scan" in mock_dn_span.call_args[0][0]
        assert call_kwargs["attributes"]["tool.status"] == "success"

    def test_trace_tool_call_with_error(self):
        """trace_tool_call should record error status and message."""
        from unittest.mock import MagicMock, patch

        from ares.core.tracing import trace_tool_call

        mock_span = MagicMock()
        mock_span.__enter__ = MagicMock(return_value=mock_span)
        mock_span.__exit__ = MagicMock(return_value=False)

        with patch("dreadnode.span", return_value=mock_span) as mock_dn_span:
            trace_tool_call(
                "credential_access",
                "red",
                "secretsdump",
                is_error=True,
                error_message="Connection refused",
            )

        call_kwargs = mock_dn_span.call_args[1]
        assert call_kwargs["attributes"]["tool.status"] == "error"
        assert call_kwargs["attributes"]["error.message"] == "Connection refused"

    def test_trace_tool_call_truncates_long_error(self):
        """trace_tool_call should truncate error messages over 500 chars."""
        from unittest.mock import MagicMock, patch

        from ares.core.tracing import trace_tool_call

        mock_span = MagicMock()
        mock_span.__enter__ = MagicMock(return_value=mock_span)
        mock_span.__exit__ = MagicMock(return_value=False)

        long_error = "x" * 1000

        with patch("dreadnode.span", return_value=mock_span) as mock_dn_span:
            trace_tool_call("recon", "red", "nmap_scan", is_error=True, error_message=long_error)

        call_kwargs = mock_dn_span.call_args[1]
        assert len(call_kwargs["attributes"]["error.message"]) == 500

    def test_trace_tool_call_handles_span_exception(self):
        """trace_tool_call should not raise if span creation fails."""
        from unittest.mock import patch

        from ares.core.tracing import trace_tool_call

        with patch("dreadnode.span", side_effect=Exception("Tracing unavailable")):
            # Should not raise - just logs debug
            trace_tool_call("recon", "red", "nmap_scan")

    def test_trace_tool_call_with_target_host(self):
        """trace_tool_call should include target host using OTel conventions."""
        from unittest.mock import MagicMock, patch

        from ares.core.tracing import trace_tool_call

        mock_span = MagicMock()
        mock_span.__enter__ = MagicMock(return_value=mock_span)
        mock_span.__exit__ = MagicMock(return_value=False)

        with patch("dreadnode.span", return_value=mock_span) as mock_dn_span:
            trace_tool_call(
                "lateral",
                "red",
                "psexec",
                target_host="dc01.contoso.local",
            )

        call_kwargs = mock_dn_span.call_args[1]
        assert call_kwargs["attributes"]["destination.address"] == "dc01.contoso.local"
        assert call_kwargs["attributes"]["attack.target.type"] == "domain_controller"
        assert call_kwargs["attributes"]["attack.target.domain"] == "contoso.local"

    def test_trace_tool_call_with_explicit_target_type(self):
        """trace_tool_call should use explicit target type."""
        from unittest.mock import MagicMock, patch

        from ares.core.tracing import trace_tool_call

        mock_span = MagicMock()
        mock_span.__enter__ = MagicMock(return_value=mock_span)
        mock_span.__exit__ = MagicMock(return_value=False)

        with patch("dreadnode.span", return_value=mock_span) as mock_dn_span:
            trace_tool_call(
                "lateral",
                "red",
                "psexec",
                target_host="192.168.58.10",
                target_type="domain_controller",
            )

        call_kwargs = mock_dn_span.call_args[1]
        assert call_kwargs["attributes"]["destination.address"] == "192.168.58.10"
        assert call_kwargs["attributes"]["attack.target.type"] == "domain_controller"

    def test_trace_tool_call_with_target_user(self):
        """trace_tool_call should include target user using OTel user.name."""
        from unittest.mock import MagicMock, patch

        from ares.core.tracing import trace_tool_call

        mock_span = MagicMock()
        mock_span.__enter__ = MagicMock(return_value=mock_span)
        mock_span.__exit__ = MagicMock(return_value=False)

        with patch("dreadnode.span", return_value=mock_span) as mock_dn_span:
            trace_tool_call(
                "credential_access",
                "red",
                "kerberoast",
                target_user="svc_backup",
                target_domain="contoso.local",
            )

        call_kwargs = mock_dn_span.call_args[1]
        assert call_kwargs["attributes"]["user.name"] == "svc_backup"
        assert call_kwargs["attributes"]["attack.target.type"] == "user"
        assert call_kwargs["attributes"]["attack.target.domain"] == "contoso.local"

    def test_trace_tool_call_includes_attack_tool_attrs(self):
        """trace_tool_call should include attack_tool_name and attack_tool_category."""
        from unittest.mock import MagicMock, patch

        from ares.core.tracing import trace_tool_call

        mock_span = MagicMock()
        mock_span.__enter__ = MagicMock(return_value=mock_span)
        mock_span.__exit__ = MagicMock(return_value=False)

        with patch("dreadnode.span", return_value=mock_span) as mock_dn_span:
            trace_tool_call(
                "lateral",
                "red",
                "psexec",
                target_host="dc01.contoso.local",
            )

        call_kwargs = mock_dn_span.call_args[1]
        assert call_kwargs["attributes"]["attack_tool_name"] == "psexec"
        assert call_kwargs["attributes"]["attack_tool_category"] == "LateralMovementTools"


class TestTraceBlueInvestigation:
    """Tests for trace_blue_investigation function."""

    def test_trace_blue_investigation_basic(self):
        """trace_blue_investigation should create span with investigation attributes."""
        from unittest.mock import MagicMock, patch

        from ares.core.tracing import trace_blue_investigation

        mock_span = MagicMock()
        mock_span.__enter__ = MagicMock(return_value=mock_span)
        mock_span.__exit__ = MagicMock(return_value=False)

        with patch("dreadnode.span", return_value=mock_span) as mock_dn_span:
            trace_blue_investigation(
                role="triage",
                investigation_id="inv-12345",
            )

        mock_dn_span.assert_called_once()
        call_kwargs = mock_dn_span.call_args[1]
        assert call_kwargs["attributes"]["investigation.id"] == "inv-12345"
        assert call_kwargs["attributes"]["attack_team"] == "blue"

    def test_trace_blue_investigation_with_techniques(self):
        """trace_blue_investigation should record MITRE techniques found."""
        from unittest.mock import MagicMock, patch

        from ares.core.tracing import trace_blue_investigation

        mock_span = MagicMock()
        mock_span.__enter__ = MagicMock(return_value=mock_span)
        mock_span.__exit__ = MagicMock(return_value=False)

        with patch("dreadnode.span", return_value=mock_span) as mock_dn_span:
            trace_blue_investigation(
                role="threat_hunter",
                investigation_id="inv-hunt",
                techniques_found=["T1003", "T1558.003", "T1021"],
            )

        call_kwargs = mock_dn_span.call_args[1]
        assert call_kwargs["attributes"]["mitre.technique.id"] == "T1003"
        assert call_kwargs["attributes"]["mitre.techniques.count"] == 3

    def test_trace_blue_investigation_with_severity(self):
        """trace_blue_investigation should record severity assessment."""
        from unittest.mock import MagicMock, patch

        from ares.core.tracing import trace_blue_investigation

        mock_span = MagicMock()
        mock_span.__enter__ = MagicMock(return_value=mock_span)
        mock_span.__exit__ = MagicMock(return_value=False)

        with patch("dreadnode.span", return_value=mock_span) as mock_dn_span:
            trace_blue_investigation(
                role="triage",
                investigation_id="inv-critical",
                severity="critical",
            )

        call_kwargs = mock_dn_span.call_args[1]
        assert call_kwargs["attributes"]["investigation.severity"] == "critical"

    def test_trace_blue_investigation_handles_exception(self):
        """trace_blue_investigation should not raise if span creation fails."""
        from unittest.mock import patch

        from ares.core.tracing import trace_blue_investigation

        with patch("dreadnode.span", side_effect=Exception("Tracing unavailable")):
            # Should not raise - just logs debug
            trace_blue_investigation(role="triage", investigation_id="inv-fail")
