"""Tests for the tracing module."""

from unittest.mock import MagicMock, patch

from ares.core.tracing import (
    ROLE_TO_PHASE,
    ROLE_TO_TACTIC,
    TOOL_TO_CATEGORY,
    TOOL_TO_TECHNIQUE,
    create_agent_span_attributes,
    get_tool_category,
    get_tool_mitre_info,
    infer_target_type,
    is_likely_fqdn,
    setup_otel_tracing,
)


class TestSetupOtelTracing:
    """Tests for setup_otel_tracing function."""

    def test_returns_false_when_no_endpoint_configured(self, monkeypatch):
        """Should return False when no OTEL endpoint is configured."""
        # Clear any existing env vars
        monkeypatch.delenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", raising=False)
        monkeypatch.delenv("OTEL_EXPORTER_OTLP_ENDPOINT", raising=False)

        # Reset initialization state
        import ares.core.tracing as tracing_module

        tracing_module._otel_initialized = False

        result = setup_otel_tracing()
        assert result is False

    def test_configures_from_traces_endpoint(self, monkeypatch):
        """Should configure TracerProvider from OTEL_EXPORTER_OTLP_TRACES_ENDPOINT."""
        monkeypatch.setenv(
            "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
            "http://alloy.test.local:4318/v1/traces",
        )
        monkeypatch.setenv("OTEL_SERVICE_NAME", "ares-test-agent")

        # Reset initialization state
        import ares.core.tracing as tracing_module

        tracing_module._otel_initialized = False

        # Mock at the source module level since imports are inside the function
        with (
            patch("opentelemetry.trace.set_tracer_provider") as mock_set_provider,
            patch("opentelemetry.sdk.trace.TracerProvider") as mock_provider_cls,
            patch(
                "opentelemetry.exporter.otlp.proto.http.trace_exporter.OTLPSpanExporter"
            ) as mock_exporter_cls,
            patch("opentelemetry.sdk.trace.export.BatchSpanProcessor"),
            patch("opentelemetry.sdk.resources.Resource") as mock_resource_cls,
        ):
            # Setup mocks
            mock_provider = MagicMock()
            mock_provider_cls.return_value = mock_provider
            mock_resource_cls.create.return_value = MagicMock()

            result = setup_otel_tracing()

            assert result is True
            mock_exporter_cls.assert_called_once_with(
                endpoint="http://alloy.test.local:4318/v1/traces"
            )
            mock_set_provider.assert_called_once_with(mock_provider)

    def test_configures_from_base_endpoint(self, monkeypatch):
        """Should append /v1/traces to base OTEL_EXPORTER_OTLP_ENDPOINT."""
        monkeypatch.delenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", raising=False)
        monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://collector.test:4318")
        monkeypatch.setenv("OTEL_SERVICE_NAME", "ares-test")

        # Reset initialization state
        import ares.core.tracing as tracing_module

        tracing_module._otel_initialized = False

        with (
            patch("opentelemetry.trace.set_tracer_provider"),
            patch("opentelemetry.sdk.trace.TracerProvider") as mock_provider_cls,
            patch(
                "opentelemetry.exporter.otlp.proto.http.trace_exporter.OTLPSpanExporter"
            ) as mock_exporter_cls,
            patch("opentelemetry.sdk.trace.export.BatchSpanProcessor"),
            patch("opentelemetry.sdk.resources.Resource"),
        ):
            mock_provider_cls.return_value = MagicMock()

            result = setup_otel_tracing()

            assert result is True
            mock_exporter_cls.assert_called_once_with(
                endpoint="http://collector.test:4318/v1/traces"
            )

    def test_parses_resource_attributes(self, monkeypatch):
        """Should parse OTEL_RESOURCE_ATTRIBUTES into resource."""
        monkeypatch.setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "http://test:4318/v1/traces")
        monkeypatch.setenv("OTEL_SERVICE_NAME", "ares-agent")
        monkeypatch.setenv(
            "OTEL_RESOURCE_ATTRIBUTES",
            "service.namespace=attack-simulation,deployment.environment=staging,attack.team=red",
        )

        # Reset initialization state
        import ares.core.tracing as tracing_module

        tracing_module._otel_initialized = False

        with (
            patch("opentelemetry.trace.set_tracer_provider"),
            patch("opentelemetry.sdk.trace.TracerProvider") as mock_provider_cls,
            patch("opentelemetry.exporter.otlp.proto.http.trace_exporter.OTLPSpanExporter"),
            patch("opentelemetry.sdk.trace.export.BatchSpanProcessor"),
            patch("opentelemetry.sdk.resources.Resource") as mock_resource_cls,
        ):
            mock_provider_cls.return_value = MagicMock()
            mock_resource_cls.create.return_value = MagicMock()

            result = setup_otel_tracing()

            assert result is True
            # Verify resource was created with parsed attributes
            call_args = mock_resource_cls.create.call_args[0][0]
            assert call_args["service.name"] == "ares-agent"
            assert call_args["service.namespace"] == "attack-simulation"
            assert call_args["deployment.environment"] == "staging"
            assert call_args["attack.team"] == "red"

    def test_returns_true_when_already_initialized(self, monkeypatch):
        """Should return True without reconfiguring when already initialized."""
        monkeypatch.setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "http://test:4318")

        # Set already initialized
        import ares.core.tracing as tracing_module

        tracing_module._otel_initialized = True

        with patch("ares.core.tracing.trace.set_tracer_provider") as mock_set:
            result = setup_otel_tracing()

            assert result is True
            mock_set.assert_not_called()  # Should not reconfigure

    def test_handles_import_error_gracefully(self, monkeypatch):
        """Should return False gracefully if OTEL dependencies unavailable."""
        monkeypatch.setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "http://test:4318/v1/traces")

        # Reset initialization state
        import ares.core.tracing as tracing_module

        tracing_module._otel_initialized = False

        # Simulate import failure by making the exporter import raise
        with patch(
            "opentelemetry.exporter.otlp.proto.http.trace_exporter.OTLPSpanExporter",
            side_effect=ImportError("No module"),
        ):
            result = setup_otel_tracing()
            assert result is False

    def test_handles_configuration_error_gracefully(self, monkeypatch):
        """Should return False gracefully if TracerProvider configuration fails."""
        monkeypatch.setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "http://test:4318/v1/traces")
        monkeypatch.setenv("OTEL_SERVICE_NAME", "test")

        # Reset initialization state
        import ares.core.tracing as tracing_module

        tracing_module._otel_initialized = False

        with patch(
            "opentelemetry.sdk.trace.TracerProvider",
            side_effect=Exception("Config error"),
        ):
            result = setup_otel_tracing()
            assert result is False


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

    def test_recon_agent_tools(self):
        """Recon agent tools should have technique IDs."""
        # enumerate_users - Account Discovery: Domain Account
        technique_id, tactic = get_tool_mitre_info("enumerate_users")
        assert technique_id == "T1087.002"
        assert tactic == "discovery"

        # run_bloodhound - Account Discovery: Domain Account
        technique_id, tactic = get_tool_mitre_info("run_bloodhound")
        assert technique_id == "T1087.002"
        assert tactic == "discovery"

        # resolve_domain_controllers - Remote System Discovery
        technique_id, tactic = get_tool_mitre_info("resolve_domain_controllers")
        assert technique_id == "T1018"
        assert tactic == "discovery"

        # smb_sweep - Network Service Scanning
        technique_id, tactic = get_tool_mitre_info("smb_sweep")
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
        assert get_tool_category("smb_sweep") == "NetworkEnumerationTools"
        assert get_tool_category("resolve_domain_controllers") == "NetworkEnumerationTools"
        assert get_tool_category("enumerate_users") == "NetworkEnumerationTools"

    def test_bloodhound_category(self):
        """BloodHound tools should return BloodHoundTools."""
        assert get_tool_category("run_bloodhound") == "BloodHoundTools"

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


class TestIsLikelyFqdn:
    """Tests for is_likely_fqdn function - distinguishes FQDNs from usernames."""

    def test_fqdn_with_local_suffix(self):
        """FQDNs ending in .local should return True."""
        assert is_likely_fqdn("dc01.contoso.local") is True
        assert is_likely_fqdn("server.domain.local") is True

    def test_fqdn_with_other_tld(self):
        """FQDNs with common TLDs should return True."""
        assert is_likely_fqdn("host.company.com") is True
        assert is_likely_fqdn("server.internal") is True
        assert is_likely_fqdn("db.corp") is True

    def test_username_with_dot_returns_false(self):
        """Usernames like 'jane.doe' should return False."""
        assert is_likely_fqdn("jane.doe") is False
        assert is_likely_fqdn("john.doe") is False
        assert is_likely_fqdn("john.doe") is False

    def test_three_segment_fqdn(self):
        """3+ segment names should return True (FQDNs)."""
        assert is_likely_fqdn("dc01.child.parent") is True
        assert is_likely_fqdn("server.sub.domain") is True

    def test_hostname_prefix_patterns(self):
        """Two-segment names with hostname prefixes should return True."""
        assert is_likely_fqdn("dc01.domain") is True
        assert is_likely_fqdn("sql01.network") is True
        assert is_likely_fqdn("web01.something") is True

    def test_ip_address_returns_false(self):
        """IP addresses should return False (not FQDNs)."""
        assert is_likely_fqdn("192.168.58.10") is False
        assert is_likely_fqdn("192.168.58.20") is False

    def test_plain_hostname_returns_false(self):
        """Plain hostnames without dots should return False."""
        assert is_likely_fqdn("dc01") is False
        assert is_likely_fqdn("server") is False

    def test_empty_and_none_returns_false(self):
        """Empty string and None should return False."""
        assert is_likely_fqdn("") is False
        assert is_likely_fqdn(None) is False  # type: ignore[arg-type]


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
    """Tests for target_ip, target_fqdn and target_type in span attributes."""

    def test_target_ip_included(self):
        """Target IP should be in destination.ip."""
        attrs = create_agent_span_attributes("lateral", "red", target_ip="192.168.58.10")
        assert attrs["destination.ip"] == "192.168.58.10"
        assert "destination.address" not in attrs  # No FQDN provided

    def test_target_type_included(self):
        """Explicit target type should be included using attack_target_type."""
        attrs = create_agent_span_attributes(
            "lateral", "red", target_ip="192.168.58.10", target_type="domain_controller"
        )
        assert attrs["attack_target_type"] == "domain_controller"

    def test_target_type_inferred_from_fqdn(self):
        """Target type should be inferred from FQDN if not provided."""
        attrs = create_agent_span_attributes("lateral", "red", target_fqdn="dc01.contoso.local")
        assert attrs["attack_target_type"] == "domain_controller"

    def test_target_type_not_overwritten_when_explicit(self):
        """Explicit target type should not be overwritten by inference."""
        attrs = create_agent_span_attributes(
            "lateral", "red", target_hostname="dc01", target_type="custom_type"
        )
        assert attrs["attack_target_type"] == "custom_type"

    def test_target_user_included(self):
        """Target user should be included using OTel user.name."""
        attrs = create_agent_span_attributes("credential_access", "red", target_user="svc_backup")
        assert attrs["user.name"] == "svc_backup"
        assert attrs["attack_target_type"] == "user"

    def test_target_domain_included(self):
        """Target domain should be included using attack_target_domain."""
        attrs = create_agent_span_attributes(
            "lateral", "red", target_fqdn="dc01.contoso.local", target_domain="contoso.local"
        )
        assert attrs["attack_target_domain"] == "contoso.local"

    def test_target_domain_inferred_from_fqdn(self):
        """Target domain should be inferred from FQDN if not provided."""
        attrs = create_agent_span_attributes("lateral", "red", target_fqdn="dc01.contoso.local")
        assert attrs["attack_target_domain"] == "contoso.local"

    def test_target_domain_not_inferred_from_ip(self):
        """Target domain should not be inferred from IP addresses."""
        attrs = create_agent_span_attributes("lateral", "red", target_ip="192.168.58.10")
        assert "attack_target_domain" not in attrs


class TestIpFqdnSeparation:
    """Tests for separate IP, FQDN, and hostname attributes."""

    def test_target_ip_sets_destination_ip(self):
        """Target IP should be used for destination.ip (separate from FQDN)."""
        attrs = create_agent_span_attributes("lateral", "red", target_ip="192.168.58.10")
        # IP goes to destination.ip, destination.address is for FQDNs only
        assert attrs["destination.ip"] == "192.168.58.10"
        assert "destination.address" not in attrs
        assert "server.address" not in attrs
        assert "host.name" not in attrs

    def test_target_fqdn_sets_server_address_and_host_name(self):
        """Target FQDN should set server.address and derive host.name."""
        attrs = create_agent_span_attributes("lateral", "red", target_fqdn="dc01.contoso.local")
        assert attrs["destination.address"] == "dc01.contoso.local"
        assert attrs["server.address"] == "dc01.contoso.local"
        assert attrs["host.name"] == "dc01"
        assert attrs["attack_target_domain"] == "contoso.local"

    def test_fqdn_and_ip_in_separate_fields(self):
        """When both IP and FQDN provided, they should be in separate fields."""
        attrs = create_agent_span_attributes(
            "lateral",
            "red",
            target_ip="192.168.58.10",
            target_fqdn="dc01.contoso.local",
        )
        # FQDN goes to destination.address and server.address
        assert attrs["destination.address"] == "dc01.contoso.local"
        assert attrs["server.address"] == "dc01.contoso.local"
        assert attrs["host.name"] == "dc01"
        # IP goes to separate destination.ip field
        assert attrs["destination.ip"] == "192.168.58.10"

    def test_target_hostname_without_fqdn(self):
        """Plain hostname should set host.name without server.address."""
        attrs = create_agent_span_attributes("lateral", "red", target_hostname="dc01")
        assert attrs["host.name"] == "dc01"
        assert "server.address" not in attrs

    def test_explicit_hostname_overrides_fqdn_derivation(self):
        """Explicit target_hostname should override FQDN-derived hostname."""
        attrs = create_agent_span_attributes(
            "lateral",
            "red",
            target_fqdn="dc01.contoso.local",
            target_hostname="custom-host",
        )
        assert attrs["host.name"] == "custom-host"
        assert attrs["server.address"] == "dc01.contoso.local"

    def test_target_type_inferred_from_fqdn(self):
        """Target type should be inferred from FQDN hostname part."""
        attrs = create_agent_span_attributes("lateral", "red", target_fqdn="dc01.contoso.local")
        assert attrs["attack_target_type"] == "domain_controller"

    def test_target_type_inferred_from_hostname(self):
        """Target type should be inferred from explicit hostname."""
        attrs = create_agent_span_attributes("lateral", "red", target_hostname="sql01")
        assert attrs["attack_target_type"] == "sql_server"

    def test_all_fields_combined(self):
        """Test all new fields combined with user and domain."""
        attrs = create_agent_span_attributes(
            "lateral",
            "red",
            tool_name="psexec",
            target_ip="192.168.58.10",
            target_fqdn="dc01.contoso.local",
            target_hostname="dc01",
            target_user="administrator",
            target_domain="contoso.local",
        )
        # FQDN goes to destination.address and server.address
        assert attrs["destination.address"] == "dc01.contoso.local"
        assert attrs["server.address"] == "dc01.contoso.local"
        # IP goes to separate destination.ip field
        assert attrs["destination.ip"] == "192.168.58.10"
        assert attrs["host.name"] == "dc01"
        assert attrs["user.name"] == "administrator"
        assert attrs["attack_target_domain"] == "contoso.local"
        assert attrs["attack_target_type"] == "domain_controller"

    def test_dc_ips_enables_dc_detection_from_ip(self):
        """DC IPs set should enable domain_controller detection from IP alone."""
        dc_ips = {"192.168.58.10", "192.168.58.20"}
        attrs = create_agent_span_attributes(
            "lateral",
            "red",
            target_ip="192.168.58.10",
            dc_ips=dc_ips,
        )
        # IP is in dc_ips set, so should be detected as domain_controller
        assert attrs["attack_target_type"] == "domain_controller"
        assert attrs["destination.ip"] == "192.168.58.10"

    def test_dc_ips_non_dc_ip_remains_server(self):
        """IP not in DC IPs set should remain as server type."""
        dc_ips = {"192.168.58.10", "192.168.58.20"}
        attrs = create_agent_span_attributes(
            "lateral",
            "red",
            target_ip="192.168.58.30",  # Not in dc_ips
            dc_ips=dc_ips,
        )
        # IP is not in dc_ips set, so should be server
        assert attrs["attack_target_type"] == "server"

    def test_host_name_type_fqdn(self):
        """host.name.type should be 'fqdn' when target_fqdn is provided."""
        attrs = create_agent_span_attributes("lateral", "red", target_fqdn="dc01.contoso.local")
        assert attrs["host.name.type"] == "fqdn"

    def test_host_name_type_netbios(self):
        """host.name.type should be 'netbios' when only target_hostname is provided."""
        attrs = create_agent_span_attributes("lateral", "red", target_hostname="dc01")
        assert attrs["host.name.type"] == "netbios"

    def test_host_name_type_ip_only(self):
        """host.name.type should be 'ip_only' when only target_ip is provided."""
        attrs = create_agent_span_attributes("lateral", "red", target_ip="192.168.58.10")
        assert attrs["host.name.type"] == "ip_only"

    def test_host_name_type_fqdn_preferred_over_hostname(self):
        """host.name.type should be 'fqdn' when both FQDN and hostname provided."""
        attrs = create_agent_span_attributes(
            "lateral",
            "red",
            target_fqdn="dc01.contoso.local",
            target_hostname="dc01",
        )
        assert attrs["host.name.type"] == "fqdn"

    def test_host_name_type_not_set_when_no_target(self):
        """host.name.type should not be set when no target info provided."""
        attrs = create_agent_span_attributes("lateral", "red")
        assert "host.name.type" not in attrs


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

    def test_trace_tool_call_with_target_fqdn(self):
        """trace_tool_call should include target FQDN using OTel conventions."""
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
                target_fqdn="dc01.contoso.local",
            )

        call_kwargs = mock_dn_span.call_args[1]
        assert call_kwargs["attributes"]["destination.address"] == "dc01.contoso.local"
        assert call_kwargs["attributes"]["attack_target_type"] == "domain_controller"
        assert call_kwargs["attributes"]["attack_target_domain"] == "contoso.local"

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
                target_ip="192.168.58.10",
                target_type="domain_controller",
            )

        call_kwargs = mock_dn_span.call_args[1]
        # IP goes to destination.ip (separate from FQDN in destination.address)
        assert call_kwargs["attributes"]["destination.ip"] == "192.168.58.10"
        assert call_kwargs["attributes"]["attack_target_type"] == "domain_controller"

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
        assert call_kwargs["attributes"]["attack_target_type"] == "user"
        assert call_kwargs["attributes"]["attack_target_domain"] == "contoso.local"

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
                target_fqdn="dc01.contoso.local",
            )

        call_kwargs = mock_dn_span.call_args[1]
        assert call_kwargs["attributes"]["attack_tool_name"] == "psexec"
        assert call_kwargs["attributes"]["attack_tool_category"] == "LateralMovementTools"

    def test_trace_tool_call_with_operation_id(self):
        """trace_tool_call should include attack_operation_id for Tempo correlation."""
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
                target_fqdn="dc01.contoso.local",
                operation_id="op-12345",
            )

        call_kwargs = mock_dn_span.call_args[1]
        assert call_kwargs["attributes"]["attack_operation_id"] == "op-12345"

    def test_trace_tool_call_without_operation_id(self):
        """trace_tool_call should not include attack_operation_id when not provided."""
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
                target_fqdn="dc01.contoso.local",
            )

        call_kwargs = mock_dn_span.call_args[1]
        assert "attack_operation_id" not in call_kwargs["attributes"]

    def test_trace_tool_call_with_credential_domain(self):
        """trace_tool_call should include credential.domain for cross-domain attacks."""
        from unittest.mock import MagicMock, patch

        from ares.core.tracing import trace_tool_call

        mock_span = MagicMock()
        mock_span.__enter__ = MagicMock(return_value=mock_span)
        mock_span.__exit__ = MagicMock(return_value=False)

        # Scenario: child domain user (child.contoso.local) attacking parent domain
        with patch("dreadnode.span", return_value=mock_span) as mock_dn_span:
            trace_tool_call(
                "lateral",
                "red",
                "secretsdump",
                target_fqdn="dc01.contoso.local",
                target_domain="contoso.local",  # Parent domain (target)
                target_user="bob.smith",
                credential_domain="child.contoso.local",  # Child domain (credential)
            )

        call_kwargs = mock_dn_span.call_args[1]
        # Target domain is where the attack is directed
        assert call_kwargs["attributes"]["attack_target_domain"] == "contoso.local"
        # Credential domain is where the user actually belongs
        assert call_kwargs["attributes"]["credential.domain"] == "child.contoso.local"
        assert call_kwargs["attributes"]["user.name"] == "bob.smith"

    def test_trace_tool_call_credential_domain_not_set_when_none(self):
        """trace_tool_call should not include credential.domain when not provided."""
        from unittest.mock import MagicMock, patch

        from ares.core.tracing import trace_tool_call

        mock_span = MagicMock()
        mock_span.__enter__ = MagicMock(return_value=mock_span)
        mock_span.__exit__ = MagicMock(return_value=False)

        with patch("dreadnode.span", return_value=mock_span) as mock_dn_span:
            trace_tool_call(
                "lateral",
                "red",
                "secretsdump",
                target_fqdn="dc01.contoso.local",
                target_domain="contoso.local",
            )

        call_kwargs = mock_dn_span.call_args[1]
        assert call_kwargs["attributes"]["attack_target_domain"] == "contoso.local"
        assert "credential.domain" not in call_kwargs["attributes"]


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

    def test_trace_blue_investigation_with_operation_id(self):
        """trace_blue_investigation should include attack_operation_id for red-blue correlation."""
        from unittest.mock import MagicMock, patch

        from ares.core.tracing import trace_blue_investigation

        mock_span = MagicMock()
        mock_span.__enter__ = MagicMock(return_value=mock_span)
        mock_span.__exit__ = MagicMock(return_value=False)

        with patch("dreadnode.span", return_value=mock_span) as mock_dn_span:
            trace_blue_investigation(
                role="triage",
                investigation_id="inv-correlated",
                operation_id="op-red-12345",
            )

        call_kwargs = mock_dn_span.call_args[1]
        assert call_kwargs["attributes"]["investigation.id"] == "inv-correlated"
        assert call_kwargs["attributes"]["attack_operation_id"] == "op-red-12345"
        assert call_kwargs["attributes"]["attack_team"] == "blue"

    def test_trace_blue_investigation_without_operation_id(self):
        """trace_blue_investigation should not include attack_operation_id if not provided."""
        from unittest.mock import MagicMock, patch

        from ares.core.tracing import trace_blue_investigation

        mock_span = MagicMock()
        mock_span.__enter__ = MagicMock(return_value=mock_span)
        mock_span.__exit__ = MagicMock(return_value=False)

        with patch("dreadnode.span", return_value=mock_span) as mock_dn_span:
            trace_blue_investigation(
                role="threat_hunter",
                investigation_id="inv-standalone",
            )

        call_kwargs = mock_dn_span.call_args[1]
        assert call_kwargs["attributes"]["investigation.id"] == "inv-standalone"
        assert "attack_operation_id" not in call_kwargs["attributes"]


class TestTraceDecision:
    """Tests for trace_decision function."""

    def test_trace_decision_creates_span_with_tool_info(self):
        """trace_decision should create a span with tool selection attributes."""
        from unittest.mock import MagicMock, patch

        from ares.core.tracing import trace_decision

        mock_span = MagicMock()
        mock_span.__enter__ = MagicMock(return_value=mock_span)
        mock_span.__exit__ = MagicMock(return_value=False)

        with patch("dreadnode.span", return_value=mock_span) as mock_dn_span:
            trace_decision(
                role="credential_access",
                team="red",
                tools_considered=["secretsdump", "kerberoast", "asrep_roast"],
                tool_chosen="secretsdump",
                reasoning_summary="I will use secretsdump to get credentials",
                confidence=0.9,
                operation_id="op-test-123",
            )

        mock_dn_span.assert_called_once()
        call_kwargs = mock_dn_span.call_args[1]
        attrs = call_kwargs["attributes"]

        assert "decision.credential_access" in mock_dn_span.call_args[0][0]
        assert attrs["decision.type"] == "tool_selection"
        assert attrs["decision.tool_chosen"] == "secretsdump"
        assert attrs["decision.tools_considered"] == ["secretsdump", "kerberoast", "asrep_roast"]
        assert attrs["decision.confidence"] == 0.9
        assert attrs["attack_operation_id"] == "op-test-123"

    def test_trace_decision_adds_mitre_technique(self):
        """trace_decision should add MITRE technique for known tools."""
        from unittest.mock import MagicMock, patch

        from ares.core.tracing import trace_decision

        mock_span = MagicMock()
        mock_span.__enter__ = MagicMock(return_value=mock_span)
        mock_span.__exit__ = MagicMock(return_value=False)

        with patch("dreadnode.span", return_value=mock_span) as mock_dn_span:
            trace_decision(
                role="credential_access",
                team="red",
                tools_considered=["secretsdump"],
                tool_chosen="secretsdump",
                reasoning_summary="Running DCSync",
            )

        call_kwargs = mock_dn_span.call_args[1]
        attrs = call_kwargs["attributes"]

        # secretsdump maps to T1003.006 (DCSync)
        assert attrs["mitre.technique.id"] == "T1003.006"

    def test_trace_decision_truncates_tools_considered(self):
        """trace_decision should limit tools_considered to 5 entries."""
        from unittest.mock import MagicMock, patch

        from ares.core.tracing import trace_decision

        mock_span = MagicMock()
        mock_span.__enter__ = MagicMock(return_value=mock_span)
        mock_span.__exit__ = MagicMock(return_value=False)

        many_tools = [f"tool_{i}" for i in range(10)]

        with patch("dreadnode.span", return_value=mock_span) as mock_dn_span:
            trace_decision(
                role="recon",
                team="red",
                tools_considered=many_tools,
                tool_chosen="tool_0",
                reasoning_summary="Testing",
            )

        call_kwargs = mock_dn_span.call_args[1]
        attrs = call_kwargs["attributes"]

        assert len(attrs["decision.tools_considered"]) == 5

    def test_trace_decision_handles_exception(self):
        """trace_decision should not raise if span creation fails."""
        from unittest.mock import patch

        from ares.core.tracing import trace_decision

        with patch("dreadnode.span", side_effect=Exception("Tracing unavailable")):
            # Should not raise - just logs debug
            trace_decision(
                role="recon",
                team="red",
                tools_considered=["nmap_scan"],
                tool_chosen="nmap_scan",
                reasoning_summary="Test",
            )

    def test_trace_decision_includes_tool_category(self):
        """trace_decision should include attack_tool_category for known tools."""
        from unittest.mock import MagicMock, patch

        from ares.core.tracing import trace_decision

        mock_span = MagicMock()
        mock_span.__enter__ = MagicMock(return_value=mock_span)
        mock_span.__exit__ = MagicMock(return_value=False)

        with patch("dreadnode.span", return_value=mock_span) as mock_dn_span:
            trace_decision(
                role="lateral",
                team="red",
                tools_considered=["psexec"],
                tool_chosen="psexec",
                reasoning_summary="Use psexec for lateral movement",
            )

        call_kwargs = mock_dn_span.call_args[1]
        attrs = call_kwargs["attributes"]

        # psexec maps to LateralMovementTools category
        assert attrs["attack_tool_category"] == "LateralMovementTools"


class TestSpanBasedTracing:
    """Tests that trace functions always create child spans (not events).

    Span attributes must be queryable via TraceQL and extractable by Tempo's
    span metrics generator, which doesn't support event attributes.
    """

    def test_trace_tool_call_creates_span(self):
        """trace_tool_call should always create a child span."""
        from unittest.mock import MagicMock, patch

        from ares.core.tracing import trace_tool_call

        mock_span = MagicMock()
        mock_span.__enter__ = MagicMock(return_value=mock_span)
        mock_span.__exit__ = MagicMock(return_value=False)

        with patch("dreadnode.span", return_value=mock_span) as mock_dn_span:
            trace_tool_call("recon", "red", "nmap_scan", is_error=False)

        mock_dn_span.assert_called_once()
        assert "tool.nmap_scan" in mock_dn_span.call_args[0][0]
        span_attrs = mock_dn_span.call_args[1]["attributes"]
        assert span_attrs["tool.status"] == "success"

    def test_trace_discovery_creates_span(self):
        """trace_discovery should always create a child span."""
        from unittest.mock import MagicMock, patch

        from ares.core.tracing import trace_discovery

        mock_span = MagicMock()
        mock_span.__enter__ = MagicMock(return_value=mock_span)
        mock_span.__exit__ = MagicMock(return_value=False)

        with patch("dreadnode.span", return_value=mock_span) as mock_dn_span:
            trace_discovery(
                discovery_type="credential",
                source_agent="credential_access",
                target_user="admin",
                target_domain="contoso.local",
            )

        mock_dn_span.assert_called_once()
        assert "discovery.credential" in mock_dn_span.call_args[0][0]
        span_attrs = mock_dn_span.call_args[1]["attributes"]
        assert span_attrs["user.name"] == "admin"
        assert span_attrs["attack_target_domain"] == "contoso.local"

    def test_trace_decision_creates_span(self):
        """trace_decision should always create a child span."""
        from unittest.mock import MagicMock, patch

        from ares.core.tracing import trace_decision

        mock_span = MagicMock()
        mock_span.__enter__ = MagicMock(return_value=mock_span)
        mock_span.__exit__ = MagicMock(return_value=False)

        with patch("dreadnode.span", return_value=mock_span) as mock_dn_span:
            trace_decision(
                role="credential_access",
                team="red",
                tools_considered=["secretsdump", "kerberoast"],
                tool_chosen="secretsdump",
                reasoning_summary="Using secretsdump for DCSync",
            )

        mock_dn_span.assert_called_once()
        assert "decision.credential_access" in mock_dn_span.call_args[0][0]
        span_attrs = mock_dn_span.call_args[1]["attributes"]
        assert span_attrs["decision.tool_chosen"] == "secretsdump"

    def test_trace_tool_call_includes_error_attributes(self):
        """trace_tool_call span should include error attributes when is_error=True."""
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
                is_error=True,
                error_message="Access denied",
            )

        span_attrs = mock_dn_span.call_args[1]["attributes"]
        assert span_attrs["tool.status"] == "error"
        assert span_attrs["error.message"] == "Access denied"

    def test_trace_tool_call_includes_operation_id(self):
        """trace_tool_call span should include operation_id when provided."""
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
                operation_id="op-test-123",
            )

        span_attrs = mock_dn_span.call_args[1]["attributes"]
        assert span_attrs["attack_operation_id"] == "op-test-123"
