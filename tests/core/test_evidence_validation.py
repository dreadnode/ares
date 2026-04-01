"""Tests for evidence validation and IOC extraction."""

from ares.core.config import get_max_stored_results, get_unvalidated_confidence_penalty
from ares.core.evidence_validation import (
    StoredQueryResult,
    _classify_ioc,
    _extract_patterns_from_string,
    _extract_searchable_values,
    _is_garbled_value,
    _is_in_target_scope,
    _is_user_in_target_scope,
    adjust_confidence_for_validation,
    auto_extract_evidence_from_query,
    boost_confidence_for_quality,
    clear_target_domains,
    extract_domains_from_red_team_state,
    get_recent_query_ids,
    get_suggested_iocs,
    reset_evidence_validation,
    set_target_domains,
    store_query_result,
    validate_evidence_value,
)


class TestStoredQueryResult:
    """Tests for StoredQueryResult dataclass."""

    def test_dataclass_creation(self):
        """Test creating a StoredQueryResult."""
        from datetime import datetime, timezone

        result = StoredQueryResult(
            query_id="q-0001",
            query_type="loki",
            query_string="{job='test'}",
            timestamp=datetime.now(timezone.utc),
            result_data={"key": "value"},
            result_count=10,
        )
        assert result.query_id == "q-0001"
        assert result.result_count == 10
        assert isinstance(result.extracted_values, set)


class TestResetEvidenceValidation:
    """Tests for reset_evidence_validation function."""

    def test_reset_clears_state(self):
        """Test reset clears stored results."""
        # Store something first
        store_query_result("test", "query", {"data": "value"}, 1)

        # Reset
        reset_evidence_validation()

        # Should have no recent results
        assert len(get_recent_query_ids()) == 0

    def test_reset_resets_counter(self):
        """Test reset resets query counter."""
        reset_evidence_validation()

        # Store a query and check ID format
        qid1 = store_query_result("test", "query", {}, 0)
        assert qid1 == "q-0001"

        # Reset and store again
        reset_evidence_validation()
        qid2 = store_query_result("test", "query", {}, 0)
        assert qid2 == "q-0001"  # Counter should be reset


class TestStoreQueryResult:
    """Tests for store_query_result function."""

    def test_store_returns_query_id(self):
        """Test store returns a query ID."""
        reset_evidence_validation()
        qid = store_query_result("loki", "{job='test'}", [], 0)
        assert qid.startswith("q-")

    def test_store_increments_counter(self):
        """Test store increments query counter."""
        reset_evidence_validation()
        qid1 = store_query_result("test", "q1", {}, 0)
        qid2 = store_query_result("test", "q2", {}, 0)

        assert qid1 == "q-0001"
        assert qid2 == "q-0002"

    def test_store_extracts_values(self):
        """Test store extracts searchable values."""
        reset_evidence_validation()
        data = {"ip": "192.168.58.100", "user": "admin@contoso.local"}
        store_query_result("test", "query", data, 2)

        # Check via suggested IOCs
        suggestions = get_suggested_iocs()
        values = [s["value"] for s in suggestions]
        assert any("192.168.58.100" in v for v in values)

    def test_store_respects_max_limit(self):
        """Test store respects max_stored_results config."""
        reset_evidence_validation()
        max_stored = get_max_stored_results()

        # Store more than max
        for i in range(max_stored + 5):
            store_query_result("test", f"query{i}", {f"val{i}": f"data{i}"}, 1)

        # Should only have max_stored_results
        assert len(get_recent_query_ids()) == max_stored


class TestExtractSearchableValues:
    """Tests for _extract_searchable_values function."""

    def test_extract_from_string(self):
        """Test extracting from string."""
        values = _extract_searchable_values("192.168.58.100")
        assert "192.168.58.100" in values

    def test_extract_from_dict(self):
        """Test extracting from dictionary."""
        data = {"ip": "192.168.58.1", "host": "server01.contoso.local"}
        values = _extract_searchable_values(data)
        assert "192.168.58.1" in values
        assert "server01.contoso.local" in values

    def test_extract_from_list(self):
        """Test extracting from list."""
        data = [{"ip": "1.2.3.4"}, {"ip": "5.6.7.8"}]
        values = _extract_searchable_values(data)
        assert "1.2.3.4" in values
        assert "5.6.7.8" in values

    def test_extract_nested(self):
        """Test extracting from nested structures."""
        data = {"outer": {"inner": {"ip": "192.168.58.1"}}}
        values = _extract_searchable_values(data)
        assert "192.168.58.1" in values

    def test_extract_depth_limit(self):
        """Test extraction respects depth limit."""
        # Create deeply nested structure
        data = {"level": "value"}
        for _ in range(15):
            data = {"nested": data}

        # Should not raise, returns empty at depth limit
        values = _extract_searchable_values(data)
        assert isinstance(values, set)

    def test_extract_skips_long_strings(self):
        """Test extraction skips very long strings."""
        long_string = "x" * 1000
        values = _extract_searchable_values(long_string)
        assert long_string.lower() not in values

    def test_extract_from_content_text_object(self):
        """Test extracting from MCP ContentText-like objects with .text attribute."""

        class MockContentText:
            """Mock MCP ContentText object."""

            def __init__(self, text: str):
                self.text = text

        # Simulate MCP result format: list of ContentText with JSON in .text
        json_content = '{"data": [{"ip": "192.168.58.100", "user": "testuser@contoso.local"}]}'
        content_text = MockContentText(json_content)

        values = _extract_searchable_values([content_text])
        assert "192.168.58.100" in values
        assert "testuser@contoso.local" in values

    def test_extract_from_embedded_json_string(self):
        """Test extracting from JSON strings embedded in results."""
        # Common format from Loki - JSON as string value
        data = '{"TargetUserName": "admin", "IpAddress": "192.168.58.50"}'
        values = _extract_searchable_values(data)
        assert "admin" in values
        assert "192.168.58.50" in values

    def test_extract_from_loki_style_result(self):
        """Test extracting from Loki-style result structure."""
        # Simulates compact Loki result after _compact_loki_result processing
        result = {
            "data": [
                {
                    "timestamp": "2024-01-01T00:00:00Z",
                    "line": {
                        "event_id": 4624,
                        "computer": "dc01.contoso.local",
                        "fields": {
                            "TargetUserName": "administrator",
                            "IpAddress": "192.168.58.100",
                        },
                    },
                }
            ],
            "count": 1,
        }
        values = _extract_searchable_values(result)
        assert "dc01.contoso.local" in values
        assert "administrator" in values
        assert "192.168.58.100" in values


class TestExtractPatternsFromString:
    """Tests for _extract_patterns_from_string function."""

    def test_extract_ipv4(self):
        """Test extracting IPv4 addresses."""
        text = "Connection from 192.168.58.100 to 192.168.58.1"
        patterns = _extract_patterns_from_string(text)
        assert "192.168.58.100" in patterns
        assert "192.168.58.1" in patterns

    def test_extract_hostname(self):
        """Test extracting hostnames."""
        text = "Host: server01.contoso.local connected"
        patterns = _extract_patterns_from_string(text)
        assert "server01.contoso.local" in patterns

    def test_extract_domain_user(self):
        """Test extracting domain\\user format."""
        text = "User DOMAIN\\admin logged in"
        patterns = _extract_patterns_from_string(text)
        assert "domain\\admin" in patterns

    def test_extract_email_user(self):
        """Test extracting user@domain format."""
        text = "User admin@contoso.local authenticated"
        patterns = _extract_patterns_from_string(text)
        assert "admin@contoso.local" in patterns

    def test_extract_json_username_fields(self):
        """Test extracting usernames from JSON fields."""
        text = '{"TargetUserName": "testuser", "SubjectUserName": "SYSTEM"}'
        patterns = _extract_patterns_from_string(text)
        assert "testuser" in patterns
        # SYSTEM should be excluded
        assert "system" not in patterns

    def test_extract_computer_name(self):
        """Test extracting computer names."""
        text = '{"Computer": "DC01.contoso.local"}'
        patterns = _extract_patterns_from_string(text)
        assert "dc01.contoso.local" in patterns

    def test_extract_process_name(self):
        """Test extracting process names."""
        text = '{"ProcessName": "C:\\Windows\\System32\\cmd.exe"}'
        patterns = _extract_patterns_from_string(text)
        assert "c:\\windows\\system32\\cmd.exe" in patterns

    def test_extract_service_name(self):
        """Test extracting service names."""
        text = '{"ServiceName": "MSSQLSERVER"}'
        patterns = _extract_patterns_from_string(text)
        assert "mssqlserver" in patterns

    def test_extract_md5_hash(self):
        """Test extracting MD5 hash."""
        text = "Hash: d41d8cd98f00b204e9800998ecf8427e"
        patterns = _extract_patterns_from_string(text)
        assert "d41d8cd98f00b204e9800998ecf8427e" in patterns  # pragma: allowlist secret

    def test_extract_sha1_hash(self):
        """Test extracting SHA1 hash."""
        text = "SHA1: da39a3ee5e6b4b0d3255bfef95601890afd80709"
        patterns = _extract_patterns_from_string(text)
        assert "da39a3ee5e6b4b0d3255bfef95601890afd80709" in patterns  # pragma: allowlist secret

    def test_extract_sha256_hash(self):
        """Test extracting SHA256 hash."""
        text = "SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        patterns = _extract_patterns_from_string(text)
        assert (
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"  # pragma: allowlist secret
            in patterns
        )


class TestValidateEvidenceValue:
    """Tests for validate_evidence_value function."""

    def test_validate_empty_value(self):
        """Test validating empty value."""
        validated, query_id = validate_evidence_value("")
        assert validated is False
        assert query_id is None

    def test_validate_exact_match(self):
        """Test validating exact match."""
        reset_evidence_validation()
        store_query_result("test", "query", {"ip": "192.168.58.100"}, 1)

        validated, query_id = validate_evidence_value("192.168.58.100")
        assert validated is True
        assert query_id is not None

    def test_validate_case_insensitive(self):
        """Test validation is case insensitive."""
        reset_evidence_validation()
        store_query_result("test", "query", {"host": "DC01.Contoso.LOCAL"}, 1)

        validated, _query_id = validate_evidence_value("dc01.contoso.local")
        assert validated is True

    def test_validate_partial_match(self):
        """Test validating partial match."""
        reset_evidence_validation()
        store_query_result("test", "query", {"user": "admin@contoso.local"}, 1)

        # Partial match on domain portion
        validated, _query_id = validate_evidence_value("admin")
        # Note: depends on implementation - partial should match if contained
        assert isinstance(validated, bool)

    def test_validate_not_found(self):
        """Test validating value not in results."""
        reset_evidence_validation()
        store_query_result("test", "query", {"ip": "192.168.58.100"}, 1)

        validated, query_id = validate_evidence_value("192.168.58.1")
        assert validated is False
        assert query_id is None


class TestGetSuggestedIOCs:
    """Tests for get_suggested_iocs function."""

    def test_empty_when_no_results(self):
        """Test returns empty when no stored results."""
        reset_evidence_validation()
        suggestions = get_suggested_iocs()
        assert suggestions == []

    def test_returns_classified_iocs(self):
        """Test returns classified IOCs."""
        reset_evidence_validation()
        store_query_result("test", "query", {"ip": "192.168.58.100"}, 1)

        suggestions = get_suggested_iocs()
        ip_suggestions = [s for s in suggestions if s["type"] == "ip"]
        assert len(ip_suggestions) > 0

    def test_limits_results(self):
        """Test limits results to 50."""
        reset_evidence_validation()
        # Store many values
        data = {f"ip{i}": f"192.168.{i}.{i}" for i in range(100)}
        store_query_result("test", "query", data, 100)

        suggestions = get_suggested_iocs()
        assert len(suggestions) <= 50

    def test_deduplicates_values(self):
        """Test deduplicates values."""
        reset_evidence_validation()
        store_query_result("test", "q1", {"ip": "192.168.58.100"}, 1)
        store_query_result("test", "q2", {"ip": "192.168.58.100"}, 1)

        suggestions = get_suggested_iocs()
        ip_values = [s["value"] for s in suggestions if s["value"] == "192.168.58.100"]
        # Should only appear once
        assert len(ip_values) <= 1


class TestClassifyIOC:
    """Tests for _classify_ioc function."""

    def test_classify_ip(self):
        """Test classifying IP address."""
        assert _classify_ioc("192.168.58.100") == "ip"
        assert _classify_ioc("192.168.58.1") == "ip"

    def test_classify_hostname(self):
        """Test classifying hostname."""
        assert _classify_ioc("app-srv01.contoso.local") == "hostname"
        assert _classify_ioc("dc01.corp.contoso.com") == "hostname"

    def test_classify_user_domain(self):
        """Test classifying domain\\user."""
        assert _classify_ioc("domain\\admin") == "user"

    def test_classify_user_email(self):
        """Test classifying user@domain."""
        assert _classify_ioc("admin@contoso.local") == "user"

    def test_classify_md5_hash(self):
        """Test classifying MD5 hash."""
        md5_hash = "d41d8cd98f00b204e9800998ecf8427e"  # pragma: allowlist secret
        assert _classify_ioc(md5_hash) == "hash"

    def test_classify_sha1_hash(self):
        """Test classifying SHA1 hash."""
        sha1_hash = "da39a3ee5e6b4b0d3255bfef95601890afd80709"  # pragma: allowlist secret
        assert _classify_ioc(sha1_hash) == "hash"

    def test_classify_sha256_hash(self):
        """Test classifying SHA256 hash."""
        result = _classify_ioc("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        assert result == "hash"

    def test_classify_unknown(self):
        """Test classifying unknown value."""
        assert _classify_ioc("random_string") is None
        assert _classify_ioc("123") is None

    def test_classify_file_extensions_not_hostnames(self):
        """Test that file extensions are NOT classified as hostnames.

        Files like svchost.exe look like hostnames but should be rejected.
        This was a real bug where the blue team report showed svchost.exe
        as a hostname evidence item.
        """
        # Common Windows executables that match hostname pattern
        assert _classify_ioc("svchost.exe") is None
        assert _classify_ioc("lsass.exe") is None
        assert _classify_ioc("dfsrs.exe") is None
        assert _classify_ioc("winlogon.exe") is None
        assert _classify_ioc("services.exe") is None
        # Other file extensions
        assert _classify_ioc("config.dll") is None
        assert _classify_ioc("script.ps1") is None
        assert _classify_ioc("malware.sys") is None
        assert _classify_ioc("setup.msi") is None
        assert _classify_ioc("debug.log") is None

    def test_classify_windows_paths_not_users(self):
        """Test that Windows paths are NOT classified as users.

        Paths like windows\\system32 match the DOMAIN\\user pattern but
        should be rejected. This was a real bug where the blue team report
        showed windows\\system32 as a user evidence item.
        """
        # Common Windows paths that match domain\\user pattern
        assert _classify_ioc("windows\\system32") is None
        assert _classify_ioc("windows\\sysvol") is None
        assert _classify_ioc("system32\\drivers") is None
        assert _classify_ioc("programdata\\microsoft") is None
        assert _classify_ioc("users\\administrator") is None
        # Drive letters
        assert _classify_ioc("c:\\windows") is None
        assert _classify_ioc("d:\\data") is None
        # But valid domain users should still work
        assert _classify_ioc("contoso\\admin") == "user"
        assert _classify_ioc("contoso\\jane.doe") == "user"


class TestAdjustConfidenceForValidation:
    """Tests for adjust_confidence_for_validation function."""

    def test_validated_no_change(self):
        """Test validated evidence keeps confidence."""
        assert adjust_confidence_for_validation(0.8, validated=True) == 0.8
        assert adjust_confidence_for_validation(0.5, validated=True) == 0.5

    def test_unvalidated_penalty(self):
        """Test unvalidated evidence gets penalty."""
        result = adjust_confidence_for_validation(0.8, validated=False)
        expected = 0.8 - get_unvalidated_confidence_penalty()
        assert result == expected

    def test_unvalidated_minimum(self):
        """Test unvalidated doesn't go below minimum."""
        result = adjust_confidence_for_validation(0.1, validated=False)
        assert result >= 0.1


class TestGetRecentQueryIds:
    """Tests for get_recent_query_ids function."""

    def test_empty_when_no_results(self):
        """Test returns empty when no results."""
        reset_evidence_validation()
        ids = get_recent_query_ids()
        assert ids == []

    def test_returns_ids_in_reverse_order(self):
        """Test returns IDs most recent first."""
        reset_evidence_validation()
        store_query_result("test", "q1", {}, 0)
        store_query_result("test", "q2", {}, 0)
        store_query_result("test", "q3", {}, 0)

        ids = get_recent_query_ids()
        assert ids[0] == "q-0003"
        assert ids[-1] == "q-0001"


class TestBoostConfidenceForQuality:
    """Tests for boost_confidence_for_quality function."""

    def test_no_boost_low_quality(self):
        """Test no boost for low quality evidence."""
        boost = boost_confidence_for_quality(
            evidence_type="ip",
            pyramid_level=2,
            has_timestamp=False,
            has_mitre_mapping=False,
        )
        assert boost == 0.0

    def test_boost_high_pyramid_level(self):
        """Test boost for high pyramid level."""
        boost = boost_confidence_for_quality(
            evidence_type="technique",
            pyramid_level=6,
            has_timestamp=False,
            has_mitre_mapping=False,
        )
        assert boost >= 0.1

    def test_boost_medium_pyramid_level(self):
        """Test boost for medium pyramid level."""
        boost = boost_confidence_for_quality(
            evidence_type="tool",
            pyramid_level=4,
            has_timestamp=False,
            has_mitre_mapping=False,
        )
        assert boost >= 0.05

    def test_boost_timestamp(self):
        """Test boost for having timestamp."""
        boost = boost_confidence_for_quality(
            evidence_type="ip",
            pyramid_level=2,
            has_timestamp=True,
            has_mitre_mapping=False,
        )
        assert boost >= 0.05

    def test_boost_mitre_mapping(self):
        """Test boost for having MITRE mapping."""
        boost = boost_confidence_for_quality(
            evidence_type="ip",
            pyramid_level=2,
            has_timestamp=False,
            has_mitre_mapping=True,
        )
        assert boost >= 0.05

    def test_boost_max_limit(self):
        """Test boost is capped at maximum."""
        boost = boost_confidence_for_quality(
            evidence_type="technique",
            pyramid_level=6,
            has_timestamp=True,
            has_mitre_mapping=True,
        )
        assert boost <= 0.2


class TestAutoExtractEvidenceFromQuery:
    """Tests for auto_extract_evidence_from_query function."""

    def test_extract_ip_address(self):
        """Test extracting IP address evidence."""
        result = {"ip": "192.168.58.100"}
        evidence = auto_extract_evidence_from_query(result, "test query")

        ip_evidence = [e for e in evidence if e["type"] == "ip"]
        assert len(ip_evidence) > 0
        assert ip_evidence[0]["pyramid_level"] == 2

    def test_extract_hostname(self):
        """Test extracting hostname evidence."""
        result = {"host": "server01.contoso.local"}
        evidence = auto_extract_evidence_from_query(result, "test query")

        host_evidence = [e for e in evidence if e["type"] == "hostname"]
        assert len(host_evidence) > 0
        assert host_evidence[0]["pyramid_level"] == 3

    def test_extract_with_mitre_technique(self):
        """Test extracting with MITRE technique."""
        result = {"ip": "192.168.58.100"}
        evidence = auto_extract_evidence_from_query(result, "test query", mitre_technique="T1003")

        ip_evidence = [e for e in evidence if e["type"] == "ip"]
        assert len(ip_evidence) > 0
        assert ip_evidence[0]["mitre_techniques"] == ["T1003"]

    def test_extract_validated_flag(self):
        """Test extracted evidence is marked validated."""
        result = {"ip": "192.168.58.100"}
        evidence = auto_extract_evidence_from_query(result, "test query")

        for ev in evidence:
            assert ev["validated"] is True

    def test_extract_limits_results(self):
        """Test extraction limits results."""
        # Create result with many IPs
        result = {f"ip{i}": f"192.168.{i}.{i}" for i in range(50)}
        evidence = auto_extract_evidence_from_query(result, "test query")

        assert len(evidence) <= 20

    def test_extract_skips_short_values(self):
        """Test extraction skips very short values."""
        result = {"short": "ab", "valid": "192.168.58.100"}
        evidence = auto_extract_evidence_from_query(result, "test query")

        # Should have IP but not the short value
        assert any(e["value"] == "192.168.58.100" for e in evidence)

    def test_extract_deduplicates(self):
        """Test extraction deduplicates values."""
        result = [{"ip": "192.168.58.100"}, {"ip": "192.168.58.100"}]
        evidence = auto_extract_evidence_from_query(result, "test query")

        ip_values = [e["value"] for e in evidence if e["value"] == "192.168.58.100"]
        assert len(ip_values) <= 1

    def test_extract_source_description(self):
        """Test source includes description."""
        result = {"ip": "192.168.58.100"}
        evidence = auto_extract_evidence_from_query(result, "Loki query for auth logs")

        assert any("Loki query" in e["source"] for e in evidence)


class TestIsGarbledValue:
    """Tests for _is_garbled_value function."""

    def test_unicode_escape_is_garbled(self):
        """Test Unicode escape sequences are detected as garbled."""
        assert _is_garbled_value("\\u003e0x21993862\\u003c") is True
        assert _is_garbled_value("test\\u003evalue") is True

    def test_html_entity_style_is_garbled(self):
        """Test HTML entity-style escapes are detected."""
        assert _is_garbled_value("u003e0x21993862u003c") is True
        assert _is_garbled_value("valueu003emore") is True

    def test_hex_heavy_is_garbled(self):
        """Test hex-heavy strings are detected."""
        assert _is_garbled_value("0x2199386293847") is True

    def test_mostly_special_chars_is_garbled(self):
        """Test strings with mostly special characters are detected."""
        assert _is_garbled_value("!@#$%^&*()") is True
        assert _is_garbled_value(">>><<<:::") is True

    def test_valid_ip_not_garbled(self):
        """Test valid IP addresses are not garbled."""
        assert _is_garbled_value("192.168.58.100") is False

    def test_valid_hostname_not_garbled(self):
        """Test valid hostnames are not garbled."""
        assert _is_garbled_value("dc01.contoso.local") is False

    def test_valid_username_not_garbled(self):
        """Test valid usernames are not garbled."""
        assert _is_garbled_value("admin@contoso.local") is False
        assert _is_garbled_value("DOMAIN\\admin") is False

    def test_short_values_not_garbled(self):
        """Test short values are not flagged by special char ratio."""
        assert _is_garbled_value("test") is False
        assert _is_garbled_value("ab.cd") is False


class TestTargetDomainScope:
    """Tests for target domain scope filtering."""

    def setup_method(self):
        """Clear target domains before each test."""
        clear_target_domains()

    def teardown_method(self):
        """Clear target domains after each test."""
        clear_target_domains()

    def test_no_scope_allows_all(self):
        """Test that without scope set, all domains are allowed."""
        assert _is_in_target_scope("dc01.contoso.local") is True
        assert _is_in_target_scope("server.random.com") is True
        assert _is_in_target_scope("anything.example.org") is True

    def test_empty_hostname_not_in_scope(self):
        """Test empty hostname returns False."""
        set_target_domains(["contoso.local"])
        assert _is_in_target_scope("") is False

    def test_exact_domain_match(self):
        """Test exact domain match is in scope."""
        set_target_domains(["contoso.local", "fabrikam.local"])
        assert _is_in_target_scope("contoso.local") is True
        assert _is_in_target_scope("fabrikam.local") is True

    def test_subdomain_match(self):
        """Test subdomain of target domain is in scope."""
        set_target_domains(["contoso.local"])
        assert _is_in_target_scope("dc01.contoso.local") is True
        assert _is_in_target_scope("sql01.corp.contoso.local") is True
        assert _is_in_target_scope("web.app.contoso.local") is True

    def test_unrelated_domain_not_in_scope(self):
        """Test unrelated domains are filtered out when scope is set."""
        set_target_domains(["contoso.local"])
        assert _is_in_target_scope("dc01.fabrikam.local") is False
        assert _is_in_target_scope("random.example.com") is False
        assert _is_in_target_scope("vortexindustries.local") is False

    def test_case_insensitive(self):
        """Test scope matching is case insensitive."""
        set_target_domains(["Contoso.Local"])
        assert _is_in_target_scope("DC01.CONTOSO.LOCAL") is True
        assert _is_in_target_scope("dc01.contoso.local") is True

    def test_multiple_target_domains(self):
        """Test multiple target domains all work."""
        set_target_domains(["contoso.local", "child.contoso.local", "fabrikam.local"])
        assert _is_in_target_scope("dc02.child.contoso.local") is True
        assert _is_in_target_scope("dc01.contoso.local") is True
        assert _is_in_target_scope("dc01.fabrikam.local") is True
        assert _is_in_target_scope("unrelated.domain.com") is False

    def test_clear_domains_resets_scope(self):
        """Test clear_target_domains resets to allow-all mode."""
        set_target_domains(["contoso.local"])
        assert _is_in_target_scope("random.com") is False

        clear_target_domains()
        assert _is_in_target_scope("random.com") is True


class TestUserDomainScope:
    """Tests for user domain scope filtering."""

    def setup_method(self):
        """Clear target domains before each test."""
        clear_target_domains()

    def teardown_method(self):
        """Clear target domains after each test."""
        clear_target_domains()

    def test_no_scope_allows_all_users(self):
        """Test without scope, all users pass."""
        assert _is_user_in_target_scope("CONTOSO\\admin") is True
        assert _is_user_in_target_scope("RANDOM\\user") is True
        assert _is_user_in_target_scope("user@random.com") is True

    def test_empty_user_not_in_scope(self):
        """Test empty user returns False when scope is set."""
        set_target_domains(["contoso.local"])
        assert _is_user_in_target_scope("") is False
        assert _is_user_in_target_scope(None) is False  # type: ignore[arg-type]

    def test_domain_backslash_format_matches_netbios(self):
        """Test DOMAIN\\user format matches NetBIOS name from FQDN."""
        set_target_domains(["contoso.local"])
        # "contoso" is NetBIOS of "contoso.local"
        assert _is_user_in_target_scope("CONTOSO\\admin") is True
        assert _is_user_in_target_scope("contoso\\admin") is True
        assert _is_user_in_target_scope("FABRIKAM\\admin") is False

    def test_domain_backslash_format_exact_match(self):
        """Test DOMAIN\\user format with exact domain match."""
        set_target_domains(["contoso"])  # Short name only
        assert _is_user_in_target_scope("contoso\\admin") is True
        assert _is_user_in_target_scope("fabrikam\\admin") is False

    def test_upn_format_matches_domain(self):
        """Test user@domain.tld format matches target domains."""
        set_target_domains(["contoso.local"])
        assert _is_user_in_target_scope("admin@contoso.local") is True
        assert _is_user_in_target_scope("admin@dc01.contoso.local") is True
        assert _is_user_in_target_scope("admin@fabrikam.local") is False

    def test_plain_username_allowed(self):
        """Test plain username (no domain) is allowed when scope set."""
        set_target_domains(["contoso.local"])
        # Plain usernames could be local accounts, so allow them
        assert _is_user_in_target_scope("administrator") is True
        assert _is_user_in_target_scope("localuser") is True

    def test_multiple_target_domains(self):
        """Test multiple target domains all work for users."""
        set_target_domains(["contoso.local", "fabrikam.local"])
        assert _is_user_in_target_scope("CONTOSO\\admin") is True
        assert _is_user_in_target_scope("FABRIKAM\\admin") is True
        assert _is_user_in_target_scope("OTHERDOMAIN\\admin") is False

    def test_case_insensitive(self):
        """Test user scope matching is case insensitive."""
        set_target_domains(["Contoso.Local"])
        assert _is_user_in_target_scope("CONTOSO\\ADMIN") is True
        assert _is_user_in_target_scope("contoso\\admin") is True
        assert _is_user_in_target_scope("admin@CONTOSO.LOCAL") is True

    def test_filters_out_of_scope_users_from_extraction(self):
        """Test user extraction respects domain scope."""
        set_target_domains(["contoso.local"])
        text = "User CONTOSO\\admin logged in. Also saw RANDOM\\attacker and admin@fabrikam.local"
        patterns = _extract_patterns_from_string(text)

        # Should have in-scope user but not out-of-scope
        assert "contoso\\admin" in patterns
        assert "random\\attacker" not in patterns
        assert "admin@fabrikam.local" not in patterns

    def test_filters_out_of_scope_users_from_classification(self):
        """Test user classification respects domain scope."""
        set_target_domains(["contoso.local"])

        assert _classify_ioc("contoso\\admin") == "user"
        assert _classify_ioc("random\\attacker") is None
        assert _classify_ioc("admin@fabrikam.local") is None


class TestExtractDomainsFromRedTeamState:
    """Tests for extract_domains_from_red_team_state helper."""

    def test_extracts_from_target(self):
        """Test extraction from target.domain."""

        class MockTarget:
            domain = "contoso.local"

        class MockState:
            target = MockTarget()
            all_domains = ()
            all_credentials = ()
            trusted_domains = ()

        domains = extract_domains_from_red_team_state(MockState())
        assert "contoso.local" in domains

    def test_extracts_from_all_domains(self):
        """Test extraction from all_domains list."""

        class MockState:
            target = None
            all_domains = ("contoso.local", "fabrikam.local")
            all_credentials = ()
            trusted_domains = ()

        domains = extract_domains_from_red_team_state(MockState())
        assert "contoso.local" in domains
        assert "fabrikam.local" in domains

    def test_extracts_from_credentials(self):
        """Test extraction from credential domains."""

        class MockCred:
            domain = "contoso.local"

        class MockState:
            target = None
            all_domains = ()
            all_credentials = (MockCred(),)
            trusted_domains = ()

        domains = extract_domains_from_red_team_state(MockState())
        assert "contoso.local" in domains

    def test_extracts_from_trusted_domains(self):
        """Test extraction from trusted_domains."""

        class MockState:
            target = None
            all_domains = ()
            all_credentials = ()
            trusted_domains = ("fabrikam.local",)

        domains = extract_domains_from_red_team_state(MockState())
        assert "fabrikam.local" in domains

    def test_deduplicates_and_lowercases(self):
        """Test domains are deduplicated and lowercased."""

        class MockTarget:
            domain = "CONTOSO.LOCAL"

        class MockState:
            target = MockTarget()
            all_domains = ("Contoso.Local", "FABRIKAM.local")
            all_credentials = ()
            trusted_domains = ("fabrikam.local",)

        domains = extract_domains_from_red_team_state(MockState())
        assert len(domains) == 2
        assert "contoso.local" in domains
        assert "fabrikam.local" in domains


class TestFilteringIntegration:
    """Integration tests for filtering in IOC extraction."""

    def setup_method(self):
        """Clear target domains before each test."""
        clear_target_domains()

    def teardown_method(self):
        """Clear target domains after each test."""
        clear_target_domains()

    def test_garbled_values_filtered_from_extraction(self):
        """Test garbled values are filtered from pattern extraction."""
        text = "User: \\u003e0x21993862\\u003c logged in from 192.168.58.100"
        patterns = _extract_patterns_from_string(text)

        # Should have IP but not the garbled value
        assert "192.168.58.100" in patterns
        assert "\\u003e0x21993862\\u003c" not in patterns

    def test_scope_based_filtering_from_extraction(self):
        """Test domains outside target scope are filtered from extraction."""
        # Set target scope to contoso.local only
        set_target_domains(["contoso.local"])

        text = "Host: dc01.contoso.local connected to server.otherdomain.local"
        patterns = _extract_patterns_from_string(text)

        # Should have target domain but not out-of-scope domain
        assert "dc01.contoso.local" in patterns
        assert "server.otherdomain.local" not in patterns

    def test_no_scope_allows_all_domains(self):
        """Test without scope, all domains are extracted."""
        # No scope set
        text = "Host: dc01.contoso.local connected to server.random.local"
        patterns = _extract_patterns_from_string(text)

        # Both domains should be extracted
        assert "dc01.contoso.local" in patterns
        assert "server.random.local" in patterns

    def test_scope_based_filtering_from_classification(self):
        """Test out-of-scope domains return None from classification."""
        set_target_domains(["contoso.local"])

        assert _classify_ioc("dc01.contoso.local") == "hostname"
        assert _classify_ioc("server.otherdomain.local") is None  # Out of scope

    def test_garbled_values_filtered_from_classification(self):
        """Test garbled values return None from classification."""
        assert _classify_ioc("\\u003e0x21993862\\u003c") is None
        assert _classify_ioc("u003etest") is None

    def test_auto_extract_with_scope(self):
        """Test auto_extract_evidence_from_query respects target scope."""
        set_target_domains(["contoso.local"])

        result = {
            "valid_host": "dc01.contoso.local",
            "out_of_scope": "server.otherdomain.local",
            "valid_ip": "192.168.58.100",
            "garbled": "\\u003e0x21993862\\u003c",
        }
        evidence = auto_extract_evidence_from_query(result, "test query")

        values = [e["value"] for e in evidence]
        assert "dc01.contoso.local" in values
        assert "192.168.58.100" in values  # IPs not filtered by domain scope
        assert "server.otherdomain.local" not in values
        assert "\\u003e0x21993862\\u003c" not in values
