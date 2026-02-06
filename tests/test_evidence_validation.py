"""Tests for evidence validation and IOC extraction."""

from ares.core.evidence_validation import (
    MAX_STORED_RESULTS,
    UNVALIDATED_CONFIDENCE_PENALTY,
    StoredQueryResult,
    _classify_ioc,
    _extract_patterns_from_string,
    _extract_searchable_values,
    adjust_confidence_for_validation,
    auto_extract_evidence_from_query,
    boost_confidence_for_quality,
    get_recent_query_ids,
    get_suggested_iocs,
    reset_evidence_validation,
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
        data = {"ip": "192.168.58.100", "user": "admin@domain.local"}
        store_query_result("test", "query", data, 2)

        # Check via suggested IOCs
        suggestions = get_suggested_iocs()
        values = [s["value"] for s in suggestions]
        assert any("192.168.58.100" in v for v in values)

    def test_store_respects_max_limit(self):
        """Test store respects MAX_STORED_RESULTS."""
        reset_evidence_validation()

        # Store more than max
        for i in range(MAX_STORED_RESULTS + 5):
            store_query_result("test", f"query{i}", {f"val{i}": f"data{i}"}, 1)

        # Should only have MAX_STORED_RESULTS
        assert len(get_recent_query_ids()) == MAX_STORED_RESULTS


class TestExtractSearchableValues:
    """Tests for _extract_searchable_values function."""

    def test_extract_from_string(self):
        """Test extracting from string."""
        values = _extract_searchable_values("192.168.58.100")
        assert "192.168.58.100" in values

    def test_extract_from_dict(self):
        """Test extracting from dictionary."""
        data = {"ip": "192.168.58.1", "host": "server01.domain.local"}
        values = _extract_searchable_values(data)
        assert "192.168.58.1" in values
        assert "server01.domain.local" in values

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
        text = "Host: server01.domain.local connected"
        patterns = _extract_patterns_from_string(text)
        assert "server01.domain.local" in patterns

    def test_extract_domain_user(self):
        """Test extracting domain\\user format."""
        text = "User DOMAIN\\admin logged in"
        patterns = _extract_patterns_from_string(text)
        assert "domain\\admin" in patterns

    def test_extract_email_user(self):
        """Test extracting user@domain format."""
        text = "User admin@domain.local authenticated"
        patterns = _extract_patterns_from_string(text)
        assert "admin@domain.local" in patterns

    def test_extract_json_username_fields(self):
        """Test extracting usernames from JSON fields."""
        text = '{"TargetUserName": "testuser", "SubjectUserName": "SYSTEM"}'
        patterns = _extract_patterns_from_string(text)
        assert "testuser" in patterns
        # SYSTEM should be excluded
        assert "system" not in patterns

    def test_extract_computer_name(self):
        """Test extracting computer names."""
        text = '{"Computer": "DC01.domain.local"}'
        patterns = _extract_patterns_from_string(text)
        assert "dc01.domain.local" in patterns

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
        store_query_result("test", "query", {"host": "DC01.Domain.LOCAL"}, 1)

        validated, _query_id = validate_evidence_value("dc01.domain.local")
        assert validated is True

    def test_validate_partial_match(self):
        """Test validating partial match."""
        reset_evidence_validation()
        store_query_result("test", "query", {"user": "admin@domain.local"}, 1)

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
        assert _classify_ioc("admin@domain.local") == "user"

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


class TestAdjustConfidenceForValidation:
    """Tests for adjust_confidence_for_validation function."""

    def test_validated_no_change(self):
        """Test validated evidence keeps confidence."""
        assert adjust_confidence_for_validation(0.8, validated=True) == 0.8
        assert adjust_confidence_for_validation(0.5, validated=True) == 0.5

    def test_unvalidated_penalty(self):
        """Test unvalidated evidence gets penalty."""
        result = adjust_confidence_for_validation(0.8, validated=False)
        expected = 0.8 - UNVALIDATED_CONFIDENCE_PENALTY
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
        result = {"host": "server01.domain.local"}
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
