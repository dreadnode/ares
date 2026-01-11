"""Tests for query template tools."""

from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from ares.tools.blue.query_templates import QueryTemplateTools


class TestQueryTemplateToolsInit:
    """Tests for QueryTemplateTools initialization."""

    def test_init_with_loki_url(self):
        """Test initialization with Loki URL."""
        tools = QueryTemplateTools(loki_url="http://localhost:3100")
        assert tools.loki_url == "http://localhost:3100"
        assert tools.timeout == 30

    def test_init_with_custom_timeout(self):
        """Test initialization with custom timeout."""
        tools = QueryTemplateTools(loki_url="http://localhost:3100", timeout=60)
        assert tools.timeout == 60


class TestQueryLokiInternal:
    """Tests for internal _query_loki method."""

    @pytest.fixture
    def tools(self) -> QueryTemplateTools:
        return QueryTemplateTools(loki_url="http://localhost:3100")

    @pytest.mark.asyncio
    async def test_query_loki_rejects_empty_regex(self, tools: QueryTemplateTools):
        """Test _query_loki rejects empty-compatible regex."""
        result = await tools._query_loki(
            logql='{job=~".*"}',
            start_time="2024-01-15T10:00:00Z",
            end_time="2024-01-15T11:00:00Z",
        )
        assert result["status"] == "error"
        assert "empty-compatible regex" in result["error"]

    @pytest.mark.asyncio
    async def test_query_loki_success(self, tools: QueryTemplateTools):
        """Test successful _query_loki execution."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "status": "success",
            "data": {"result": [{"values": [["1705320000", "log"]]}]},
        }
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(
                return_value=mock_response
            )
            result = await tools._query_loki(
                logql='{job="syslog"}',
                start_time="2024-01-15T10:00:00Z",
                end_time="2024-01-15T11:00:00Z",
                limit=100,
            )

        assert result["status"] == "success"

    @pytest.mark.asyncio
    async def test_query_loki_http_error(self, tools: QueryTemplateTools):
        """Test _query_loki handles HTTP errors."""
        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(
                side_effect=httpx.HTTPError("Connection failed")
            )
            result = await tools._query_loki(
                logql='{job="syslog"}',
                start_time="2024-01-15T10:00:00Z",
                end_time="2024-01-15T11:00:00Z",
            )

        assert result["status"] == "error"
        assert "Connection failed" in result["error"]


class TestGetTimeRange:
    """Tests for _get_time_range method."""

    @pytest.fixture
    def tools(self) -> QueryTemplateTools:
        return QueryTemplateTools(loki_url="http://localhost:3100")

    def test_get_time_range_default(self, tools: QueryTemplateTools):
        """Test default 1-hour time range."""
        start, end = tools._get_time_range()
        start_dt = datetime.fromisoformat(start.replace("Z", "+00:00"))
        end_dt = datetime.fromisoformat(end.replace("Z", "+00:00"))

        # Default is 1 hour (default_hours_back=1)
        delta = end_dt - start_dt
        assert 0.9 <= delta.total_seconds() / 3600 <= 1.1  # ~1 hour

    def test_get_time_range_custom(self, tools: QueryTemplateTools):
        """Test custom hour range."""
        start, end = tools._get_time_range(hours_back=4)
        start_dt = datetime.fromisoformat(start.replace("Z", "+00:00"))
        end_dt = datetime.fromisoformat(end.replace("Z", "+00:00"))

        delta = end_dt - start_dt
        assert 3.9 <= delta.total_seconds() / 3600 <= 4.1  # ~4 hours


class TestCountResults:
    """Tests for _count_results method."""

    @pytest.fixture
    def tools(self) -> QueryTemplateTools:
        return QueryTemplateTools(loki_url="http://localhost:3100")

    def test_count_results_empty(self, tools: QueryTemplateTools):
        """Test counting empty results."""
        result = {"data": {"result": []}}
        assert tools._count_results(result) == 0

    def test_count_results_single_stream(self, tools: QueryTemplateTools):
        """Test counting single stream results."""
        result = {"data": {"result": [{"values": [["1", "a"], ["2", "b"], ["3", "c"]]}]}}
        assert tools._count_results(result) == 3

    def test_count_results_multiple_streams(self, tools: QueryTemplateTools):
        """Test counting multiple stream results."""
        result = {
            "data": {
                "result": [
                    {"values": [["1", "a"], ["2", "b"]]},
                    {"values": [["3", "c"]]},
                    {"values": [["4", "d"], ["5", "e"]]},
                ]
            }
        }
        assert tools._count_results(result) == 5

    def test_count_results_missing_data(self, tools: QueryTemplateTools):
        """Test counting with missing data key."""
        result = {}
        assert tools._count_results(result) == 0


class TestPortScanningDetection:
    """Tests for detect_port_scanning method."""

    @pytest.fixture
    def tools(self) -> QueryTemplateTools:
        return QueryTemplateTools(loki_url="http://localhost:3100")

    @pytest.mark.asyncio
    async def test_detect_port_scanning_basic(self, tools: QueryTemplateTools):
        """Test basic port scanning detection."""
        mock_response = MagicMock()
        mock_response.json.return_value = {"status": "success", "data": {"result": []}}
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(
                return_value=mock_response
            )
            result = await tools.detect_port_scanning()

        assert result["_query_template"] == "port_scanning"
        assert result["_mitre_technique"] == "T1046"
        assert result["_red_team_tool"] == "nmap_scan"

    @pytest.mark.asyncio
    async def test_detect_port_scanning_with_target(self, tools: QueryTemplateTools):
        """Test port scanning detection with target IP."""
        mock_response = MagicMock()
        mock_response.json.return_value = {"status": "success", "data": {"result": []}}
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = mock_client.return_value.__aenter__.return_value
            mock_instance.get = AsyncMock(return_value=mock_response)

            await tools.detect_port_scanning(target_ip="192.168.1.100")

            call_args = mock_instance.get.call_args
            params = call_args.kwargs.get("params", call_args[1].get("params", {}))
            assert "192.168.1.100" in params["query"]


class TestUserEnumerationDetection:
    """Tests for detect_user_enumeration method."""

    @pytest.fixture
    def tools(self) -> QueryTemplateTools:
        return QueryTemplateTools(loki_url="http://localhost:3100")

    @pytest.mark.asyncio
    async def test_detect_user_enumeration(self, tools: QueryTemplateTools):
        """Test user enumeration detection."""
        mock_response = MagicMock()
        mock_response.json.return_value = {"status": "success", "data": {"result": []}}
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(
                return_value=mock_response
            )
            result = await tools.detect_user_enumeration()

        assert result["_query_template"] == "user_enumeration"
        assert result["_mitre_technique"] == "T1087.002"


class TestShareEnumerationDetection:
    """Tests for detect_share_enumeration method."""

    @pytest.fixture
    def tools(self) -> QueryTemplateTools:
        return QueryTemplateTools(loki_url="http://localhost:3100")

    @pytest.mark.asyncio
    async def test_detect_share_enumeration(self, tools: QueryTemplateTools):
        """Test share enumeration detection."""
        mock_response = MagicMock()
        mock_response.json.return_value = {"status": "success", "data": {"result": []}}
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(
                return_value=mock_response
            )
            result = await tools.detect_share_enumeration()

        assert result["_query_template"] == "share_enumeration"
        assert result["_mitre_technique"] == "T1135"


class TestSecretsdumpDetection:
    """Tests for detect_secretsdump method."""

    @pytest.fixture
    def tools(self) -> QueryTemplateTools:
        return QueryTemplateTools(loki_url="http://localhost:3100")

    @pytest.mark.asyncio
    async def test_detect_secretsdump(self, tools: QueryTemplateTools):
        """Test secretsdump detection."""
        mock_response = MagicMock()
        mock_response.json.return_value = {"status": "success", "data": {"result": []}}
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(
                return_value=mock_response
            )
            result = await tools.detect_secretsdump()

        assert result["_query_template"] == "secretsdump"
        assert result["_mitre_technique"] == "T1003"
        assert "T1003.001" in result["_mitre_subtechniques"]


class TestDCSyncDetection:
    """Tests for detect_dcsync method."""

    @pytest.fixture
    def tools(self) -> QueryTemplateTools:
        return QueryTemplateTools(loki_url="http://localhost:3100")

    @pytest.mark.asyncio
    async def test_detect_dcsync(self, tools: QueryTemplateTools):
        """Test DCSync detection."""
        mock_response = MagicMock()
        mock_response.json.return_value = {"status": "success", "data": {"result": []}}
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(
                return_value=mock_response
            )
            result = await tools.detect_dcsync()

        assert result["_query_template"] == "dcsync"
        assert result["_mitre_technique"] == "T1003.006"
        assert result["_severity"] == "critical"


class TestKerberoastingDetection:
    """Tests for detect_kerberoasting method."""

    @pytest.fixture
    def tools(self) -> QueryTemplateTools:
        return QueryTemplateTools(loki_url="http://localhost:3100")

    @pytest.mark.asyncio
    async def test_detect_kerberoasting(self, tools: QueryTemplateTools):
        """Test Kerberoasting detection."""
        mock_response = MagicMock()
        mock_response.json.return_value = {"status": "success", "data": {"result": []}}
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(
                return_value=mock_response
            )
            result = await tools.detect_kerberoasting()

        assert result["_query_template"] == "kerberoasting"
        assert result["_mitre_technique"] == "T1558.003"


class TestASREPRoastingDetection:
    """Tests for detect_asrep_roasting method."""

    @pytest.fixture
    def tools(self) -> QueryTemplateTools:
        return QueryTemplateTools(loki_url="http://localhost:3100")

    @pytest.mark.asyncio
    async def test_detect_asrep_roasting(self, tools: QueryTemplateTools):
        """Test AS-REP roasting detection."""
        mock_response = MagicMock()
        mock_response.json.return_value = {"status": "success", "data": {"result": []}}
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(
                return_value=mock_response
            )
            result = await tools.detect_asrep_roasting()

        assert result["_query_template"] == "asrep_roasting"
        assert result["_mitre_technique"] == "T1558.004"


class TestBruteForceDetection:
    """Tests for detect_brute_force method."""

    @pytest.fixture
    def tools(self) -> QueryTemplateTools:
        return QueryTemplateTools(loki_url="http://localhost:3100")

    @pytest.mark.asyncio
    async def test_detect_brute_force_below_threshold(self, tools: QueryTemplateTools):
        """Test brute force detection below threshold."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "status": "success",
            "data": {"result": [{"values": [["1", "a"], ["2", "b"]]}]},
        }
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(
                return_value=mock_response
            )
            result = await tools.detect_brute_force(threshold=10)

        assert result["_analysis"]["is_likely_attack"] is False
        assert result["_analysis"]["total_failures"] == 2

    @pytest.mark.asyncio
    async def test_detect_brute_force_above_threshold(self, tools: QueryTemplateTools):
        """Test brute force detection above threshold."""
        mock_response = MagicMock()
        # Create 15 log entries
        mock_response.json.return_value = {
            "status": "success",
            "data": {"result": [{"values": [[str(i), f"log{i}"] for i in range(15)]}]},
        }
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(
                return_value=mock_response
            )
            result = await tools.detect_brute_force(threshold=10)

        assert result["_analysis"]["is_likely_attack"] is True
        assert result["_analysis"]["total_failures"] == 15


class TestPassTheHashDetection:
    """Tests for detect_pass_the_hash method."""

    @pytest.fixture
    def tools(self) -> QueryTemplateTools:
        return QueryTemplateTools(loki_url="http://localhost:3100")

    @pytest.mark.asyncio
    async def test_detect_pass_the_hash(self, tools: QueryTemplateTools):
        """Test Pass-the-Hash detection."""
        mock_response = MagicMock()
        mock_response.json.return_value = {"status": "success", "data": {"result": []}}
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(
                return_value=mock_response
            )
            result = await tools.detect_pass_the_hash()

        assert result["_query_template"] == "pass_the_hash"
        assert result["_mitre_technique"] == "T1550.002"


class TestQueryTemplatesWithHostFilter:
    """Tests for query templates with host filtering."""

    @pytest.fixture
    def tools(self) -> QueryTemplateTools:
        return QueryTemplateTools(loki_url="http://localhost:3100")

    @pytest.mark.asyncio
    async def test_secretsdump_with_host(self, tools: QueryTemplateTools):
        """Test secretsdump with target host filter."""
        mock_response = MagicMock()
        mock_response.json.return_value = {"status": "success", "data": {"result": []}}
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = mock_client.return_value.__aenter__.return_value
            mock_instance.get = AsyncMock(return_value=mock_response)

            await tools.detect_secretsdump(target_host="dc01")

            call_args = mock_instance.get.call_args
            params = call_args.kwargs.get("params", call_args[1].get("params", {}))
            assert "dc01" in params["query"]

    @pytest.mark.asyncio
    async def test_kerberoasting_with_dc(self, tools: QueryTemplateTools):
        """Test kerberoasting with domain controller filter."""
        mock_response = MagicMock()
        mock_response.json.return_value = {"status": "success", "data": {"result": []}}
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = mock_client.return_value.__aenter__.return_value
            mock_instance.get = AsyncMock(return_value=mock_response)

            await tools.detect_kerberoasting(domain_controller="dc01.corp.local")

            call_args = mock_instance.get.call_args
            params = call_args.kwargs.get("params", call_args[1].get("params", {}))
            assert "dc01.corp.local" in params["query"]


class TestTimeRangeParameter:
    """Tests for hours_back parameter across methods."""

    @pytest.fixture
    def tools(self) -> QueryTemplateTools:
        return QueryTemplateTools(loki_url="http://localhost:3100")

    @pytest.mark.asyncio
    async def test_custom_time_range(self, tools: QueryTemplateTools):
        """Test custom hours_back parameter."""
        mock_response = MagicMock()
        mock_response.json.return_value = {"status": "success", "data": {"result": []}}
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = mock_client.return_value.__aenter__.return_value
            mock_instance.get = AsyncMock(return_value=mock_response)

            await tools.detect_port_scanning(hours_back=1)

            call_args = mock_instance.get.call_args
            params = call_args.kwargs.get("params", call_args[1].get("params", {}))

            # Verify time range is ~1 hour
            start = datetime.fromisoformat(params["start"].replace("Z", "+00:00"))
            end = datetime.fromisoformat(params["end"].replace("Z", "+00:00"))
            delta = (end - start).total_seconds() / 3600
            assert 0.9 <= delta <= 1.1


class TestGoldenTicketDetection:
    """Tests for detect_golden_ticket method."""

    @pytest.fixture
    def tools(self) -> QueryTemplateTools:
        return QueryTemplateTools(loki_url="http://localhost:3100")

    @pytest.mark.asyncio
    async def test_detect_golden_ticket(self, tools: QueryTemplateTools):
        """Test Golden Ticket detection."""
        mock_response = MagicMock()
        mock_response.json.return_value = {"status": "success", "data": {"result": []}}
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(
                return_value=mock_response
            )
            result = await tools.detect_golden_ticket()

        assert result["_query_template"] == "golden_ticket"
        assert result["_mitre_technique"] == "T1558.001"
        assert result["_severity"] == "critical"


class TestLateralMovementDetection:
    """Tests for detect_lateral_movement method."""

    @pytest.fixture
    def tools(self) -> QueryTemplateTools:
        return QueryTemplateTools(loki_url="http://localhost:3100")

    @pytest.mark.asyncio
    async def test_detect_lateral_movement(self, tools: QueryTemplateTools):
        """Test lateral movement detection."""
        mock_response = MagicMock()
        mock_response.json.return_value = {"status": "success", "data": {"result": []}}
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(
                return_value=mock_response
            )
            result = await tools.detect_lateral_movement()

        assert result["_query_template"] == "lateral_movement"
        assert result["_mitre_technique"] == "T1021"


class TestImpacketWMIExecDetection:
    """Tests for detect_impacket_wmiexec method."""

    @pytest.fixture
    def tools(self) -> QueryTemplateTools:
        return QueryTemplateTools(loki_url="http://localhost:3100")

    @pytest.mark.asyncio
    async def test_detect_impacket_wmiexec(self, tools: QueryTemplateTools):
        """Test Impacket WMI execution detection."""
        mock_response = MagicMock()
        mock_response.json.return_value = {"status": "success", "data": {"result": []}}
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(
                return_value=mock_response
            )
            result = await tools.detect_impacket_wmiexec()

        assert result["_query_template"] == "impacket_wmiexec"
        assert result["_mitre_technique"] == "T1047"


class TestImpacketPsExecDetection:
    """Tests for detect_impacket_psexec method."""

    @pytest.fixture
    def tools(self) -> QueryTemplateTools:
        return QueryTemplateTools(loki_url="http://localhost:3100")

    @pytest.mark.asyncio
    async def test_detect_impacket_psexec(self, tools: QueryTemplateTools):
        """Test Impacket PsExec detection."""
        mock_response = MagicMock()
        mock_response.json.return_value = {"status": "success", "data": {"result": []}}
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(
                return_value=mock_response
            )
            result = await tools.detect_impacket_psexec()

        assert result["_query_template"] == "impacket_psexec"
        assert result["_mitre_technique"] == "T1569.002"


class TestImpacketSMBExecDetection:
    """Tests for detect_impacket_smbexec method."""

    @pytest.fixture
    def tools(self) -> QueryTemplateTools:
        return QueryTemplateTools(loki_url="http://localhost:3100")

    @pytest.mark.asyncio
    async def test_detect_impacket_smbexec(self, tools: QueryTemplateTools):
        """Test Impacket SMBExec detection."""
        mock_response = MagicMock()
        mock_response.json.return_value = {"status": "success", "data": {"result": []}}
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(
                return_value=mock_response
            )
            result = await tools.detect_impacket_smbexec()

        assert result["_query_template"] == "impacket_smbexec"
        assert result["_mitre_technique"] == "T1569.002"


class TestImpacketDCOMExecDetection:
    """Tests for detect_impacket_dcomexec method."""

    @pytest.fixture
    def tools(self) -> QueryTemplateTools:
        return QueryTemplateTools(loki_url="http://localhost:3100")

    @pytest.mark.asyncio
    async def test_detect_impacket_dcomexec(self, tools: QueryTemplateTools):
        """Test Impacket DCOM execution detection."""
        mock_response = MagicMock()
        mock_response.json.return_value = {"status": "success", "data": {"result": []}}
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(
                return_value=mock_response
            )
            result = await tools.detect_impacket_dcomexec()

        assert result["_query_template"] == "impacket_dcomexec"
        assert result["_mitre_technique"] == "T1021.003"


class TestDelegationAbuseDetection:
    """Tests for detect_delegation_abuse method."""

    @pytest.fixture
    def tools(self) -> QueryTemplateTools:
        return QueryTemplateTools(loki_url="http://localhost:3100")

    @pytest.mark.asyncio
    async def test_detect_delegation_abuse(self, tools: QueryTemplateTools):
        """Test delegation abuse detection."""
        mock_response = MagicMock()
        mock_response.json.return_value = {"status": "success", "data": {"result": []}}
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(
                return_value=mock_response
            )
            result = await tools.detect_delegation_abuse()

        assert result["_query_template"] == "delegation_abuse"
        assert result["_mitre_technique"] == "T1134.001"


class TestImpacketNTLMRelayxDetection:
    """Tests for detect_impacket_ntlmrelayx method."""

    @pytest.fixture
    def tools(self) -> QueryTemplateTools:
        return QueryTemplateTools(loki_url="http://localhost:3100")

    @pytest.mark.asyncio
    async def test_detect_impacket_ntlmrelayx(self, tools: QueryTemplateTools):
        """Test NTLM relay detection."""
        mock_response = MagicMock()
        mock_response.json.return_value = {"status": "success", "data": {"result": []}}
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(
                return_value=mock_response
            )
            result = await tools.detect_impacket_ntlmrelayx()

        assert result["_query_template"] == "impacket_ntlmrelayx"
        assert result["_mitre_technique"] == "T1557.001"


class TestADCSExploitationDetection:
    """Tests for detect_adcs_exploitation method."""

    @pytest.fixture
    def tools(self) -> QueryTemplateTools:
        return QueryTemplateTools(loki_url="http://localhost:3100")

    @pytest.mark.asyncio
    async def test_detect_adcs_exploitation(self, tools: QueryTemplateTools):
        """Test AD CS exploitation detection."""
        mock_response = MagicMock()
        mock_response.json.return_value = {"status": "success", "data": {"result": []}}
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(
                return_value=mock_response
            )
            result = await tools.detect_adcs_exploitation()

        assert result["_query_template"] == "adcs_exploitation"
        assert result["_mitre_technique"] == "T1649"


class TestImpacketSecretsdumpSAMDetection:
    """Tests for detect_impacket_secretsdump_sam method."""

    @pytest.fixture
    def tools(self) -> QueryTemplateTools:
        return QueryTemplateTools(loki_url="http://localhost:3100")

    @pytest.mark.asyncio
    async def test_detect_impacket_secretsdump_sam(self, tools: QueryTemplateTools):
        """Test SAM secrets dump detection."""
        mock_response = MagicMock()
        mock_response.json.return_value = {"status": "success", "data": {"result": []}}
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(
                return_value=mock_response
            )
            result = await tools.detect_impacket_secretsdump_sam()

        assert result["_query_template"] == "impacket_secretsdump_sam"
        assert result["_mitre_technique"] == "T1003.002"


class TestImpacketSecretsdumpLSADetection:
    """Tests for detect_impacket_secretsdump_lsa method."""

    @pytest.fixture
    def tools(self) -> QueryTemplateTools:
        return QueryTemplateTools(loki_url="http://localhost:3100")

    @pytest.mark.asyncio
    async def test_detect_impacket_secretsdump_lsa(self, tools: QueryTemplateTools):
        """Test LSA secrets dump detection."""
        mock_response = MagicMock()
        mock_response.json.return_value = {"status": "success", "data": {"result": []}}
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(
                return_value=mock_response
            )
            result = await tools.detect_impacket_secretsdump_lsa()

        assert result["_query_template"] == "impacket_secretsdump_lsa"
        assert result["_mitre_technique"] == "T1003.004"


class TestBloodhoundCollectionDetection:
    """Tests for detect_bloodhound_collection method."""

    @pytest.fixture
    def tools(self) -> QueryTemplateTools:
        return QueryTemplateTools(loki_url="http://localhost:3100")

    @pytest.mark.asyncio
    async def test_detect_bloodhound_collection(self, tools: QueryTemplateTools):
        """Test BloodHound collection detection."""
        mock_response = MagicMock()
        mock_response.json.return_value = {"status": "success", "data": {"result": []}}
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(
                return_value=mock_response
            )
            result = await tools.detect_bloodhound_collection()

        assert result["_query_template"] == "bloodhound_collection"
        assert "T1087" in result["_mitre_techniques"]


class TestSMBFileAccessDetection:
    """Tests for detect_smb_file_access method."""

    @pytest.fixture
    def tools(self) -> QueryTemplateTools:
        return QueryTemplateTools(loki_url="http://localhost:3100")

    @pytest.mark.asyncio
    async def test_detect_smb_file_access(self, tools: QueryTemplateTools):
        """Test SMB file access detection."""
        mock_response = MagicMock()
        mock_response.json.return_value = {"status": "success", "data": {"result": []}}
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(
                return_value=mock_response
            )
            result = await tools.detect_smb_file_access()

        assert result["_query_template"] == "smb_file_access"
        assert result["_mitre_technique"] == "T1039"


class TestCertipyEnumerationDetection:
    """Tests for detect_certipy_enumeration method."""

    @pytest.fixture
    def tools(self) -> QueryTemplateTools:
        return QueryTemplateTools(loki_url="http://localhost:3100")

    @pytest.mark.asyncio
    async def test_detect_certipy_enumeration(self, tools: QueryTemplateTools):
        """Test Certipy enumeration detection."""
        mock_response = MagicMock()
        mock_response.json.return_value = {"status": "success", "data": {"result": []}}
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(
                return_value=mock_response
            )
            result = await tools.detect_certipy_enumeration()

        assert result["_query_template"] == "certipy_enumeration"
        assert result["_mitre_technique"] == "T1649"


class TestSuspiciousExecutionDetection:
    """Tests for detect_suspicious_execution method."""

    @pytest.fixture
    def tools(self) -> QueryTemplateTools:
        return QueryTemplateTools(loki_url="http://localhost:3100")

    @pytest.mark.asyncio
    async def test_detect_suspicious_execution(self, tools: QueryTemplateTools):
        """Test suspicious execution detection."""
        mock_response = MagicMock()
        mock_response.json.return_value = {"status": "success", "data": {"result": []}}
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(
                return_value=mock_response
            )
            result = await tools.detect_suspicious_execution()

        assert result["_query_template"] == "suspicious_execution"
        assert result["_mitre_technique"] == "T1059"


class TestImpacketAtExecDetection:
    """Tests for detect_impacket_atexec method."""

    @pytest.fixture
    def tools(self) -> QueryTemplateTools:
        return QueryTemplateTools(loki_url="http://localhost:3100")

    @pytest.mark.asyncio
    async def test_detect_impacket_atexec(self, tools: QueryTemplateTools):
        """Test Impacket AtExec detection."""
        mock_response = MagicMock()
        mock_response.json.return_value = {"status": "success", "data": {"result": []}}
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(
                return_value=mock_response
            )
            result = await tools.detect_impacket_atexec()

        assert result["_query_template"] == "impacket_atexec"
        assert result["_mitre_technique"] == "T1053.002"


class TestImpacketSMBClientDetection:
    """Tests for detect_impacket_smbclient method."""

    @pytest.fixture
    def tools(self) -> QueryTemplateTools:
        return QueryTemplateTools(loki_url="http://localhost:3100")

    @pytest.mark.asyncio
    async def test_detect_impacket_smbclient(self, tools: QueryTemplateTools):
        """Test Impacket SMB client detection."""
        mock_response = MagicMock()
        mock_response.json.return_value = {"status": "success", "data": {"result": []}}
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(
                return_value=mock_response
            )
            result = await tools.detect_impacket_smbclient()

        assert result["_query_template"] == "impacket_smbclient"
        assert result["_mitre_technique"] == "T1021.002"


class TestESC1AttackDetection:
    """Tests for detect_esc1_attack method."""

    @pytest.fixture
    def tools(self) -> QueryTemplateTools:
        return QueryTemplateTools(loki_url="http://localhost:3100")

    @pytest.mark.asyncio
    async def test_detect_esc1_attack(self, tools: QueryTemplateTools):
        """Test ESC1 attack detection."""
        mock_response = MagicMock()
        mock_response.json.return_value = {"status": "success", "data": {"result": []}}
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(
                return_value=mock_response
            )
            result = await tools.detect_esc1_attack()

        assert result["_query_template"] == "esc1_attack"
        assert result["_mitre_technique"] == "T1649"


class TestESC4AttackDetection:
    """Tests for detect_esc4_attack method."""

    @pytest.fixture
    def tools(self) -> QueryTemplateTools:
        return QueryTemplateTools(loki_url="http://localhost:3100")

    @pytest.mark.asyncio
    async def test_detect_esc4_attack(self, tools: QueryTemplateTools):
        """Test ESC4 attack detection."""
        mock_response = MagicMock()
        mock_response.json.return_value = {"status": "success", "data": {"result": []}}
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(
                return_value=mock_response
            )
            result = await tools.detect_esc4_attack()

        assert result["_query_template"] == "esc4_attack"
        assert result["_mitre_technique"] == "T1649"


class TestESC8AttackDetection:
    """Tests for detect_esc8_attack method."""

    @pytest.fixture
    def tools(self) -> QueryTemplateTools:
        return QueryTemplateTools(loki_url="http://localhost:3100")

    @pytest.mark.asyncio
    async def test_detect_esc8_attack(self, tools: QueryTemplateTools):
        """Test ESC8 attack detection."""
        mock_response = MagicMock()
        mock_response.json.return_value = {"status": "success", "data": {"result": []}}
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(
                return_value=mock_response
            )
            result = await tools.detect_esc8_attack()

        assert result["_query_template"] == "esc8_attack"
        assert result["_mitre_technique"] == "T1649"


class TestCertificateAuthenticationDetection:
    """Tests for detect_certificate_authentication method."""

    @pytest.fixture
    def tools(self) -> QueryTemplateTools:
        return QueryTemplateTools(loki_url="http://localhost:3100")

    @pytest.mark.asyncio
    async def test_detect_certificate_authentication(self, tools: QueryTemplateTools):
        """Test certificate-based authentication detection."""
        mock_response = MagicMock()
        mock_response.json.return_value = {"status": "success", "data": {"result": []}}
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(
                return_value=mock_response
            )
            result = await tools.detect_certificate_authentication()

        assert result["_query_template"] == "certificate_authentication"
        assert result["_mitre_technique"] == "T1649"


class TestBloodhoundDomainEnumDetection:
    """Tests for detect_bloodhound_domain_enum method."""

    @pytest.fixture
    def tools(self) -> QueryTemplateTools:
        return QueryTemplateTools(loki_url="http://localhost:3100")

    @pytest.mark.asyncio
    async def test_detect_bloodhound_domain_enum(self, tools: QueryTemplateTools):
        """Test BloodHound domain enumeration detection."""
        mock_response = MagicMock()
        mock_response.json.return_value = {"status": "success", "data": {"result": []}}
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(
                return_value=mock_response
            )
            result = await tools.detect_bloodhound_domain_enum()

        assert result["_query_template"] == "bloodhound_domain_enum"
        assert result["_mitre_technique"] == "T1482"


class TestBloodhoundACLEnumDetection:
    """Tests for detect_bloodhound_acl_enum method."""

    @pytest.fixture
    def tools(self) -> QueryTemplateTools:
        return QueryTemplateTools(loki_url="http://localhost:3100")

    @pytest.mark.asyncio
    async def test_detect_bloodhound_acl_enum(self, tools: QueryTemplateTools):
        """Test BloodHound ACL enumeration detection."""
        mock_response = MagicMock()
        mock_response.json.return_value = {"status": "success", "data": {"result": []}}
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(
                return_value=mock_response
            )
            result = await tools.detect_bloodhound_acl_enum()

        assert result["_query_template"] == "bloodhound_acl_enum"
        assert result["_mitre_technique"] == "T1069.002"


class TestBloodhoundSessionEnumDetection:
    """Tests for detect_bloodhound_session_enum method."""

    @pytest.fixture
    def tools(self) -> QueryTemplateTools:
        return QueryTemplateTools(loki_url="http://localhost:3100")

    @pytest.mark.asyncio
    async def test_detect_bloodhound_session_enum(self, tools: QueryTemplateTools):
        """Test BloodHound session enumeration detection."""
        mock_response = MagicMock()
        mock_response.json.return_value = {"status": "success", "data": {"result": []}}
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(
                return_value=mock_response
            )
            result = await tools.detect_bloodhound_session_enum()

        assert result["_query_template"] == "bloodhound_session_enum"
        assert result["_mitre_technique"] == "T1033"


class TestBloodhoundGPOEnumDetection:
    """Tests for detect_bloodhound_gpo_enum method."""

    @pytest.fixture
    def tools(self) -> QueryTemplateTools:
        return QueryTemplateTools(loki_url="http://localhost:3100")

    @pytest.mark.asyncio
    async def test_detect_bloodhound_gpo_enum(self, tools: QueryTemplateTools):
        """Test BloodHound GPO enumeration detection."""
        mock_response = MagicMock()
        mock_response.json.return_value = {"status": "success", "data": {"result": []}}
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(
                return_value=mock_response
            )
            result = await tools.detect_bloodhound_gpo_enum()

        assert result["_query_template"] == "bloodhound_gpo_enum"
        assert result["_mitre_technique"] == "T1615"


class TestBloodhoundComputerEnumDetection:
    """Tests for detect_bloodhound_computer_enum method."""

    @pytest.fixture
    def tools(self) -> QueryTemplateTools:
        return QueryTemplateTools(loki_url="http://localhost:3100")

    @pytest.mark.asyncio
    async def test_detect_bloodhound_computer_enum(self, tools: QueryTemplateTools):
        """Test BloodHound computer enumeration detection."""
        mock_response = MagicMock()
        mock_response.json.return_value = {"status": "success", "data": {"result": []}}
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(
                return_value=mock_response
            )
            result = await tools.detect_bloodhound_computer_enum()

        assert result["_query_template"] == "bloodhound_computer_enum"
        assert result["_mitre_technique"] == "T1018"


class TestListQueryTemplates:
    """Tests for list_query_templates method."""

    @pytest.fixture
    def tools(self) -> QueryTemplateTools:
        return QueryTemplateTools(loki_url="http://localhost:3100")

    def test_list_query_templates(self, tools: QueryTemplateTools):
        """Test listing all available templates."""
        templates = tools.list_query_templates()
        assert isinstance(templates, list)
        assert len(templates) > 0
        # Check each template has required fields
        for template in templates:
            assert "name" in template
            assert "description" in template
            assert "mitre" in template

    def test_list_templates_includes_common_detections(self, tools: QueryTemplateTools):
        """Test that common detection templates are listed."""
        templates = tools.list_query_templates()
        template_names = [t["name"] for t in templates]
        # Should include common detection methods
        assert "detect_port_scanning" in template_names
        assert "detect_secretsdump" in template_names
        assert "detect_dcsync" in template_names
        assert "detect_kerberoasting" in template_names


class TestInternalHelperMethods:
    """Tests for internal helper methods."""

    @pytest.fixture
    def tools(self) -> QueryTemplateTools:
        return QueryTemplateTools(loki_url="http://localhost:3100")

    def test_build_selector_with_extra_labels_exact_match(self, tools: QueryTemplateTools):
        """Test _build_selector with extra_labels using exact match."""
        # extra_labels without wildcards or dots should use exact match
        selector = tools._build_selector(extra_labels={"env": "prod", "region": "us-east"})
        assert 'env="prod"' in selector
        assert 'region="us-east"' in selector

    def test_build_selector_with_extra_labels_regex_wildcard(self, tools: QueryTemplateTools):
        """Test _build_selector with extra_labels containing wildcard."""
        # extra_labels with wildcard should use regex
        selector = tools._build_selector(extra_labels={"namespace": "prod-*"})
        assert 'namespace=~"prod-*"' in selector

    def test_build_selector_with_extra_labels_regex_dot(self, tools: QueryTemplateTools):
        """Test _build_selector with extra_labels containing dots."""
        # extra_labels with dots should use regex
        selector = tools._build_selector(extra_labels={"host": "server.domain.local"})
        assert 'host=~"server.domain.local"' in selector

    def test_build_event_filter_empty(self, tools: QueryTemplateTools):
        """Test _build_event_filter with empty list."""
        result = tools._build_event_filter([])
        assert result == ""

    def test_build_event_filter_single_id(self, tools: QueryTemplateTools):
        """Test _build_event_filter with single event ID."""
        result = tools._build_event_filter(["4624"])
        assert result == '|= "4624"'

    def test_build_event_filter_multiple_ids(self, tools: QueryTemplateTools):
        """Test _build_event_filter with multiple event IDs."""
        result = tools._build_event_filter(["4624", "4625", "4648"])
        assert "|~" in result
        assert "4624" in result
        assert "4625" in result
        assert "4648" in result

    def test_build_pattern_filter_empty(self, tools: QueryTemplateTools):
        """Test _build_pattern_filter with empty list."""
        result = tools._build_pattern_filter([])
        assert result == ""

    def test_build_pattern_filter_single_pattern(self, tools: QueryTemplateTools):
        """Test _build_pattern_filter with single pattern."""
        result = tools._build_pattern_filter(["mimikatz"])
        assert "|~" in result
        assert "mimikatz" in result
        assert "(?i)" in result  # case insensitive by default

    def test_build_pattern_filter_case_sensitive(self, tools: QueryTemplateTools):
        """Test _build_pattern_filter with case_insensitive=False."""
        result = tools._build_pattern_filter(["Mimikatz"], case_insensitive=False)
        assert "(?i)" not in result
        assert "Mimikatz" in result
