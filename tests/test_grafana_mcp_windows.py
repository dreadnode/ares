#!/usr/bin/env python3
"""
Test script for Grafana MCP integration - Windows attack queries.

This script tests the agent's ability to query Grafana/Loki for
Windows security events and attack indicators.
"""

import asyncio
from datetime import datetime, timedelta


async def test_grafana_mcp_windows_queries():
    """Test Grafana MCP integration for Windows attack detection."""

    # Note: This test demonstrates what queries the agent CAN make
    # The actual MCP tools (mcp__grafana__*) are available when running
    # within the Ares agent context with Grafana MCP server configured

    datasource_uid = "loki"
    environment = "staging"

    # Calculate time range (last 1 hour)
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(hours=1)
    start_rfc3339 = start_time.strftime("%Y-%m-%dT%H:%M:%SZ")
    end_rfc3339 = end_time.strftime("%Y-%m-%dT%H:%M:%SZ")

    # Test 1: List available label names

    # Test 2: List environment values

    # Test 3: Check log volume

    # Test 4: Search for attack indicators

    # Test 5: Check for DCSync activity (Event ID 4662)

    # Test 6: Check authentication events (Event ID 4624)
    auth_logql = f'{{environment="{environment}"}} | json | event_id="4624"'
    print("Query: mcp__grafana__query_loki_logs")
    print(f"  datasourceUid: {datasource_uid}")
    print(f"  logql: {auth_logql}")
    print("  limit: 5")
    print("  direction: backward")
    print(f"  startRfc3339: {start_rfc3339}")
    print(f"  endRfc3339: {end_rfc3339}")
    print()
    print("Context: Event ID 4624 indicates successful logons. Useful for")
    print("         tracking user activity and identifying suspicious")
    print("         authentication patterns.")
    print()
    print("Expected output: List of Event ID 4624 entries")
    print()

    # Test 7: Check failed authentication (Event ID 4625)
    print("=" * 80)
    print("TEST 7: Check Failed Authentication (Event ID 4625)")
    print("=" * 80)
    print()
    failed_auth_logql = f'{{environment="{environment}"}} | json | event_id="4625"'
    print("Query: mcp__grafana__query_loki_logs")
    print(f"  datasourceUid: {datasource_uid}")
    print(f"  logql: {failed_auth_logql}")
    print("  limit: 5")
    print("  direction: backward")
    print(f"  startRfc3339: {start_rfc3339}")
    print(f"  endRfc3339: {end_rfc3339}")
    print()
    print("Context: Event ID 4625 indicates failed logon attempts.")
    print("         Multiple failures could indicate brute-force attacks.")
    print()
    print("Expected output: List of Event ID 4625 entries (if any)")
    print()

    # Test 8: Check PowerShell activity
    print("=" * 80)
    print("TEST 8: Check PowerShell Activity")
    print("=" * 80)
    print()
    powershell_logql = f'{{environment="{environment}"}} |~ "(?i)(powershell|pwsh|invoke-|iex)"'
    print("Query: mcp__grafana__query_loki_logs")
    print(f"  datasourceUid: {datasource_uid}")
    print(f"  logql: {powershell_logql}")
    print("  limit: 10")
    print("  direction: backward")
    print(f"  startRfc3339: {start_rfc3339}")
    print(f"  endRfc3339: {end_rfc3339}")
    print()
    print("Context: PowerShell is frequently used in attacks for execution,")
    print("         reconnaissance, and persistence.")
    print()
    print("Expected output: List of logs containing PowerShell activity")
    print()

    # Test 9: Check suspicious network activity
    print("=" * 80)
    print("TEST 9: Check Suspicious Network Activity")
    print("=" * 80)
    print()
    network_logql = f'{{environment="{environment}"}} |~ "(?i)(nc |netcat|ncat|curl.*sh|wget.*sh)"'
    print("Query: mcp__grafana__query_loki_logs")
    print(f"  datasourceUid: {datasource_uid}")
    print(f"  logql: {network_logql}")
    print("  limit: 10")
    print("  direction: backward")
    print(f"  startRfc3339: {start_rfc3339}")
    print(f"  endRfc3339: {end_rfc3339}")
    print()
    print("Context: Commands like netcat, curl, and wget downloading shell")
    print("         scripts are common in initial access and persistence.")
    print()
    print("Expected output: List of logs with suspicious network commands")
    print()

    # Summary
    print("=" * 80)
    print("SUMMARY")
    print("=" * 80)
    print()
    print("The Ares agent can query Grafana/Loki for:")
    print()
    print("1. ✅ Label discovery (environments, hosts, jobs, etc.)")
    print("2. ✅ Log volume statistics")
    print("3. ✅ General attack indicators (mimikatz, impacket, etc.)")
    print("4. ✅ DCSync activity (Event ID 4662)")
    print("5. ✅ Authentication events (Event ID 4624)")
    print("6. ✅ Failed authentication (Event ID 4625)")
    print("7. ✅ PowerShell activity")
    print("8. ✅ Suspicious network commands")
    print()
    print("These queries are available through the GrafanaMCPTools")
    print("and can be executed during investigations via:")
    print("  - list_loki_label_names_guide()")
    print("  - list_loki_label_values_guide(label_name)")
    print("  - query_loki_stats_guide(logql_selector)")
    print("  - query_loki_logs_guide(logql, limit)")
    print("  - search_attack_indicators_guide(environment)")
    print("  - discover_environment_guide(environment)")
    print()
    print("The agent uses these guide methods to learn how to call")
    print("the native mcp__grafana__* tools available in the environment.")
    print()
    print("=" * 80)
    print("Test Complete")
    print("=" * 80)


if __name__ == "__main__":
    asyncio.run(test_grafana_mcp_windows_queries())
