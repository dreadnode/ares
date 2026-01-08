"""Test Grafana MCP integration."""

import asyncio
import os

from loguru import logger

from ares.tools.blue.grafana import connect_grafana_mcp


async def test_mcp_connection() -> bool:
    """Test connecting to Grafana MCP and listing tools."""
    logger.info("Testing Grafana MCP connection...")

    # Check environment variables
    grafana_url = os.getenv("GRAFANA_URL")
    grafana_api_key = os.getenv("GRAFANA_API_KEY")

    if not grafana_url or not grafana_api_key:
        logger.error("GRAFANA_URL and GRAFANA_API_KEY must be set")
        return False

    logger.info(f"Grafana URL: {grafana_url}")

    try:
        # Connect to MCP server
        mcp_client = await connect_grafana_mcp(
            grafana_url=grafana_url,
            grafana_api_key=grafana_api_key,
        )

        logger.success(f"Connected! {len(mcp_client.tools)} tools available")

        # List all tools
        logger.info("\nAvailable MCP tools:")
        logger.info("=" * 60)
        for tool in mcp_client.tools:
            logger.info(f"  - {tool.name}: {tool.description[:100]}")

        # Try a simple query - list datasources
        logger.info("\nTesting list_datasources...")
        list_datasources_tool = next(
            (t for t in mcp_client.tools if t.name == "list_datasources"),
            None,
        )

        if list_datasources_tool:
            result = await list_datasources_tool.fn()
            logger.success(
                f"Query successful! Found {len(result) if isinstance(result, list) else 'N/A'} datasources"
            )
            if result:
                logger.info(
                    f"First result sample: {result[0] if isinstance(result, list) else result}"
                )
        else:
            logger.warning("list_datasources tool not found")

        # Close connection
        await mcp_client.__aexit__(None, None, None)
        logger.success("Connection closed successfully")

        return True

    except Exception as e:
        logger.error(f"Test failed: {e}")
        import traceback

        traceback.print_exc()
        return False


if __name__ == "__main__":
    import sys

    success = asyncio.run(test_mcp_connection())
    sys.exit(0 if success else 1)
