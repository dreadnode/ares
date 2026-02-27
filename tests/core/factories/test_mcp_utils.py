"""Tests for MCP utility functions."""

from ares.core.factories.mcp_utils import parse_mcp_text_content


class TextContent:
    """Mock MCP TextContent object."""

    def __init__(self, text: str):
        self.text = text


class TestParseMcpTextContent:
    """Tests for parse_mcp_text_content function."""

    def test_single_text_content_with_valid_json(self):
        """Test parsing a single TextContent with valid JSON."""
        content = TextContent('{"line": "test log", "labels": {"app": "myapp"}}')
        result = parse_mcp_text_content(content)
        assert result == {"line": "test log", "labels": {"app": "myapp"}}

    def test_single_text_content_with_invalid_json(self):
        """Test parsing a single TextContent with invalid JSON falls back."""
        content = TextContent("plain text log line")
        result = parse_mcp_text_content(content)
        assert result == [{"line": "plain text log line", "labels": {}}]

    def test_list_of_text_content_with_valid_json(self):
        """Test parsing a list of TextContent objects with valid JSON."""
        contents = [
            TextContent('{"line": "log1", "labels": {"host": "dc01"}}'),
            TextContent('{"line": "log2", "labels": {"host": "dc02"}}'),
        ]
        result = parse_mcp_text_content(contents)
        assert result == [
            {"line": "log1", "labels": {"host": "dc01"}},
            {"line": "log2", "labels": {"host": "dc02"}},
        ]

    def test_list_of_text_content_with_mixed_json(self):
        """Test parsing a list with mixed valid/invalid JSON."""
        contents = [
            TextContent('{"line": "valid", "labels": {}}'),
            TextContent("invalid json"),
        ]
        result = parse_mcp_text_content(contents)
        assert result == [
            {"line": "valid", "labels": {}},
            {"line": "invalid json", "labels": {}},
        ]

    def test_list_with_items_missing_text_attribute(self):
        """Test that items without .text attribute are skipped."""

        class NoText:
            pass

        contents = [TextContent('{"line": "valid", "labels": {}}'), NoText()]
        result = parse_mcp_text_content(contents)
        assert result == [{"line": "valid", "labels": {}}]

    def test_empty_list(self):
        """Test parsing an empty list returns empty list."""
        result = parse_mcp_text_content([])
        assert result == []

    def test_passthrough_non_text_content(self):
        """Test that non-TextContent results pass through unchanged."""
        data = {"already": "parsed"}
        result = parse_mcp_text_content(data)
        assert result == {"already": "parsed"}

    def test_passthrough_string(self):
        """Test that plain strings pass through unchanged."""
        result = parse_mcp_text_content("plain string")
        assert result == "plain string"

    def test_passthrough_none(self):
        """Test that None passes through unchanged."""
        result = parse_mcp_text_content(None)
        assert result is None

    def test_complex_json_structure(self):
        """Test parsing complex nested JSON."""
        content = TextContent('{"values": [[1234567890, "log line"]], "stats": {"bytes": 1024}}')
        result = parse_mcp_text_content(content)
        assert result == {
            "values": [[1234567890, "log line"]],
            "stats": {"bytes": 1024},
        }

    def test_list_with_none_text(self):
        """Test list items where .text is None are skipped."""

        class NoneText:
            text = None

        contents = [TextContent('{"line": "valid", "labels": {}}'), NoneText()]
        result = parse_mcp_text_content(contents)
        assert result == [{"line": "valid", "labels": {}}]
