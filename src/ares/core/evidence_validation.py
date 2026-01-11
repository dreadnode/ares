"""Evidence validation and IOC extraction for investigation integrity.

This module provides:
1. Storage for recent query results (for evidence provenance)
2. Validation of evidence values against query results
3. Auto-extraction of IOCs from query results
"""

import re
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from loguru import logger

# Maximum number of query results to store for validation
MAX_STORED_RESULTS = 10

# Confidence penalty for unvalidated evidence
UNVALIDATED_CONFIDENCE_PENALTY = 0.3


@dataclass
class StoredQueryResult:
    """A stored query result for evidence validation."""

    query_id: str
    query_type: str  # e.g., "query_loki_logs", "query_prometheus"
    query_string: str
    timestamp: datetime
    result_data: Any  # The actual result (list, dict, or string)
    result_count: int
    extracted_values: set[str] = field(default_factory=set)  # Pre-extracted searchable values


# Global storage for recent query results
_recent_results: deque[StoredQueryResult] = deque(maxlen=MAX_STORED_RESULTS)
_query_counter = 0


def reset_evidence_validation():
    """Reset evidence validation state for a new investigation."""
    global _recent_results, _query_counter
    _recent_results = deque(maxlen=MAX_STORED_RESULTS)
    _query_counter = 0


def store_query_result(
    query_type: str,
    query_string: str,
    result_data: Any,
    result_count: int,
) -> str:
    """Store a query result for evidence validation.

    Args:
        query_type: Type of query (e.g., "query_loki_logs")
        query_string: The query string executed
        result_data: The actual result data
        result_count: Number of results returned

    Returns:
        Query ID for reference
    """
    global _query_counter
    _query_counter += 1
    query_id = f"q-{_query_counter:04d}"

    # Extract searchable values from results
    extracted = _extract_searchable_values(result_data)

    stored = StoredQueryResult(
        query_id=query_id,
        query_type=query_type,
        query_string=query_string,
        timestamp=datetime.now(timezone.utc),
        result_data=result_data,
        result_count=result_count,
        extracted_values=extracted,
    )

    _recent_results.append(stored)
    logger.debug(f"Stored query result {query_id} with {len(extracted)} extracted values")

    return query_id


def _extract_searchable_values(data: Any, depth: int = 0) -> set[str]:
    """Recursively extract searchable string values from query results.

    Extracts IPs, hostnames, usernames, and other IOC-like values.

    Args:
        data: Data to extract from (dict, list, or primitive)
        depth: Current recursion depth (to prevent infinite recursion)

    Returns:
        Set of extracted string values
    """
    if depth > 10:  # Prevent infinite recursion
        return set()

    values: set[str] = set()

    if isinstance(data, str):
        # Add the string itself if it looks like an IOC
        if data and len(data) < 500:  # Skip very long strings
            values.add(data.lower())
            # Also extract embedded patterns
            values.update(_extract_patterns_from_string(data))
    elif isinstance(data, dict):
        for val in data.values():
            # Add key-value pairs for common fields
            if isinstance(val, str) and val:
                values.add(val.lower())
                values.update(_extract_patterns_from_string(val))
            elif isinstance(val, (dict, list)):
                values.update(_extract_searchable_values(val, depth + 1))
    elif isinstance(data, list):
        for item in data:
            values.update(_extract_searchable_values(item, depth + 1))

    return values


def _extract_patterns_from_string(text: str) -> set[str]:
    """Extract IOC patterns from a string.

    Args:
        text: Text to extract patterns from

    Returns:
        Set of extracted patterns (IPs, hostnames, etc.)
    """
    patterns: set[str] = set()

    # IP addresses
    ip_pattern = r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b"
    for match in re.findall(ip_pattern, text):
        patterns.add(match.lower())

    # Hostnames/FQDNs
    hostname_pattern = r"\b([a-zA-Z0-9][-a-zA-Z0-9]*\.[-a-zA-Z0-9.]+)\b"
    for match in re.findall(hostname_pattern, text):
        if "." in match and not match[0].isdigit():
            patterns.add(match.lower())

    # Windows usernames (domain\user or user@domain)
    user_patterns = [
        r"\b([a-zA-Z0-9_-]+\\[a-zA-Z0-9_.-]+)\b",  # domain\user
        r"\b([a-zA-Z0-9_.-]+@[a-zA-Z0-9.-]+)\b",  # user@domain
    ]
    for pattern in user_patterns:
        for match in re.findall(pattern, text):
            patterns.add(match.lower())

    # Simple usernames (from common fields)
    simple_user = r'"(?:user|username|account|TargetUserName|SubjectUserName)":\s*"([^"]+)"'
    for match in re.findall(simple_user, text, re.IGNORECASE):
        patterns.add(match.lower())

    return patterns


def validate_evidence_value(value: str) -> tuple[bool, str | None]:
    """Validate an evidence value against recent query results.

    Args:
        value: The evidence value to validate

    Returns:
        Tuple of (is_validated, source_query_id)
    """
    if not value:
        return False, None

    normalized_value = value.lower().strip()

    # Search through recent results
    for stored in reversed(_recent_results):  # Most recent first
        # Check if value appears in extracted values
        if normalized_value in stored.extracted_values:
            logger.info(f"Evidence '{value[:50]}...' validated against query {stored.query_id}")
            return True, stored.query_id

        # Also do a substring search in extracted values for partial matches
        for extracted in stored.extracted_values:
            if normalized_value in extracted or extracted in normalized_value:
                logger.info(
                    f"Evidence '{value[:50]}...' partially validated against query {stored.query_id}"
                )
                return True, stored.query_id

    logger.warning(f"Evidence '{value[:50]}...' could not be validated against recent queries")
    return False, None


def get_suggested_iocs() -> list[dict]:
    """Extract and return suggested IOCs from recent query results.

    Returns:
        List of suggested IOCs with type, value, and source query ID
    """
    suggestions: list[dict] = []
    seen_values: set[str] = set()

    for stored in reversed(_recent_results):  # Most recent first
        for value in stored.extracted_values:
            if value in seen_values:
                continue
            seen_values.add(value)

            ioc_type = _classify_ioc(value)
            if ioc_type:
                suggestions.append(
                    {
                        "type": ioc_type,
                        "value": value,
                        "source_query_id": stored.query_id,
                    }
                )

    return suggestions[:50]  # Limit to 50 suggestions


def _classify_ioc(value: str) -> str | None:
    """Classify an IOC value by type.

    Args:
        value: The value to classify

    Returns:
        IOC type or None if not classifiable
    """
    # IP address
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", value):
        return "ip"

    # Domain/hostname
    if re.match(r"^[a-z0-9][-a-z0-9]*\.[a-z0-9][-a-z0-9.]+$", value) and not value[0].isdigit():
        return "hostname"

    # Username patterns
    if "\\" in value or "@" in value:
        return "user"

    # Hash patterns
    if re.match(r"^[a-f0-9]{32}$", value):
        return "hash"  # MD5
    if re.match(r"^[a-f0-9]{40}$", value):
        return "hash"  # SHA1
    if re.match(r"^[a-f0-9]{64}$", value):
        return "hash"  # SHA256

    return None


def adjust_confidence_for_validation(
    confidence: float,
    validated: bool,
) -> float:
    """Adjust confidence score based on validation status.

    Args:
        confidence: Original confidence score
        validated: Whether evidence was validated

    Returns:
        Adjusted confidence score
    """
    if validated:
        return confidence
    # Apply penalty for unvalidated evidence
    return max(0.1, confidence - UNVALIDATED_CONFIDENCE_PENALTY)


def get_recent_query_ids() -> list[str]:
    """Get list of recent query IDs for reference.

    Returns:
        List of query IDs from most recent to oldest
    """
    return [stored.query_id for stored in reversed(_recent_results)]
