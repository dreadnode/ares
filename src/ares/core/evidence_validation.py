"""Evidence validation and IOC extraction for investigation integrity.

This module provides:
1. Storage for recent query results (for evidence provenance)
2. Validation of evidence values against query results
3. Auto-extraction of IOCs from query results
4. Optional Redis persistence for crash recovery
"""

import asyncio
import json
import re
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from loguru import logger

from ares.core.config import get_max_stored_results, get_unvalidated_confidence_penalty

if TYPE_CHECKING:
    from redis.asyncio import Redis


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
_recent_results: deque[StoredQueryResult] = deque(maxlen=get_max_stored_results())
_query_counter = 0

# Redis backing for persistence
# Automatically used when set via set_redis_client() - typically called by
# the orchestrator/dispatcher during initialization for crash recovery.
# Falls back to in-memory only when Redis is not configured (e.g., standalone CLI).
_redis_client: "Redis | None" = None
_operation_id: str = ""
_background_tasks: set = set()

# Redis key constants
_REDIS_KEY_PREFIX = "ares:evidence"
_REDIS_TTL = 86400  # 24 hours


def set_redis_client(client: "Redis", operation_id: str) -> None:
    """Set Redis client for evidence validation persistence.

    Called by the orchestrator/dispatcher during initialization to enable
    Redis-backed persistence for crash recovery. When set, all query results
    are automatically persisted to Redis in addition to in-memory storage.

    Args:
        client: Async Redis client
        operation_id: Current operation ID for namespacing
    """
    global _redis_client, _operation_id
    _redis_client = client
    _operation_id = operation_id
    logger.info(f"Evidence validation Redis persistence enabled for {operation_id}")


def _get_redis_key() -> str:
    """Get Redis key for current operation."""
    return f"{_REDIS_KEY_PREFIX}:{_operation_id}:results"


def _serialize_query_result(result: StoredQueryResult) -> str:
    """Serialize a StoredQueryResult to JSON string."""
    return json.dumps(
        {
            "query_id": result.query_id,
            "query_type": result.query_type,
            "query_string": result.query_string,
            "timestamp": result.timestamp.isoformat(),
            "result_data": result.result_data,
            "result_count": result.result_count,
            "extracted_values": list(result.extracted_values),
        },
        separators=(",", ":"),
        default=str,
    )


def _deserialize_query_result(data: str | bytes) -> StoredQueryResult:
    """Deserialize a StoredQueryResult from JSON string."""
    if isinstance(data, bytes):
        data = data.decode()
    d = json.loads(data)
    return StoredQueryResult(
        query_id=d.get("query_id", ""),
        query_type=d.get("query_type", ""),
        query_string=d.get("query_string", ""),
        timestamp=datetime.fromisoformat(d["timestamp"])
        if d.get("timestamp")
        else datetime.now(timezone.utc),
        result_data=d.get("result_data"),
        result_count=d.get("result_count", 0),
        extracted_values=set(d.get("extracted_values", [])),
    )


async def _persist_to_redis(result: StoredQueryResult) -> None:
    """Persist a query result to Redis (async background task)."""
    if not _redis_client or not _operation_id:
        return

    try:
        key = _get_redis_key()
        data = _serialize_query_result(result)
        # Use ZADD with timestamp as score for time-ordered storage
        score = result.timestamp.timestamp()
        await _redis_client.zadd(key, {data: score})
        await _redis_client.expire(key, _REDIS_TTL)

        # Trim to max size (keep most recent N entries)
        max_size = get_max_stored_results()
        count = await _redis_client.zcard(key)
        if count > max_size:
            # Remove oldest entries (lowest scores)
            await _redis_client.zremrangebyrank(key, 0, count - max_size - 1)

        logger.debug(f"Persisted query result {result.query_id} to Redis")
    except Exception as e:
        logger.warning(f"Failed to persist query result to Redis: {e}")


async def load_from_redis() -> int:
    """Load query results from Redis into memory.

    Returns:
        Number of results loaded
    """
    global _query_counter

    if not _redis_client or not _operation_id:
        return 0

    try:
        key = _get_redis_key()
        # Get all entries ordered by timestamp (score)
        items = await _redis_client.zrange(key, 0, -1)

        loaded = 0
        max_query_num = 0
        for item in items:
            try:
                result = _deserialize_query_result(item)
                _recent_results.append(result)
                loaded += 1

                # Track highest query number for counter
                if result.query_id.startswith("q-"):
                    try:
                        num = int(result.query_id[2:])
                        max_query_num = max(max_query_num, num)
                    except ValueError:
                        pass
            except Exception as e:  # noqa: PERF203 - need per-item exception handling
                logger.warning(f"Failed to deserialize query result: {e}")

        # Restore query counter
        _query_counter = max(_query_counter, max_query_num)

        if loaded > 0:
            logger.info(f"Loaded {loaded} query results from Redis (counter at {_query_counter})")
        return loaded
    except Exception as e:
        logger.warning(f"Failed to load query results from Redis: {e}")
        return 0


def reset_evidence_validation():
    """Reset evidence validation state for a new investigation."""
    global _recent_results, _query_counter
    _recent_results = deque(maxlen=get_max_stored_results())
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

    # Persist to Redis if available (async background task)
    if _redis_client and _operation_id:
        try:
            loop = asyncio.get_running_loop()
            task = loop.create_task(_persist_to_redis(stored))
            _background_tasks.add(task)
            task.add_done_callback(_background_tasks.discard)
        except RuntimeError:
            pass  # No event loop running

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
        if data and len(data) < 500:
            values.add(data.lower())
            # Also extract embedded patterns
            values.update(_extract_patterns_from_string(data))
    elif isinstance(data, dict):
        for val in data.values():
            if isinstance(val, str) and val:
                values.add(val.lower())
                values.update(_extract_patterns_from_string(val))
            elif isinstance(val, (dict, list)):
                values.update(_extract_searchable_values(val, depth + 1))
    elif isinstance(data, list):
        for item in data:
            values.update(_extract_searchable_values(item, depth + 1))

    return values


def _extract_patterns_from_string(text: str) -> set[str]:  # noqa: PLR0912
    """Extract IOC patterns from a string.

    Args:
        text: Text to extract patterns from

    Returns:
        Set of extracted patterns (IPs, hostnames, users, hashes, etc.)
    """
    patterns: set[str] = set()

    # IP addresses (IPv4)
    ip_pattern = r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b"
    for match in re.findall(ip_pattern, text):
        patterns.add(match.lower())

    # Hostnames/FQDNs
    hostname_pattern = r"\b([a-zA-Z0-9][-a-zA-Z0-9]*\.[-a-zA-Z0-9.]+)\b"
    for match in re.findall(hostname_pattern, text):
        if "." in match and not match[0].isdigit():
            patterns.add(match.lower())

    # Windows usernames (multiple formats)
    user_patterns = [
        r"\b([a-zA-Z0-9_-]+\\[a-zA-Z0-9_.-]+)\b",  # domain\user
        r"\b([a-zA-Z0-9_.-]+@[a-zA-Z0-9.-]+)\b",  # user@domain
    ]
    for pattern in user_patterns:
        for match in re.findall(pattern, text):
            if match and len(match) > 2:
                patterns.add(match.lower())

    # Usernames from JSON fields (expanded list)
    user_json_patterns = [
        r'"(?:TargetUserName|SubjectUserName|User|Account|AccountName|UserName)":\s*"([^"]+)"',
        r"(?:TargetUserName|SubjectUserName|User|Account)=([^\s,;}\]]+)",
    ]
    for pattern in user_json_patterns:
        for match in re.findall(pattern, text, re.IGNORECASE):
            if match and len(match) > 1 and match not in ("-", "SYSTEM", "LOCAL SERVICE"):
                patterns.add(match.lower())

    # Computer names from Windows events
    computer_patterns = [
        r'"(?:Computer|WorkstationName|Workstation|ComputerName|HostName)":\s*"([^"]+)"',
        r"(?:Computer|WorkstationName|HostName)=([^\s,;}\]]+)",
    ]
    for pattern in computer_patterns:
        for match in re.findall(pattern, text, re.IGNORECASE):
            if match and len(match) > 1:
                patterns.add(match.lower())

    process_patterns = [
        r'"(?:ProcessName|NewProcessName|ParentProcessName|Image)":\s*"([^"]+)"',
        r"(?:ProcessName|Process)=([^\s,;}\]]+)",
    ]
    for pattern in process_patterns:
        for match in re.findall(pattern, text, re.IGNORECASE):
            if match and (".exe" in match.lower() or ".dll" in match.lower()):
                patterns.add(match.lower())

    # Service names
    service_patterns = [
        r'"(?:ServiceName|Service)":\s*"([^"]+)"',
        r"ServiceName=([^\s,;}\]]+)",
    ]
    for pattern in service_patterns:
        for match in re.findall(pattern, text, re.IGNORECASE):
            if match and len(match) > 1:
                patterns.add(match.lower())

    # Hash values (MD5, SHA1, SHA256)
    hash_patterns = [
        (r"\b([a-fA-F0-9]{32})\b", "md5"),  # MD5
        (r"\b([a-fA-F0-9]{40})\b", "sha1"),  # SHA1
        (r"\b([a-fA-F0-9]{64})\b", "sha256"),  # SHA256
    ]
    for pattern, _ in hash_patterns:
        for match in re.findall(pattern, text):
            patterns.add(match.lower())

    return patterns


def _is_mitre_technique_description(value: str) -> bool:
    """Check if value is a MITRE technique description that shouldn't be validated.

    MITRE technique descriptions (e.g., "T1003.006 - DCSync") don't appear in
    query results, so they cannot be validated and should be skipped.

    Args:
        value: The evidence value to check

    Returns:
        True if value looks like a MITRE technique description
    """
    # Match patterns like "T1003", "T1003.006", "T1003.006 - DCSync", etc.
    mitre_pattern = r"^T\d{4}(\.\d{3})?\s*(-\s*.+)?$"
    return bool(re.match(mitre_pattern, value.strip(), re.IGNORECASE))


def validate_evidence_value(value: str) -> tuple[bool, str | None]:
    """Validate an evidence value against recent query results.

    Args:
        value: The evidence value to validate

    Returns:
        Tuple of (is_validated, source_query_id)
    """
    if not value:
        return False, None

    if _is_mitre_technique_description(value):
        logger.debug(f"Skipping validation for MITRE technique: {value}")
        return True, None

    normalized_value = value.lower().strip()

    for stored in reversed(_recent_results):
        # Exact match only
        if normalized_value in stored.extracted_values:
            logger.info(f"Evidence '{value[:50]}...' validated against query {stored.query_id}")
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
    return max(0.1, confidence - get_unvalidated_confidence_penalty())


def get_recent_query_ids() -> list[str]:
    """Get list of recent query IDs for reference.

    Returns:
        List of query IDs from most recent to oldest
    """
    return [stored.query_id for stored in reversed(_recent_results)]


def boost_confidence_for_quality(
    evidence_type: str,
    pyramid_level: int,
    has_timestamp: bool,
    has_mitre_mapping: bool,
) -> float:
    """Calculate confidence boost for high-quality evidence.

    Args:
        evidence_type: Type of evidence (ip, user, hostname, etc.)
        pyramid_level: Pyramid of Pain level (1-6)
        has_timestamp: Whether evidence has a timestamp
        has_mitre_mapping: Whether evidence has MITRE technique mapping

    Returns:
        Additional confidence (0.0 to 0.2) based on evidence quality
    """
    boost = 0.0

    # Higher pyramid levels are more valuable
    if pyramid_level >= 5:
        boost += 0.1
    elif pyramid_level >= 4:
        boost += 0.05

    # Evidence with timestamps is more reliable
    if has_timestamp:
        boost += 0.05

    # MITRE mapping shows understanding
    if has_mitre_mapping:
        boost += 0.05

    return min(boost, 0.2)


def auto_extract_evidence_from_query(
    query_result: Any,
    source_description: str,
    mitre_technique: str | None = None,
) -> list[dict]:
    """Automatically extract IOCs from query results as evidence candidates.

    This function extracts potential evidence items from query results
    without requiring manual parsing by the LLM.

    Args:
        query_result: Raw query result data
        source_description: Description of the query source
        mitre_technique: Optional MITRE technique ID

    Returns:
        List of evidence dicts with type, value, pyramid_level, and confidence
    """
    evidence_items: list[dict] = []
    seen_values: set[str] = set()

    extracted = _extract_searchable_values(query_result)

    for value in extracted:
        if value in seen_values:
            continue
        seen_values.add(value)

        # Skip very short values
        if len(value) < 3:
            continue

        ioc_type = _classify_ioc(value)
        if not ioc_type:
            continue

        # Map IOC type to pyramid level
        pyramid_map = {
            "hash": 1,
            "ip": 2,
            "hostname": 3,
            "user": 4,
            "process": 4,
            "service": 5,
        }
        pyramid_level = pyramid_map.get(ioc_type, 3)

        # Calculate confidence with quality boost
        base_confidence = 0.7  # Auto-extracted gets 0.7 base confidence
        boost = boost_confidence_for_quality(
            evidence_type=ioc_type,
            pyramid_level=pyramid_level,
            has_timestamp=False,  # Auto-extracted doesn't have precise timestamps
            has_mitre_mapping=mitre_technique is not None,
        )
        confidence = min(base_confidence + boost, 0.95)

        evidence_items.append(
            {
                "type": ioc_type,
                "value": value,
                "source": f"Auto-extracted: {source_description[:100]}",
                "pyramid_level": pyramid_level,
                "confidence": confidence,
                "mitre_techniques": [mitre_technique] if mitre_technique else [],
                "validated": True,  # Auto-extracted is inherently validated
            }
        )

    # Limit to prevent overwhelming the investigation
    return evidence_items[:20]
