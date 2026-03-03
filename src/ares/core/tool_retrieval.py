"""
Semantic tool retrieval for reducing LLM tool overhead.

Uses sentence-transformers to embed tool descriptions and retrieve
only the most relevant tools for a given alert context. This reduces
the 79+ tools to 10-15 relevant ones, improving LLM performance.
"""

import functools
from typing import Any

from loguru import logger

# Lazy-load sentence-transformers to avoid slow import on startup
_model = None
_tool_embeddings: dict[str, Any] = {}


def _get_model():
    """Lazy-load the sentence transformer model."""
    global _model
    if _model is None:
        try:
            from sentence_transformers import SentenceTransformer

            # Use a small, fast model optimized for semantic similarity
            _model = SentenceTransformer("all-MiniLM-L6-v2")
            logger.info("Loaded sentence-transformers model for tool retrieval")
        except ImportError:
            logger.warning(
                "sentence-transformers not installed. "
                "Tool filtering will use keyword matching instead."
            )
            _model = False  # Mark as unavailable
    return _model if _model is not False else None


# Tool descriptions for semantic matching
# Maps tool method names to rich descriptions for embedding
TOOL_DESCRIPTIONS: dict[str, str] = {
    # Reconnaissance
    "detect_port_scanning": "Detect network port scanning reconnaissance nmap scan probing services",
    "detect_user_enumeration": "Detect Active Directory user enumeration LDAP queries net user domain users",
    "detect_share_enumeration": "Detect SMB share enumeration network shares file shares net share",
    # Credential Access
    "detect_secretsdump": "Detect secretsdump credential dumping NTLM hashes SAM LSA secrets password extraction",  # pragma: allowlist secret
    "detect_dcsync": "Detect DCSync domain controller replication attack credential theft DRSUAPI",
    "detect_kerberoasting": "Detect Kerberoasting attack TGS request service ticket SPN hash cracking",
    "detect_asrep_roasting": "Detect AS-REP roasting attack pre-authentication disabled Kerberos",
    "detect_asrep_roasting_bulk": "Detect bulk AS-REP roasting spray attack multiple TGT requests GetNPUsers",
    "detect_brute_force": "Detect brute force password attack failed login attempts authentication",
    "detect_pass_the_hash": "Detect pass-the-hash attack NTLM authentication lateral movement",  # nosec B105
    "detect_golden_ticket": "Detect golden ticket attack Kerberos TGT forged ticket persistence",
    # Lateral Movement
    "detect_lateral_movement": "Detect lateral movement remote access network logon type 3 remote execution",
    "detect_smb_file_access": "Detect SMB file access share access network file operations",
    "detect_impacket_wmiexec": "Detect Impacket WMIExec remote execution WMI command execution",
    "detect_impacket_psexec": "Detect Impacket PSExec remote execution service creation PSEXESVC",
    "detect_impacket_smbexec": "Detect Impacket SMBExec remote execution SMB command execution",
    "detect_impacket_atexec": "Detect Impacket ATExec scheduled task remote execution",
    "detect_impacket_dcomexec": "Detect Impacket DCOMExec DCOM remote execution MMC20",
    "detect_impacket_ntlmrelayx": "Detect NTLM relay attack ntlmrelayx credential relay SMB HTTP",
    "detect_impacket_smbclient": "Detect Impacket SMBClient file transfer SMB access",
    # Credential Theft
    "detect_impacket_secretsdump_sam": "Detect SAM database dump local credential extraction",  # pragma: allowlist secret
    "detect_impacket_secretsdump_lsa": "Detect LSA secrets dump credential extraction cached",  # pragma: allowlist secret
    "detect_s4u_delegation": "Detect S4U constrained delegation abuse Kerberos impersonation",
    "detect_dcsync_replication": "Detect domain replication DCSync directory replication DRSUAPI 4662",
    "detect_lsa_secrets_access": "Detect LSA secrets access credential theft LSASS memory",  # pragma: allowlist secret
    "detect_remote_registry_start": "Detect remote registry service start credential access",
    # ADCS Attacks
    "detect_adcs_exploitation": "Detect ADCS certificate services exploitation PKI attack",
    "detect_certipy_enumeration": "Detect Certipy AD CS enumeration certificate template analysis",
    "detect_esc1_attack": "Detect ESC1 certificate template attack misconfigured enrollment",
    "detect_esc4_attack": "Detect ESC4 certificate template modification attack ACL",
    "detect_esc8_attack": "Detect ESC8 NTLM relay to ADCS web enrollment HTTP relay",
    "detect_certificate_authentication": "Detect certificate-based authentication PKINIT Kerberos",
    # Privilege Escalation
    "detect_delegation_abuse": "Detect Kerberos delegation abuse unconstrained constrained S4U",
    "detect_suspicious_execution": "Detect suspicious process execution command line malicious",
    # BloodHound Collection
    "detect_bloodhound_collection": "Detect BloodHound data collection AD enumeration SharpHound",
    "detect_bloodhound_domain_enum": "Detect BloodHound domain enumeration domain trust LDAP",
    "detect_bloodhound_acl_enum": "Detect BloodHound ACL enumeration permissions DACL analysis",
    "detect_bloodhound_session_enum": "Detect BloodHound session enumeration logged on users",
    "detect_bloodhound_gpo_enum": "Detect BloodHound GPO enumeration group policy analysis",
    "detect_bloodhound_computer_enum": "Detect BloodHound computer enumeration domain computers",
    # Generic Activity
    "get_host_activity": "Get all activity for a specific host machine computer logs",
    "get_user_activity": "Get all activity for a specific user account login authentication",
    "list_query_templates": "List all available query templates detection methods MITRE",
}

# Keyword-based fallback mapping for when embeddings aren't available
KEYWORD_MAPPING: dict[str, list[str]] = {
    # Alert name patterns -> relevant tool names
    "dcsync": [
        "detect_dcsync",
        "detect_dcsync_replication",
        "detect_pass_the_hash",
        "detect_lateral_movement",
    ],
    "kerberoast": ["detect_kerberoasting", "detect_pass_the_hash", "detect_lateral_movement"],
    "asrep": ["detect_asrep_roasting", "detect_asrep_roasting_bulk", "detect_brute_force"],
    "pass.the.hash": ["detect_pass_the_hash", "detect_lateral_movement", "detect_impacket_psexec"],
    "pth": ["detect_pass_the_hash", "detect_lateral_movement", "detect_impacket_psexec"],
    "lateral": [
        "detect_lateral_movement",
        "detect_impacket_psexec",
        "detect_impacket_wmiexec",
        "detect_smb_file_access",
    ],
    "psexec": ["detect_impacket_psexec", "detect_lateral_movement", "detect_service_creation"],
    "wmi": ["detect_impacket_wmiexec", "detect_lateral_movement", "detect_suspicious_execution"],
    "smb": ["detect_smb_file_access", "detect_impacket_smbexec", "detect_lateral_movement"],
    "adcs": [
        "detect_adcs_exploitation",
        "detect_certipy_enumeration",
        "detect_esc1_attack",
        "detect_esc4_attack",
        "detect_esc8_attack",
    ],
    "certificate": [
        "detect_adcs_exploitation",
        "detect_certificate_authentication",
        "detect_esc1_attack",
    ],
    "certipy": [
        "detect_certipy_enumeration",
        "detect_esc1_attack",
        "detect_esc4_attack",
        "detect_esc8_attack",
    ],
    "golden.ticket": ["detect_golden_ticket", "detect_dcsync", "detect_lateral_movement"],
    "bloodhound": [
        "detect_bloodhound_collection",
        "detect_bloodhound_domain_enum",
        "detect_bloodhound_acl_enum",
    ],
    "recon": ["detect_port_scanning", "detect_user_enumeration", "detect_share_enumeration"],
    "enumeration": [
        "detect_user_enumeration",
        "detect_share_enumeration",
        "detect_bloodhound_domain_enum",
    ],
    "brute": ["detect_brute_force", "detect_pass_the_hash"],
    "ntlm": ["detect_pass_the_hash", "detect_impacket_ntlmrelayx", "detect_lateral_movement"],
    "relay": ["detect_impacket_ntlmrelayx", "detect_esc8_attack"],
    "secretsdump": [
        "detect_secretsdump",
        "detect_impacket_secretsdump_sam",
        "detect_impacket_secretsdump_lsa",
    ],
    "credential": [
        "detect_secretsdump",
        "detect_pass_the_hash",
        "detect_kerberoasting",
        "detect_lsa_secrets_access",
    ],
    "delegation": ["detect_delegation_abuse", "detect_s4u_delegation"],
}

# MITRE technique -> relevant tools mapping
MITRE_TOOL_MAPPING: dict[str, list[str]] = {
    "T1003": ["detect_secretsdump", "detect_dcsync", "detect_lsa_secrets_access"],
    "T1003.001": ["detect_lsa_secrets_access", "detect_secretsdump"],
    "T1003.002": ["detect_impacket_secretsdump_sam", "detect_secretsdump"],
    "T1003.003": ["detect_impacket_secretsdump_lsa", "detect_lsa_secrets_access"],
    "T1003.006": ["detect_dcsync", "detect_dcsync_replication"],
    "T1046": ["detect_port_scanning"],
    "T1087": ["detect_user_enumeration", "detect_bloodhound_domain_enum"],
    "T1087.002": ["detect_user_enumeration", "detect_bloodhound_domain_enum"],
    "T1110": ["detect_brute_force"],
    "T1135": ["detect_share_enumeration", "detect_smb_file_access"],
    "T1550": ["detect_pass_the_hash", "detect_golden_ticket"],
    "T1550.002": ["detect_pass_the_hash"],
    "T1558": [
        "detect_kerberoasting",
        "detect_asrep_roasting",
        "detect_asrep_roasting_bulk",
        "detect_golden_ticket",
    ],
    "T1558.001": ["detect_golden_ticket"],
    "T1558.003": ["detect_kerberoasting"],
    "T1558.004": ["detect_asrep_roasting", "detect_asrep_roasting_bulk"],
    "T1021": ["detect_lateral_movement", "detect_smb_file_access"],
    "T1021.002": ["detect_smb_file_access", "detect_impacket_smbclient"],
    "T1569": ["detect_impacket_psexec", "detect_service_creation"],
    "T1569.002": ["detect_impacket_psexec"],
    "T1047": ["detect_impacket_wmiexec"],
    "T1649": ["detect_adcs_exploitation", "detect_certificate_authentication"],
    "T1484": ["detect_delegation_abuse", "detect_s4u_delegation"],
}

# Essential tools that should always be included
ESSENTIAL_TOOLS = [
    "detect_lateral_movement",  # Core for any investigation
    "detect_suspicious_execution",  # Catch-all for malicious activity
    "get_host_activity",  # Generic host investigation
    "get_user_activity",  # Generic user investigation
    "list_query_templates",  # Discovery
]


@functools.lru_cache(maxsize=128)
def _embed_text(text: str) -> Any:
    """Embed text using sentence-transformers (cached)."""
    model = _get_model()
    if model is None:
        return None
    return model.encode(text, convert_to_tensor=False)


def _compute_tool_embeddings() -> None:
    """Pre-compute embeddings for all tool descriptions."""
    model = _get_model()
    if model is None:
        return

    if _tool_embeddings:
        return  # Already computed

    for tool_name, description in TOOL_DESCRIPTIONS.items():
        _tool_embeddings[tool_name] = model.encode(description, convert_to_tensor=False)

    logger.info(f"Computed embeddings for {len(_tool_embeddings)} tools")


def get_relevant_tools_semantic(
    alert_context: str,
    all_tools: list[Any],
    top_k: int = 10,
) -> list[Any]:
    """Get relevant tools using semantic similarity.

    Args:
        alert_context: Alert name, description, and any MITRE techniques
        all_tools: Full list of available tools
        top_k: Number of top matching tools to return

    Returns:
        Filtered list of most relevant tools
    """
    try:
        from sklearn.metrics.pairwise import cosine_similarity
    except ImportError:
        logger.warning("sklearn not available, falling back to keyword matching")
        return get_relevant_tools_keyword(alert_context, all_tools, top_k)

    model = _get_model()
    if model is None:
        return get_relevant_tools_keyword(alert_context, all_tools, top_k)

    # Ensure tool embeddings are computed
    _compute_tool_embeddings()

    if not _tool_embeddings:
        return get_relevant_tools_keyword(alert_context, all_tools, top_k)

    # Embed the alert context
    query_embedding = model.encode(alert_context, convert_to_tensor=False)

    # Calculate similarities
    similarities = {}
    for tool_name, tool_embedding in _tool_embeddings.items():
        sim = cosine_similarity([query_embedding], [tool_embedding])[0][0]
        similarities[tool_name] = sim

    # Sort by similarity
    sorted_tools = sorted(similarities.items(), key=lambda x: x[1], reverse=True)

    # Get top-k tool names
    selected_names = set()

    # Always include essential tools
    selected_names.update(ESSENTIAL_TOOLS)

    # Add top semantic matches
    for tool_name, _score in sorted_tools[:top_k]:
        selected_names.add(tool_name)

    # Filter the actual tool objects
    filtered_tools = []
    tool_name_to_obj = {}

    for tool in all_tools:
        name = _get_tool_name(tool)
        tool_name_to_obj[name] = tool
        if name in selected_names:
            filtered_tools.append(tool)

    # Add essential tools if they weren't in the list
    for essential in ESSENTIAL_TOOLS:
        if essential in tool_name_to_obj and essential not in [
            _get_tool_name(t) for t in filtered_tools
        ]:
            filtered_tools.append(tool_name_to_obj[essential])

    logger.info(
        f"Semantic tool retrieval: {len(all_tools)} -> {len(filtered_tools)} tools "
        f"for context: {alert_context[:50]}..."
    )

    return filtered_tools


def get_relevant_tools_keyword(
    alert_context: str,
    all_tools: list[Any],
    top_k: int = 15,
) -> list[Any]:
    """Get relevant tools using keyword matching (fallback).

    Args:
        alert_context: Alert name, description, and any MITRE techniques
        all_tools: Full list of available tools
        top_k: Maximum number of tools to return

    Returns:
        Filtered list of relevant tools
    """
    context_lower = alert_context.lower()
    selected_names = set()

    # Always include essential tools
    selected_names.update(ESSENTIAL_TOOLS)

    # Check keyword patterns
    for pattern, tool_names in KEYWORD_MAPPING.items():
        if pattern.replace(".", ".*") in context_lower or pattern in context_lower:
            selected_names.update(tool_names)

    # Check MITRE techniques
    for technique, tool_names in MITRE_TOOL_MAPPING.items():
        if technique.lower() in context_lower:
            selected_names.update(tool_names)

    # If we didn't find much, include some generic tools
    if len(selected_names) < 8:
        # Add common detection tools
        selected_names.update(
            [
                "detect_lateral_movement",
                "detect_pass_the_hash",
                "detect_suspicious_execution",
                "detect_secretsdump",
            ]
        )

    # Filter the actual tool objects
    filtered_tools = []
    for tool in all_tools:
        name = _get_tool_name(tool)
        if name in selected_names:
            filtered_tools.append(tool)

    # Limit to top_k
    filtered_tools = filtered_tools[:top_k]

    logger.info(
        f"Keyword tool retrieval: {len(all_tools)} -> {len(filtered_tools)} tools "
        f"for context: {alert_context[:50]}..."
    )

    return filtered_tools


def _get_tool_name(tool: Any) -> str:
    """Extract tool name from various tool object types."""
    if hasattr(tool, "name"):
        return tool.name
    if hasattr(tool, "__name__"):
        return tool.__name__
    if hasattr(tool, "fn") and hasattr(tool.fn, "__name__"):
        return tool.fn.__name__
    return str(tool)


def filter_tools_for_alert(
    alert: dict,
    all_tools: list[Any],
    use_semantic: bool = True,
    top_k: int = 12,
) -> list[Any]:
    """Filter tools based on alert context.

    This is the main entry point for tool filtering.

    Args:
        alert: Alert dictionary with labels and annotations
        all_tools: Full list of available tools
        use_semantic: Whether to use semantic matching (requires sentence-transformers)
        top_k: Maximum number of detection tools to include

    Returns:
        Filtered list of relevant tools
    """
    # Build context string from alert
    labels = alert.get("labels", {})
    annotations = alert.get("annotations", {})

    context_parts = [
        labels.get("alertname", ""),
        labels.get("severity", ""),
        annotations.get("summary", ""),
        annotations.get("description", ""),
    ]

    # Add MITRE technique if present
    for key in ["mitre_technique", "mitre", "technique_id"]:
        if labels.get(key):
            context_parts.append(labels[key])
        if annotations.get(key):
            context_parts.append(annotations[key])

    context = " ".join(filter(None, context_parts))

    if not context:
        context = "security investigation lateral movement credential access"

    if use_semantic:
        return get_relevant_tools_semantic(context, all_tools, top_k)
    return get_relevant_tools_keyword(context, all_tools, top_k)
