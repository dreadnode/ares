"""User summary generation for consolidating credentials, hashes, and attack paths."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime

    from ares.core.models import Credential, Hash, SharedRedTeamState


@dataclass
class AttackChainStep:
    """A single step in an attack chain."""

    step_number: int
    item_type: str  # "credential" or "hash"
    username: str
    domain: str
    source: str
    item_id: str

    def format(self, include_id: bool = False) -> str:
        """Format this step for display."""
        user_str = f"{self.domain}\\{self.username}" if self.domain else self.username
        result = f"[{self.step_number}] {self.source} -> {user_str}"
        if include_id:
            result += f" ({self.item_id[:8]})"
        return result


@dataclass
class UserSummary:
    """Consolidated view of a user with all credentials, hashes, and attack paths.

    Attributes:
        username: The username.
        domain: The domain.
        is_admin: Whether any credential for this user is admin.
        description: User description from LDAP (if available).
        credentials: All credentials discovered for this user.
        hashes: All hashes discovered for this user.
        discovery_sources: Set of sources that discovered credentials/hashes.
        first_discovered_at: Earliest discovery timestamp.
        attack_chains: Attack chain for each credential/hash showing how it was obtained.
        max_attack_depth: Maximum depth in the attack graph (longest chain).
    """

    username: str
    domain: str
    is_admin: bool = False
    description: str = ""
    credentials: list[Credential] = field(default_factory=list)
    hashes: list[Hash] = field(default_factory=list)
    discovery_sources: set[str] = field(default_factory=set)
    first_discovered_at: datetime | None = None
    attack_chains: dict[str, list[AttackChainStep]] = field(default_factory=dict)
    max_attack_depth: int = 0

    @property
    def user_key(self) -> str:
        """Normalized key for deduplication."""
        return f"{self.domain.lower()}\\{self.username.lower()}"

    @property
    def display_name(self) -> str:
        """User display string."""
        if self.domain:
            return f"{self.domain}\\{self.username}"
        return self.username

    def has_cleartext(self) -> bool:
        """Check if any credential has a cleartext password."""
        return len(self.credentials) > 0

    def has_hash(self) -> bool:
        """Check if any hash is available."""
        return len(self.hashes) > 0


def _build_item_index(
    credentials: list[Credential],
    hashes: list[Hash],
) -> dict[str, Credential | Hash]:
    """Build a lookup index by item ID for chain tracing."""
    index: dict[str, Credential | Hash] = {}
    for cred in credentials:
        if cred.id:
            index[cred.id] = cred
    for h in hashes:
        if h.id:
            index[h.id] = h
    return index


def trace_attack_chain(
    item: Credential | Hash,
    item_index: dict[str, Credential | Hash],
) -> list[AttackChainStep]:
    """Trace the attack chain from initial access to this item.

    Walks backward through parent_id links to construct the full path.

    Args:
        item: The credential or hash to trace from.
        item_index: Lookup index of all credentials and hashes by ID.

    Returns:
        List of AttackChainStep from initial access (step 0) to the target item.
    """
    chain: list[AttackChainStep] = []
    visited: set[str] = set()
    current: Credential | Hash | None = item

    while current is not None:
        item_id = current.id
        if not item_id or item_id in visited:
            break
        visited.add(item_id)

        # Determine item type
        item_type = "credential" if isinstance(current, Credential) else "hash"

        step = AttackChainStep(
            step_number=current.attack_step,
            item_type=item_type,
            username=current.username,
            domain=current.domain,
            source=current.source or "unknown",
            item_id=item_id,
        )
        chain.append(step)

        # Follow parent link
        parent_id = current.parent_id
        current = item_index[parent_id] if parent_id and parent_id in item_index else None

    # Reverse to get initial access first
    return list(reversed(chain))


def generate_user_summaries(state: SharedRedTeamState) -> list[UserSummary]:
    """Generate user summaries from shared state.

    Aggregates all credentials and hashes per user, traces attack chains,
    and computes derived metrics.

    Args:
        state: The shared red team state containing all discovered items.

    Returns:
        List of UserSummary objects sorted by domain then username.
    """
    # Build index for chain tracing
    item_index = _build_item_index(state.all_credentials, state.all_hashes)

    # Group credentials and hashes by user key
    creds_by_user: dict[str, list[Credential]] = defaultdict(list)
    hashes_by_user: dict[str, list[Hash]] = defaultdict(list)
    user_info: dict[str, dict] = {}  # user_key -> {domain, username, is_admin, description}

    for cred in state.all_credentials:
        key = f"{cred.domain.lower()}\\{cred.username.lower()}"
        creds_by_user[key].append(cred)
        if key not in user_info:
            user_info[key] = {
                "domain": cred.domain,
                "username": cred.username,
                "is_admin": cred.is_admin,
                "description": "",
            }
        elif cred.is_admin:
            user_info[key]["is_admin"] = True

    for h in state.all_hashes:
        key = f"{h.domain.lower()}\\{h.username.lower()}"
        hashes_by_user[key].append(h)
        if key not in user_info:
            user_info[key] = {
                "domain": h.domain,
                "username": h.username,
                "is_admin": False,
                "description": "",
            }

    # Enrich with User objects if available
    for user in state.all_users:
        key = f"{user.domain.lower()}\\{user.username.lower()}"
        if key in user_info:
            if user.description:
                user_info[key]["description"] = user.description
            if user.is_admin:
                user_info[key]["is_admin"] = True
        else:
            # User exists but no credentials/hashes - skip for now
            # (could add option to include all users later)
            pass

    # Build summaries
    summaries: list[UserSummary] = []
    all_user_keys = set(creds_by_user.keys()) | set(hashes_by_user.keys())

    for key in all_user_keys:
        info = user_info.get(key, {})
        creds = creds_by_user.get(key, [])
        hashes = hashes_by_user.get(key, [])

        # Collect discovery sources
        sources: set[str] = set()
        for c in creds:
            if c.source:
                sources.add(c.source)
        for h in hashes:
            if h.source:
                sources.add(h.source)

        # Find earliest discovery time
        first_discovered: datetime | None = None
        for h in hashes:
            if h.discovered_at and (first_discovered is None or h.discovered_at < first_discovered):
                first_discovered = h.discovered_at

        # Trace attack chains for each credential/hash
        attack_chains: dict[str, list[AttackChainStep]] = {}
        max_depth = 0

        for c in creds:
            if c.id:
                chain = trace_attack_chain(c, item_index)
                if chain:
                    attack_chains[c.id] = chain
                    max_depth = max(max_depth, c.attack_step)

        for h in hashes:
            if h.id:
                chain = trace_attack_chain(h, item_index)
                if chain:
                    attack_chains[h.id] = chain
                    max_depth = max(max_depth, h.attack_step)

        summary = UserSummary(
            username=info.get("username", key.split("\\")[-1]),
            domain=info.get("domain", key.split("\\")[0] if "\\" in key else ""),
            is_admin=info.get("is_admin", False),
            description=info.get("description", ""),
            credentials=creds,
            hashes=hashes,
            discovery_sources=sources,
            first_discovered_at=first_discovered,
            attack_chains=attack_chains,
            max_attack_depth=max_depth,
        )
        summaries.append(summary)

    # Sort by domain, then username
    summaries.sort(key=lambda s: (s.domain.lower(), s.username.lower()))

    return summaries


def format_attack_chain(chain: list[AttackChainStep], compact: bool = True) -> str:
    """Format an attack chain for display.

    Args:
        chain: List of attack chain steps.
        compact: If True, use compact single-line format.

    Returns:
        Formatted string representation of the attack chain.
    """
    if not chain:
        return "(no chain data)"

    if compact:
        # Compact: source1 -> source2 -> source3
        sources = [step.source for step in chain]
        return " -> ".join(sources)

    # Verbose: multi-line with details
    lines = []
    for step in chain:
        lines.append(step.format())
    return "\n".join(lines)
