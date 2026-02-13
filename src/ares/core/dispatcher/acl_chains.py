"""ACL chain tracking and orchestration for multi-hop ACL abuse.

This module provides tools for tracking and executing multi-hop ACL abuse chains
discovered through BloodHound analysis. ACL chains allow privilege escalation
through a series of intermediate accounts.

Example chain: svc.backup -> helpdesk01 -> admin01 -> Domain Admins
- svc.backup has ForceChangePassword on helpdesk01
- helpdesk01 has WriteDacl on admin01
- admin01 has GenericAll on Domain Admins
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import TYPE_CHECKING, Any

from loguru import logger

if TYPE_CHECKING:
    from ares.core.dispatcher._dispatcher import RedTeamDispatcher


class ACLRight(Enum):
    """ACL rights that can be abused for privilege escalation."""

    GENERIC_ALL = "GenericAll"
    GENERIC_WRITE = "GenericWrite"
    WRITE_DACL = "WriteDacl"
    WRITE_OWNER = "WriteOwner"
    FORCE_CHANGE_PASSWORD = "ForceChangePassword"  # noqa: S105  # nosec B105  # pragma: allowlist secret
    ADD_MEMBER = "AddMember"
    WRITE_MEMBER = "WriteMember"
    ALL_EXTENDED_RIGHTS = "AllExtendedRights"
    USER_FORCE_CHANGE_PASSWORD = "User-Force-Change-Password"  # noqa: S105  # nosec B105  # pragma: allowlist secret

    @classmethod
    def from_string(cls, s: str) -> ACLRight | None:
        """Parse ACL right from string."""
        normalized = s.strip().lower().replace("-", "").replace("_", "")
        for right in cls:
            if right.value.lower().replace("-", "").replace("_", "") == normalized:
                return right
        return None


class ACLAction(Enum):
    """Actions that can be taken to exploit an ACL right."""

    RESET_PASSWORD = "reset_password"  # noqa: S105  # nosec B105  # pragma: allowlist secret
    ADD_TO_GROUP = "add_to_group"
    SHADOW_CREDENTIALS = "shadow_credentials"
    TARGETED_KERBEROAST = "targeted_kerberoast"
    WRITE_DACL = "write_dacl"
    TAKE_OWNERSHIP = "take_ownership"
    RBCD = "rbcd"


@dataclass
class ACLChainStep:
    """Single step in an ACL abuse chain."""

    step_id: str
    source: str  # Principal performing the action (who we control)
    target: str  # Target of the action (what we're attacking)
    right: str  # ACL right being abused
    action: ACLAction  # Action to take
    target_type: str = "user"  # user, group, computer
    completed: bool = False
    result: str = ""
    completed_at: datetime | None = None
    new_credential: dict[str, str] | None = None  # Credential obtained from this step

    def to_dict(self) -> dict[str, Any]:
        """Convert step to dictionary for serialization."""
        return {
            "step_id": self.step_id,
            "source": self.source,
            "target": self.target,
            "right": self.right,
            "action": self.action.value,
            "target_type": self.target_type,
            "completed": self.completed,
            "result": self.result,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "new_credential": self.new_credential,
        }


@dataclass
class ACLChain:
    """A complete ACL abuse chain from source to goal."""

    chain_id: str
    steps: list[ACLChainStep] = field(default_factory=list)
    goal: str = ""  # Final target (e.g., "Domain Admins")
    domain: str = ""
    discovered_by: str = ""  # Agent that discovered the chain
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def is_complete(self) -> bool:
        """Check if all steps are completed."""
        return all(step.completed for step in self.steps)

    @property
    def current_step_index(self) -> int:
        """Get index of current (first uncompleted) step."""
        for i, step in enumerate(self.steps):
            if not step.completed:
                return i
        return len(self.steps)

    @property
    def current_step(self) -> ACLChainStep | None:
        """Get the current step to execute."""
        idx = self.current_step_index
        if idx < len(self.steps):
            return self.steps[idx]
        return None

    @property
    def progress(self) -> str:
        """Get progress string."""
        completed = sum(1 for s in self.steps if s.completed)
        return f"{completed}/{len(self.steps)}"

    def to_dict(self) -> dict[str, Any]:
        """Convert chain to dictionary for serialization."""
        return {
            "chain_id": self.chain_id,
            "steps": [s.to_dict() for s in self.steps],
            "goal": self.goal,
            "domain": self.domain,
            "discovered_by": self.discovered_by,
            "created_at": self.created_at.isoformat(),
            "is_complete": self.is_complete,
            "progress": self.progress,
        }


class ACLChainTracker:
    """Track and orchestrate multi-hop ACL abuse chains.

    Chains are persisted to SharedRedTeamState.acl_chains for pub/sub visibility
    and recovery after orchestrator restart.
    """

    def __init__(self, state: Any | None = None) -> None:
        self.chains: dict[str, ACLChain] = {}
        self._active_chain_id: str | None = None
        self._state = state
        # Load existing chains from state if available
        if state is not None:
            self.sync_from_state()

    def set_state(self, state: Any) -> None:
        """Set state reference and sync from it."""
        self._state = state
        self.sync_from_state()

    def sync_from_state(self) -> None:
        """Load chains from persisted state (for recovery after restart)."""
        if not self._state or not hasattr(self._state, "acl_chains"):
            return

        for chain_data in self._state.acl_chains:
            chain_id = chain_data.get("chain_id")
            if not chain_id or chain_id in self.chains:
                continue  # Already loaded or invalid

            # Reconstruct ACLChain from dict
            steps: list[ACLChainStep] = []
            for step_data in chain_data.get("steps", []):
                action_str = step_data.get("action", "shadow_credentials")
                try:
                    action = ACLAction(action_str)
                except ValueError:
                    action = ACLAction.SHADOW_CREDENTIALS

                step = ACLChainStep(
                    step_id=step_data.get("step_id", f"step-{len(steps) + 1}"),
                    source=step_data.get("source", ""),
                    target=step_data.get("target", ""),
                    right=step_data.get("right", ""),
                    action=action,
                    target_type=step_data.get("target_type", "user"),
                    completed=step_data.get("completed", False),
                    result=step_data.get("result", ""),
                    new_credential=step_data.get("new_credential"),
                )
                if step_data.get("completed_at"):
                    try:
                        step.completed_at = datetime.fromisoformat(step_data["completed_at"])
                    except (ValueError, TypeError):
                        pass
                steps.append(step)

            chain = ACLChain(
                chain_id=chain_id,
                steps=steps,
                goal=chain_data.get("goal", ""),
                domain=chain_data.get("domain", ""),
                discovered_by=chain_data.get("discovered_by", ""),
            )
            if chain_data.get("created_at"):
                try:
                    chain.created_at = datetime.fromisoformat(chain_data["created_at"])
                except (ValueError, TypeError):
                    pass

            self.chains[chain_id] = chain
            logger.debug(f"🔗 Restored ACL chain from state: {chain_id}")

    def sync_to_state(self) -> None:
        """Persist all chains to state for pub/sub visibility."""
        if not self._state or not hasattr(self._state, "acl_chains"):
            return

        # Build list of chain dicts
        chain_list = [chain.to_dict() for chain in self.chains.values()]
        self._state.acl_chains = chain_list

    def add_chain(self, chain: ACLChain) -> str:
        """Register a new ACL chain and persist to state."""
        self.chains[chain.chain_id] = chain
        logger.info(
            f"🔗 ACL chain registered: {chain.chain_id} with {len(chain.steps)} steps -> {chain.goal}"
        )
        # Persist to state
        self.sync_to_state()
        return chain.chain_id

    def create_chain_from_bloodhound_path(
        self,
        path_output: str,
        domain: str,
        discovered_by: str = "bloodhound",
    ) -> ACLChain | None:
        """
        Parse BloodHound shortest path output and create an ACL chain.

        BloodHound path formats:
        - "USER1@DOMAIN -[ForceChangePassword]-> USER2@DOMAIN -[GenericAll]-> GROUP"
        - "user1 -> user2 (ForceChangePassword) -> user3 (WriteDacl) -> Domain Admins"
        """
        chain_id = f"acl-chain-{uuid.uuid4().hex[:8]}"
        steps: list[ACLChainStep] = []

        # Pattern 1: BloodHound arrow format with brackets
        # USER1@DOMAIN -[ForceChangePassword]-> USER2@DOMAIN
        pattern1 = re.compile(
            r"([^\s\-]+)\s*-\[(\w+)\]->\s*([^\s\-]+)",
            re.IGNORECASE,
        )

        # Pattern 2: Simplified format
        # user1 -> user2 (ForceChangePassword)
        pattern2 = re.compile(
            r"([^\s\(\)]+)\s*->\s*([^\s\(\)]+)\s*\((\w+)\)",
            re.IGNORECASE,
        )

        # Pattern 3: Table/list format from BloodHound
        # Source: user1, Target: user2, Edge: ForceChangePassword
        pattern3 = re.compile(
            r"source:\s*([^\s,]+).*?target:\s*([^\s,]+).*?(?:edge|right|permission):\s*(\w+)",
            re.IGNORECASE,
        )

        matches = []

        # Try all patterns
        for match in pattern1.finditer(path_output):
            source, right, target = match.groups()
            matches.append((source, target, right))

        if not matches:
            for match in pattern2.finditer(path_output):
                source, target, right = match.groups()
                matches.append((source, target, right))

        if not matches:
            for match in pattern3.finditer(path_output):
                source, target, right = match.groups()
                matches.append((source, target, right))

        if not matches:
            logger.warning(f"Could not parse ACL chain from output: {path_output[:200]}...")
            return None

        # Build steps from matches
        for i, (source, target, right) in enumerate(matches):
            # Clean up names (remove @DOMAIN suffix if present)
            source_clean = source.split("@")[0].strip()
            target_clean = target.split("@")[0].strip()
            right_clean = right.strip()

            # Determine action based on right
            action = self._right_to_action(right_clean, target_clean)

            # Determine target type
            target_type = "user"
            if target_clean.lower() in ("domain admins", "enterprise admins", "administrators"):
                target_type = "group"
            elif target_clean.endswith("$"):
                target_type = "computer"

            step = ACLChainStep(
                step_id=f"step-{i + 1}",
                source=source_clean,
                target=target_clean,
                right=right_clean,
                action=action,
                target_type=target_type,
            )
            steps.append(step)

        if not steps:
            return None

        # Determine goal (last target)
        goal = steps[-1].target

        chain = ACLChain(
            chain_id=chain_id,
            steps=steps,
            goal=goal,
            domain=domain,
            discovered_by=discovered_by,
        )

        self.add_chain(chain)
        return chain

    def _right_to_action(self, right: str, target: str) -> ACLAction:
        """Determine the best action for a given ACL right."""
        right_lower = right.lower().replace("-", "").replace("_", "")
        target_lower = target.lower()

        # Group targets - add member
        is_group_target = target_lower in ("domain admins", "enterprise admins", "administrators")
        has_member_right = (
            "member" in right_lower or "genericall" in right_lower or "genericwrite" in right_lower
        )
        if is_group_target and has_member_right:
            return ACLAction.ADD_TO_GROUP

        # ForceChangePassword - reset password
        if "forcechangepassword" in right_lower or "resetpassword" in right_lower:
            return ACLAction.RESET_PASSWORD

        # GenericAll/GenericWrite on user - shadow credentials preferred
        if "genericall" in right_lower or "genericwrite" in right_lower:
            if target.endswith("$"):  # Computer
                return ACLAction.RBCD
            return ACLAction.SHADOW_CREDENTIALS

        # WriteDacl - grant ourselves more permissions
        if "writedacl" in right_lower:
            return ACLAction.WRITE_DACL

        # WriteOwner - take ownership
        if "writeowner" in right_lower:
            return ACLAction.TAKE_OWNERSHIP

        # AddMember - add to group
        if "addmember" in right_lower or "writemember" in right_lower:
            return ACLAction.ADD_TO_GROUP

        # Default to shadow credentials for users, RBCD for computers
        if target.endswith("$"):
            return ACLAction.RBCD
        return ACLAction.SHADOW_CREDENTIALS

    def get_chain(self, chain_id: str) -> ACLChain | None:
        """Get a chain by ID."""
        return self.chains.get(chain_id)

    def get_next_step(self, chain_id: str) -> ACLChainStep | None:
        """Get next uncompleted step in chain."""
        chain = self.chains.get(chain_id)
        if not chain:
            return None
        return chain.current_step

    def mark_step_completed(
        self,
        chain_id: str,
        step_id: str,
        result: str = "",
        new_credential: dict[str, str] | None = None,
    ) -> bool:
        """Mark a step as completed and persist to state."""
        chain = self.chains.get(chain_id)
        if not chain:
            return False

        for step in chain.steps:
            if step.step_id == step_id:
                step.completed = True
                step.result = result
                step.completed_at = datetime.now(timezone.utc)
                step.new_credential = new_credential
                logger.info(
                    f"✅ ACL chain {chain_id} step {step_id} completed: "
                    f"{step.source} -> {step.target} ({step.action.value})"
                )
                # Persist updated state
                self.sync_to_state()
                return True
        return False

    def get_active_chains(self) -> list[ACLChain]:
        """Get all chains that have started but not completed."""
        return [c for c in self.chains.values() if not c.is_complete and c.current_step_index > 0]

    def get_pending_chains(self) -> list[ACLChain]:
        """Get all chains that haven't started yet."""
        return [c for c in self.chains.values() if c.current_step_index == 0]

    def get_chain_for_credential(self, username: str) -> ACLChain | None:
        """Find a chain where the current step's source matches the username."""
        username_lower = username.lower()
        for chain in self.chains.values():
            if chain.is_complete:
                continue
            step = chain.current_step
            if step and step.source.lower() == username_lower:
                return chain
        return None

    def generate_step_prompt(self, chain: ACLChain, step: ACLChainStep, domain: str) -> str:
        """Generate a prompt for executing a chain step."""
        prompts = {
            ACLAction.RESET_PASSWORD: f"""
Execute password reset for ACL chain step:
- Source: {step.source} (you are authenticated as this user)
- Target: {step.target}
- Right: {step.right}

Use bloodyad_set_password or force_change_password to reset {step.target}'s password.
After reset, authenticate as {step.target} to continue the chain.
""",
            ACLAction.ADD_TO_GROUP: f"""
Execute group membership modification for ACL chain step:
- Source: {step.source} (you are authenticated as this user)
- Target Group: {step.target}
- Right: {step.right}

Use bloodyad_add_group_member to add yourself or a controlled user to {step.target}.
If {step.target} is Domain Admins, this achieves Domain Admin!
""",
            ACLAction.SHADOW_CREDENTIALS: f"""
Execute shadow credentials attack for ACL chain step:
- Source: {step.source} (you are authenticated as this user)
- Target: {step.target}
- Right: {step.right}

Use pywhisker to add shadow credentials to {step.target}.
Then use certipy_auth with the PFX to get {step.target}'s NTLM hash.
""",
            ACLAction.WRITE_DACL: f"""
Execute DACL modification for ACL chain step:
- Source: {step.source} (you are authenticated as this user)
- Target: {step.target}
- Right: {step.right}

Use dacl_edit to grant yourself GenericAll on {step.target}.
Then use the new permissions for shadow credentials or password reset.
""",
            ACLAction.TAKE_OWNERSHIP: f"""
Execute ownership takeover for ACL chain step:
- Source: {step.source} (you are authenticated as this user)
- Target: {step.target}
- Right: {step.right}

Use owneredit to take ownership of {step.target}.
Then use dacl_edit to grant yourself full control.
""",
            ACLAction.RBCD: f"""
Execute RBCD attack for ACL chain step:
- Source: {step.source} (you are authenticated as this user)
- Target: {step.target}
- Right: {step.right}

Use rbcd_write to configure RBCD on {step.target}.
Then use s4u_attack to get Administrator ticket.
""",
            ACLAction.TARGETED_KERBEROAST: f"""
Execute targeted Kerberoast for ACL chain step:
- Source: {step.source} (you are authenticated as this user)
- Target: {step.target}
- Right: {step.right}

Use targeted_kerberoast to set an SPN on {step.target} and request a TGS.
Request hash cracking from orchestrator.
""",
        }

        base_prompt = prompts.get(step.action, f"Execute {step.action.value} on {step.target}")

        return f"""
## ACL Chain Execution: {chain.chain_id}
Progress: {chain.progress} - Goal: {chain.goal}
Domain: {domain}

{base_prompt}

After completing this step, report success with any new credentials obtained.
"""


# Helper function for dispatcher integration
def extract_acl_chains_from_bloodhound(
    self: RedTeamDispatcher,
    output: str,
    source_agent: str,
) -> list[ACLChain]:
    """
    Extract ACL chains from BloodHound output and register them.

    Called from result_processing when BloodHound analysis completes.
    """
    # Initialize tracker with state for persistence
    if not hasattr(self, "_acl_chain_tracker"):
        self._acl_chain_tracker = ACLChainTracker(state=self.shared_state)
    elif self._acl_chain_tracker._state is None:
        self._acl_chain_tracker.set_state(self.shared_state)

    chains: list[ACLChain] = []
    domain = ""
    if self.shared_state.target and self.shared_state.target.domain:
        domain = self.shared_state.target.domain

    # Look for shortest path sections in output
    path_indicators = [
        "shortest path",
        "attack path",
        "path to domain admin",
        "->",
        "-[",
    ]

    if not any(indicator in output.lower() for indicator in path_indicators):
        return chains

    # Split output into potential paths
    lines = output.split("\n")
    current_path: list[str] = []

    for raw_line in lines:
        line = raw_line.strip()
        if not line:
            if current_path:
                path_text = " ".join(current_path)
                chain = self._acl_chain_tracker.create_chain_from_bloodhound_path(
                    path_text, domain, source_agent
                )
                if chain:
                    chains.append(chain)
                current_path = []
        elif "->" in line or "-[" in line:
            current_path.append(line)

    # Handle last path
    if current_path:
        path_text = " ".join(current_path)
        chain = self._acl_chain_tracker.create_chain_from_bloodhound_path(
            path_text, domain, source_agent
        )
        if chain:
            chains.append(chain)

    if chains:
        logger.info(f"🔗 Extracted {len(chains)} ACL chain(s) from BloodHound output")

    return chains
