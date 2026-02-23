"""Blue team multi-agent dispatcher.

Coordinates triage, threat hunting, and lateral analysis workers
for blue team investigations. Manages shared state via Redis.
"""

from ares.core.blue_dispatcher._dispatcher import BlueTeamDispatcher

__all__ = ["BlueTeamDispatcher"]
