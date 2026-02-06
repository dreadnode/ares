"""External service integrations."""

__all__ = [
    "MITREAttackClient",
]


def __getattr__(name: str):
    if name == "MITREAttackClient":
        from ares.integrations.mitre import MITREAttackClient

        return MITREAttackClient

    raise AttributeError(f"module 'ares.integrations' has no attribute {name!r}")
