"""Site-customize shim that subtracts a fixed offset from Python's clock.

Loaded into impacket / certipy subprocesses via PYTHONPATH when ares detects
that the lab DCs' Kerberos clock disagrees with the agent host's clock by more
than the 5-minute KRB_AP_ERR_SKEW window. Reads the offset (seconds) from the
ARES_KERBEROS_TIME_OFFSET_SECS environment variable and patches:

  - datetime.datetime.now(...)   (impacket krb5/kerberosv5.py + certipy)
  - datetime.datetime.utcnow()   (older impacket call sites)
  - time.time()                  (anything that times stamps via Unix epoch)

A positive offset means "agent clock is AHEAD of DC; subtract from local time
to match DC". Negative means the reverse. 0 disables the shim.

The shim is a no-op when the env var is unset or 0, so it's safe to leave
PYTHONPATH set even for non-Kerberos invocations.
"""

import os
import sys
import time as _time
import datetime as _datetime


def _offset_secs() -> float:
    try:
        raw = os.environ.get("ARES_KERBEROS_TIME_OFFSET_SECS", "0").strip()
        return float(raw) if raw else 0.0
    except (ValueError, TypeError):
        return 0.0


_OFFSET = _offset_secs()

if _OFFSET != 0.0:
    _real_time = _time.time
    _real_datetime_now = _datetime.datetime.now
    _real_datetime_utcnow = _datetime.datetime.utcnow

    def _shifted_time() -> float:
        return _real_time() - _OFFSET

    class _ShiftedDateTime(_datetime.datetime):
        """Subclass of datetime so isinstance checks in impacket keep working."""

        @classmethod
        def now(cls, tz=None):
            return _real_datetime_now(tz) - _datetime.timedelta(seconds=_OFFSET)

        @classmethod
        def utcnow(cls):
            return _real_datetime_utcnow() - _datetime.timedelta(seconds=_OFFSET)

    # time.time is the easy one — just rebind.
    _time.time = _shifted_time

    # datetime.datetime is harder because it's a C type; we install a thin
    # wrapper *module-level* attribute that classmethod-overrides only the
    # two factories impacket/certipy actually call. Direct construction via
    # `datetime(...)` is unaffected, which is what we want — only "now"
    # readings should be shifted.
    _datetime.datetime.now = _ShiftedDateTime.now  # type: ignore[assignment]
    _datetime.datetime.utcnow = _ShiftedDateTime.utcnow  # type: ignore[assignment]

    print(
        f"[ares-krb-skew] applied offset {_OFFSET:.0f}s to time.time + datetime.now/utcnow",
        file=sys.stderr,
        flush=True,
    )
