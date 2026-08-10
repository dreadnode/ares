#!/usr/bin/env python3
"""Backfill captured Prometheus metrics into a replay Prometheus TSDB.

Converts a captured `query_range` JSON response (matrix result) into OpenMetrics
text, then runs `promtool tsdb create-blocks-from openmetrics` to write TSDB
blocks the replay Prometheus serves directly — bypassing the out-of-order
ingestion window so historical samples load cleanly.

    prom_backfill.py <captured metrics.json> <output prometheus data dir>

Requires `promtool` on PATH.
"""
import json
import math
import os
import re
import subprocess
import sys
import tempfile
from collections import defaultdict

# Classic Prometheus/OpenMetrics name grammars. Names outside these (e.g. OTel
# dotted names like `http.server.request.duration_seconds`) are emitted in the
# UTF-8 quoted form, which promtool 3.x accepts.
_VALID_METRIC = re.compile(r"^[a-zA-Z_:][a-zA-Z0-9_:]*$")
_VALID_LABEL = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*$")


def esc(v: str) -> str:
    return v.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def fmt_val(fval):
    """OpenMetrics value literal — NaN/Inf need the canonical spelling."""
    if math.isnan(fval):
        return "NaN"
    if math.isinf(fval):
        return "+Inf" if fval > 0 else "-Inf"
    return repr(fval)


def build_openmetrics(data):
    """Convert a query_range matrix result into (OpenMetrics text, family count)."""
    result = data.get("data", {}).get("result", [])
    # Group samples by metric family so OpenMetrics families aren't interleaved.
    families = defaultdict(list)
    for series in result:
        metric = series.get("metric", {})
        name = metric.get("__name__")
        if not name:
            continue
        labels = {k: v for k, v in metric.items() if k != "__name__"}
        pairs = []
        for k, v in sorted(labels.items()):
            key = k if _VALID_LABEL.match(k) else f'"{esc(k)}"'
            pairs.append(f'{key}="{esc(str(v))}"')
        labelstr = ",".join(pairs)
        if _VALID_METRIC.match(name):
            sel = f"{name}{{{labelstr}}}" if labelstr else name
        else:
            # UTF-8 metric name → quote it as the first element inside braces.
            quoted = f'"{esc(name)}"'
            sel = f"{{{quoted},{labelstr}}}" if labelstr else f"{{{quoted}}}"
        for ts, val in series.get("values", []):
            try:
                fval = float(val)
            except (TypeError, ValueError):
                continue
            families[name].append((sel, fmt_val(fval), float(ts)))

    lines = []
    for name, samples in families.items():
        type_name = name if _VALID_METRIC.match(name) else f'"{esc(name)}"'
        lines.append(f"# TYPE {type_name} gauge")
        for sel, vstr, ts in samples:
            lines.append(f"{sel} {vstr} {ts}")
    lines.append("# EOF")
    return "\n".join(lines) + "\n", len(families)


def main() -> int:
    args = sys.argv[1:]
    # `--emit-openmetrics <src.json> <out.om>`: write the OpenMetrics text only
    # (no promtool). Used at capture time, where promtool runs separately (via a
    # pinned container) to pre-build TSDB blocks so replay just copies them.
    emit_only = bool(args) and args[0] == "--emit-openmetrics"
    if emit_only:
        args = args[1:]
    if len(args) != 2:
        print(__doc__)
        return 2
    src, out = args[0], args[1]

    with open(src) as f:
        data = json.load(f)
    if not data.get("data", {}).get("result", []):
        print("no series in capture — nothing to backfill")
        return 0

    om_text, nfam = build_openmetrics(data)

    if emit_only:
        with open(out, "w") as f:
            f.write(om_text)
        print(f"wrote {nfam} metric families as OpenMetrics text to {out}")
        return 0

    os.makedirs(out, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", suffix=".openmetrics", delete=False) as tf:
        tf.write(om_text)
        ompath = tf.name

    subprocess.run(
        ["promtool", "tsdb", "create-blocks-from", "openmetrics", ompath, out],
        check=True,
    )
    os.unlink(ompath)
    print(f"backfilled {nfam} metric families into {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
