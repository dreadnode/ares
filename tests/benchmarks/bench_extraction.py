"""Benchmark script for extraction module hot parsing paths.

Profiles all extraction functions from ares.core.dispatcher.extraction
with realistic large inputs. Reports mean/min/max times, ops/sec, and
identifies the slowest function.

Usage:
    uv run python tests/benchmarks/bench_extraction.py

Pytest (requires pytest-benchmark or just runs as slow-marked tests):
    uv run pytest tests/benchmarks/bench_extraction.py -v
"""

from __future__ import annotations

import random
import statistics
import sys
import time
from typing import TYPE_CHECKING, Any

import pytest

if TYPE_CHECKING:
    from collections.abc import Callable

# ---------------------------------------------------------------------------
# Detect backend
# ---------------------------------------------------------------------------
try:
    import ares_core as _rust  # type: ignore[import-untyped]  # noqa: F401

    _BACKEND = "Rust (ares_core)"
except ImportError:
    _BACKEND = "Python fallback"

from ares.core.dispatcher.extraction import (
    extract_delegation_entries,
    extract_domain_sid,
    extract_host_from_spn,
    extract_hosts_from_output,
    extract_kerberos_hashes,
    extract_ntlm_hashes,
    extract_plaintext_passwords_from_output,
    extract_secretsdump_hashes,
    extract_shares_from_output,
    extract_ticket_path_from_output,
    extract_users_from_output,
)

# ---------------------------------------------------------------------------
# Realistic data generators -- all use contoso.local / 192.168.58.x
# ---------------------------------------------------------------------------

_RNG = random.Random(42)  # deterministic seed for reproducibility  # noqa: S311

_HOSTNAMES = [
    "DC01",
    "DC02",
    "FS01",
    "SQL01",
    "WEB01",
    "APP01",
    "EXCH01",
    "WSUS01",
    "SCCM01",
    "ADFS01",
    "CA01",
    "PKI01",
    "RDP01",
    "JUMP01",
    "MGMT01",
    "PRINT01",
    "FILE01",
    "BACKUP01",
    "MONITOR01",
    "LOG01",
]

_USERS = [
    "administrator",
    "krbtgt",
    "jsmith",
    "ajonas",
    "bwilliams",
    "cgarcia",
    "dlee",
    "emartinez",
    "frobinson",
    "gclark",
    "hlewis",
    "iwalker",
    "jhall",
    "kallen",
    "lyoung",
    "mking",
    "nwright",
    "olopez",
    "phill",
    "qscott",
    "rgreen",
    "sadams",
    "tbaker",
    "ugonzalez",
    "vnelson",
    "wcarter",
    "xmitchell",
    "yperez",
    "zroberts",
    "svc_sql",
    "svc_web",
    "svc_backup",
    "svc_monitor",
    "DC01$",
    "DC02$",
    "FS01$",
    "SQL01$",
]

_OS_VERSIONS = [
    "Windows Server 2019 Build 17763 x64",
    "Windows Server 2022 Build 20348 x64",
    "Windows 10.0 Build 19041 x64",
    "Windows Server 2016 Build 14393 x64",
]

_SHARE_NAMES = [
    "ADMIN$",
    "C$",
    "IPC$",
    "NETLOGON",
    "SYSVOL",
    "Users",
    "Share",
    "IT",
    "Finance",
    "HR",
    "Public",
    "Backups",
    "Software",
    "Logs",
    "Data",
    "Projects",
    "Archive",
    "Temp",
    "Downloads",
    "Scripts",
]

_SHARE_COMMENTS = [
    "Remote Admin",
    "Default share",
    "Remote IPC",
    "Logon server share",
    "Logon server share",
    "",
    "User profiles",
    "Shared files",
    "IT Department",
    "Finance share",
    "Human Resources",
    "Public access",
    "Backup storage",
    "Software repository",
    "Log storage",
    "Data warehouse",
    "Project files",
    "Archive storage",
    "Temporary files",
    "Script repository",
]

_PERMISSIONS = ["READ", "WRITE", "READ,WRITE", ""]


def _rand_ip() -> str:
    return f"192.168.58.{_RNG.randint(1, 254)}"


def _rand_hash() -> str:
    return "".join(_RNG.choices("0123456789abcdef", k=32))


def _rand_aes() -> str:
    return "".join(_RNG.choices("0123456789abcdef", k=64))


# -- Generators returning 1000+ line strings --------------------------------


def gen_hosts_output(n: int = 1200) -> str:
    """Generate realistic netexec SMB scan output."""
    lines: list[str] = []
    for i in range(n):
        ip = f"192.168.58.{(i % 254) + 1}"
        host = _HOSTNAMES[i % len(_HOSTNAMES)]
        os_ver = _OS_VERSIONS[i % len(_OS_VERSIONS)]
        domain = "contoso.local"
        signing = _RNG.choice(["True", "False"])
        smbv1 = _RNG.choice(["True", "False"])
        lines.append(
            f"SMB  {ip}  445  {host:<15s} [*] {os_ver} "
            f"(name:{host}) (domain:{domain.upper()}) "
            f"(signing:{signing}) (SMBv1:{smbv1})"
        )
    return "\n".join(lines)


def gen_secretsdump_output(n: int = 1200) -> str:
    """Generate realistic secretsdump NTDS output."""
    lines: list[str] = [
        "[*] Dumping Domain Credentials (domain\\uid:rid:lmhash:nthash)",
        "[*] Using the DRSUAPI method to get NTDS.DIT secrets",
    ]
    for i in range(n):
        user = _USERS[i % len(_USERS)]
        rid = 500 + i
        lm = _rand_hash()
        nt = _rand_hash()
        lines.append(f"contoso.local\\{user}:{rid}:{lm}:{nt}:::")
    # Add a few AES keys
    for i in range(50):
        user = _USERS[i % len(_USERS)]
        lines.append(f"{user}:aes256-cts-hmac-sha1-96:{_rand_aes()}")
    return "\n".join(lines)


def gen_kerberos_hashes_output(n: int = 1200) -> str:
    """Generate realistic Kerberoasting/AS-REP roasting output."""
    lines: list[str] = []
    for i in range(n):
        user = _USERS[i % len(_USERS)]
        if i % 3 == 0:
            # TGS hash
            ticket_data = _rand_hash() * 4
            lines.append(
                f"$krb5tgs$23$*{user}$contoso.local$contoso.local/{user}*"
                f"${ticket_data[:16]}${ticket_data}"
            )
        elif i % 3 == 1:
            # AS-REP hash
            ticket_data = _rand_hash() * 4
            lines.append(f"$krb5asrep$23${user}@contoso.local:{ticket_data}")
        else:
            # Noise lines (tool status messages)
            lines.append(f"[*] Getting TGT for {user}@contoso.local")
    return "\n".join(lines)


def gen_delegation_output(n: int = 1200) -> str:
    """Generate realistic findDelegation.py output."""
    lines: list[str] = [
        "Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies",
        "",
        "AccountName      AccountType    DelegationType              DelegationRightsTo",
        "-----------      -----------    ----------------            ------------------",
    ]
    types = [
        ("Unconstrained", "N/A"),
        ("Constrained", "cifs/{host}.contoso.local"),
        ("Constrained", "MSSQLSvc/{host}.contoso.local:1433"),
        ("RBCD", "cifs/{host}.contoso.local"),
    ]
    for i in range(n):
        user = _USERS[i % len(_USERS)]
        acct_type = _RNG.choice(["Person", "Computer"])
        dt, spn_tpl = types[i % len(types)]
        host = _HOSTNAMES[i % len(_HOSTNAMES)].lower()
        spn = spn_tpl.format(host=host) if spn_tpl != "N/A" else "N/A"
        lines.append(f"{user:<16s} {acct_type:<14s} {dt:<27s} {spn}")
    return "\n".join(lines)


def gen_shares_output(n: int = 1200) -> str:
    """Generate realistic netexec --shares output."""
    lines: list[str] = []
    hosts_per_block = max(1, n // 20)
    idx = 0
    for h in range(20):
        ip = f"192.168.58.{h + 10}"
        host = _HOSTNAMES[h % len(_HOSTNAMES)]
        lines.append(
            f"SMB  {ip}  445  {host:<15s} [*] Windows Server 2019 Build 17763 x64 "
            f"(name:{host}) (domain:CONTOSO.LOCAL)"
        )
        lines.append(f"SMB  {ip}  445  {host:<15s} Share           Permissions     Comment")
        lines.append(f"SMB  {ip}  445  {host:<15s} -----           -----------     -------")
        for s in range(hosts_per_block):
            share = _SHARE_NAMES[(idx + s) % len(_SHARE_NAMES)]
            perm = _PERMISSIONS[(idx + s) % len(_PERMISSIONS)]
            comment = _SHARE_COMMENTS[(idx + s) % len(_SHARE_COMMENTS)]
            if perm:
                lines.append(f"SMB  {ip}  445  {host:<15s} {share:<15s} {perm:<15s} {comment}")
            else:
                lines.append(f"SMB  {ip}  445  {host:<15s} {share:<15s} {comment}")
            idx += 1
            if idx >= n:
                break
        if idx >= n:
            break
    return "\n".join(lines)


def gen_domain_sid_output(n: int = 1200) -> str:
    """Generate output with domain SID buried in noise."""
    lines: list[str] = []
    for i in range(n):
        if i == n // 2:
            lines.append("[*] Domain SID is: S-1-5-21-1328384573-4090356449-2552632942")
        elif i % 5 == 0:
            lines.append(f"[*] Brute forcing SIDs at 192.168.58.{i % 254 + 1}")
        else:
            user = _USERS[i % len(_USERS)]
            lines.append(f"500: contoso.local\\{user} (SidTypeUser)")
    return "\n".join(lines)


def gen_ntlm_hashes_output(n: int = 1200) -> str:
    """Generate NTLM hash output (same format as secretsdump)."""
    return gen_secretsdump_output(n)


def gen_users_output(n: int = 1200) -> str:
    """Generate realistic user enumeration output."""
    lines: list[str] = []
    for i in range(n):
        user = _USERS[i % len(_USERS)]
        ip = f"192.168.58.{i % 254 + 1}"
        variant = i % 4
        if variant == 0:
            lines.append(f"user:[{user}]")
        elif variant == 1:
            lines.append(f"Account: {user}")
        elif variant == 2:
            lines.append(f"sAMAccountName: {user}")
        else:
            lines.append(f"SMB  {ip}  445  DC01  {user}  2026-01-15 08:30:00")
    return "\n".join(lines)


def gen_plaintext_passwords_output(n: int = 1200) -> str:
    """Generate realistic plaintext password output."""
    lines: list[str] = []
    for i in range(n):
        user = _USERS[i % len(_USERS)]
        variant = i % 4
        if variant == 0:
            pw = f"P@ssw0rd{i:04d}"
            lines.append(f"user:[{user}]  Password: {pw}")
        elif variant == 1:
            pw = f"Winter{i:04d}!"
            lines.append(
                f"SMB  192.168.58.10  445  DC01  {user}  2026-01-15 08:30:00  Password: {pw}"
            )
        elif variant == 2:
            # LSA DefaultPassword block
            pw = f"Summer{i:04d}#"
            lines.append("[*] DefaultPassword")
            lines.append(f"CONTOSO\\{user}:{pw}")
        else:
            # LDAP entry style
            lines.append(f"dn: CN={user},OU=Users,DC=contoso,DC=local")
            lines.append(f"sAMAccountName: {user}")
            lines.append(f"description: Password: Secret{i:04d}!")
            lines.append("")
    return "\n".join(lines)


def gen_ticket_path_output(n: int = 1200) -> str:
    """Generate getST.py output with ticket path."""
    lines: list[str] = []
    for i in range(n):
        if i == n // 2:
            lines.append(
                "[*] Saving ticket in administrator@cifs_dc01.contoso.local@CONTOSO.LOCAL.ccache"
            )
        else:
            lines.append(f"[*] Getting TGT for user {i}")
    return "\n".join(lines)


def gen_spn_list(n: int = 1200) -> list[str]:
    """Generate a list of realistic SPNs."""
    services = [
        "cifs",
        "HTTP",
        "MSSQLSvc",
        "LDAP",
        "HOST",
        "GC",
        "exchangeMDB",
        "exchangeRFR",
        "WSMAN",
        "TERMSRV",
    ]
    spns: list[str] = []
    for i in range(n):
        svc = services[i % len(services)]
        host = _HOSTNAMES[i % len(_HOSTNAMES)].lower()
        fqdn = f"{host}.contoso.local"
        if svc == "MSSQLSvc" and i % 2 == 0:
            spns.append(f"{svc}/{fqdn}:1433")
        else:
            spns.append(f"{svc}/{fqdn}")
    return spns


# ---------------------------------------------------------------------------
# Benchmark runner
# ---------------------------------------------------------------------------

BenchmarkResult = dict[str, Any]


def _run_single_benchmark(
    name: str,
    func: Callable[..., Any],
    *args: Any,
    iterations: int = 100,
) -> BenchmarkResult:
    """Run a single function benchmark and return timing statistics."""
    # Warm-up run
    func(*args)

    times: list[float] = []
    for _ in range(iterations):
        t0 = time.perf_counter()
        result = func(*args)
        t1 = time.perf_counter()
        times.append(t1 - t0)

    mean_t = statistics.mean(times)
    return {
        "name": name,
        "iterations": iterations,
        "mean": mean_t,
        "min": min(times),
        "max": max(times),
        "stdev": statistics.stdev(times) if len(times) > 1 else 0.0,
        "ops_sec": 1.0 / mean_t if mean_t > 0 else float("inf"),
        "result_count": len(result) if isinstance(result, (list, tuple)) else (1 if result else 0),
    }


def run_all_benchmarks(iterations: int = 100) -> list[BenchmarkResult]:
    """Run benchmarks for all extraction functions and return results."""
    # Pre-generate all inputs once (not counted in benchmark time)
    hosts_data = gen_hosts_output()
    secretsdump_data = gen_secretsdump_output()
    kerberos_data = gen_kerberos_hashes_output()
    delegation_data = gen_delegation_output()
    shares_data = gen_shares_output()
    domain_sid_data = gen_domain_sid_output()
    ntlm_data = gen_ntlm_hashes_output()
    users_data = gen_users_output()
    passwords_data = gen_plaintext_passwords_output()
    ticket_data = gen_ticket_path_output()
    spn_list = gen_spn_list()

    benchmarks: list[tuple[str, Callable[..., Any], tuple[Any, ...]]] = [
        ("extract_hosts_from_output", extract_hosts_from_output, (hosts_data,)),
        ("extract_secretsdump_hashes", extract_secretsdump_hashes, (secretsdump_data,)),
        ("extract_kerberos_hashes", extract_kerberos_hashes, (kerberos_data,)),
        ("extract_delegation_entries", extract_delegation_entries, (delegation_data,)),
        ("extract_shares_from_output", extract_shares_from_output, (shares_data,)),
        ("extract_domain_sid", extract_domain_sid, (domain_sid_data,)),
        ("extract_ntlm_hashes", extract_ntlm_hashes, (ntlm_data,)),
        ("extract_users_from_output", extract_users_from_output, (users_data,)),
        (
            "extract_plaintext_passwords_from_output",
            extract_plaintext_passwords_from_output,
            (passwords_data,),
        ),
        ("extract_ticket_path_from_output", extract_ticket_path_from_output, (ticket_data,)),
        (
            "extract_host_from_spn",
            lambda spns: [extract_host_from_spn(s) for s in spns],
            (spn_list,),
        ),
    ]

    results: list[BenchmarkResult] = []
    for name, func, args in benchmarks:
        result = _run_single_benchmark(name, func, *args, iterations=iterations)
        results.append(result)

    return results


def format_results_table(results: list[BenchmarkResult]) -> str:
    """Format benchmark results as a nicely aligned table."""
    # Column widths
    name_w = max(len(r["name"]) for r in results)
    name_w = max(name_w, len("Function"))

    header = (
        f"{'Function':<{name_w}}  "
        f"{'Iters':>6}  "
        f"{'Mean (ms)':>10}  "
        f"{'Min (ms)':>10}  "
        f"{'Max (ms)':>10}  "
        f"{'Stdev (ms)':>10}  "
        f"{'Ops/sec':>10}  "
        f"{'Items':>6}"
    )
    sep = "-" * len(header)

    rows: list[str] = []
    for r in sorted(results, key=lambda x: x["mean"], reverse=True):
        rows.append(
            f"{r['name']:<{name_w}}  "
            f"{r['iterations']:>6}  "
            f"{r['mean'] * 1000:>10.3f}  "
            f"{r['min'] * 1000:>10.3f}  "
            f"{r['max'] * 1000:>10.3f}  "
            f"{r['stdev'] * 1000:>10.3f}  "
            f"{r['ops_sec']:>10.1f}  "
            f"{r['result_count']:>6}"
        )

    slowest = max(results, key=lambda x: x["mean"])
    fastest = min(results, key=lambda x: x["mean"])

    summary_lines = [
        "",
        f"Slowest: {slowest['name']} ({slowest['mean'] * 1000:.3f} ms mean)",
        f"Fastest: {fastest['name']} ({fastest['mean'] * 1000:.3f} ms mean)",
        f"Ratio:   {slowest['mean'] / fastest['mean']:.1f}x slower",
    ]

    return "\n".join([sep, header, sep, *rows, sep, *summary_lines])


# ---------------------------------------------------------------------------
# Pytest benchmark tests (marked with @pytest.mark.benchmark)
# ---------------------------------------------------------------------------

_BENCH_ITERATIONS = 100


@pytest.mark.benchmark
def test_bench_extract_hosts_from_output() -> None:
    data = gen_hosts_output()
    result = _run_single_benchmark(
        "extract_hosts_from_output",
        extract_hosts_from_output,
        data,
        iterations=_BENCH_ITERATIONS,
    )
    assert result["mean"] > 0
    assert result["result_count"] > 0


@pytest.mark.benchmark
def test_bench_extract_secretsdump_hashes() -> None:
    data = gen_secretsdump_output()
    result = _run_single_benchmark(
        "extract_secretsdump_hashes",
        extract_secretsdump_hashes,
        data,
        iterations=_BENCH_ITERATIONS,
    )
    assert result["mean"] > 0
    assert result["result_count"] > 0


@pytest.mark.benchmark
def test_bench_extract_kerberos_hashes() -> None:
    data = gen_kerberos_hashes_output()
    result = _run_single_benchmark(
        "extract_kerberos_hashes",
        extract_kerberos_hashes,
        data,
        iterations=_BENCH_ITERATIONS,
    )
    assert result["mean"] > 0
    assert result["result_count"] > 0


@pytest.mark.benchmark
def test_bench_extract_delegation_entries() -> None:
    data = gen_delegation_output()
    result = _run_single_benchmark(
        "extract_delegation_entries",
        extract_delegation_entries,
        data,
        iterations=_BENCH_ITERATIONS,
    )
    assert result["mean"] > 0
    assert result["result_count"] > 0


@pytest.mark.benchmark
def test_bench_extract_shares_from_output() -> None:
    data = gen_shares_output()
    result = _run_single_benchmark(
        "extract_shares_from_output",
        extract_shares_from_output,
        data,
        iterations=_BENCH_ITERATIONS,
    )
    assert result["mean"] > 0
    assert result["result_count"] > 0


@pytest.mark.benchmark
def test_bench_extract_domain_sid() -> None:
    data = gen_domain_sid_output()
    result = _run_single_benchmark(
        "extract_domain_sid",
        extract_domain_sid,
        data,
        iterations=_BENCH_ITERATIONS,
    )
    assert result["mean"] > 0
    assert result["result_count"] > 0


@pytest.mark.benchmark
def test_bench_extract_ntlm_hashes() -> None:
    data = gen_ntlm_hashes_output()
    result = _run_single_benchmark(
        "extract_ntlm_hashes",
        extract_ntlm_hashes,
        data,
        iterations=_BENCH_ITERATIONS,
    )
    assert result["mean"] > 0
    assert result["result_count"] > 0


@pytest.mark.benchmark
def test_bench_extract_users_from_output() -> None:
    data = gen_users_output()
    result = _run_single_benchmark(
        "extract_users_from_output",
        extract_users_from_output,
        data,
        iterations=_BENCH_ITERATIONS,
    )
    assert result["mean"] > 0
    assert result["result_count"] > 0


@pytest.mark.benchmark
def test_bench_extract_plaintext_passwords_from_output() -> None:
    data = gen_plaintext_passwords_output()
    result = _run_single_benchmark(
        "extract_plaintext_passwords_from_output",
        extract_plaintext_passwords_from_output,
        data,
        iterations=_BENCH_ITERATIONS,
    )
    assert result["mean"] > 0
    assert result["result_count"] > 0


@pytest.mark.benchmark
def test_bench_extract_ticket_path_from_output() -> None:
    data = gen_ticket_path_output()
    result = _run_single_benchmark(
        "extract_ticket_path_from_output",
        extract_ticket_path_from_output,
        data,
        iterations=_BENCH_ITERATIONS,
    )
    assert result["mean"] > 0
    assert result["result_count"] > 0


@pytest.mark.benchmark
def test_bench_extract_host_from_spn() -> None:
    spns = gen_spn_list()
    result = _run_single_benchmark(
        "extract_host_from_spn",
        lambda s: [extract_host_from_spn(x) for x in s],
        spns,
        iterations=_BENCH_ITERATIONS,
    )
    assert result["mean"] > 0
    assert result["result_count"] > 0


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def main() -> None:
    iterations = 100
    if len(sys.argv) > 1:
        try:
            iterations = int(sys.argv[1])
        except ValueError:
            print(f"Usage: {sys.argv[0]} [iterations]", file=sys.stderr)
            sys.exit(1)

    print("=" * 72)
    print("  Extraction Module Benchmark")
    print("=" * 72)
    print()
    print(f"  Backend:      {_BACKEND}")
    print(f"  Iterations:   {iterations}")
    print("  Input size:   ~1200 lines per function")
    print()

    print("Generating sample data ... ", end="", flush=True)
    t0 = time.perf_counter()
    # Trigger generators to verify they work before timing
    gen_hosts_output()
    gen_secretsdump_output()
    gen_kerberos_hashes_output()
    gen_delegation_output()
    gen_shares_output()
    gen_domain_sid_output()
    gen_ntlm_hashes_output()
    gen_users_output()
    gen_plaintext_passwords_output()
    gen_ticket_path_output()
    gen_spn_list()
    print(f"done ({time.perf_counter() - t0:.3f}s)")
    print()

    print(f"Running {iterations} iterations per function ...")
    print()

    results = run_all_benchmarks(iterations=iterations)
    print(format_results_table(results))
    print()

    # Summary by backend
    total_mean = sum(r["mean"] for r in results)
    print(f"Total mean time (all functions): {total_mean * 1000:.3f} ms")
    print(f"Backend: {_BACKEND}")
    print()


if __name__ == "__main__":
    main()
