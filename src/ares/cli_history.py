"""CLI for querying historical operation data from the persistent store.

This module provides commands for:
- Listing and searching historical operations
- Cross-operation credential/hash lookup
- MITRE ATT&CK coverage analysis
- Investigation management
"""

import asyncio
import json
import sys
from datetime import datetime, timezone
from typing import Annotated

import cyclopts
from loguru import logger


# Suppress DEBUG/INFO logs from noisy modules in CLI output
def _cli_log_filter(record):
    """Return whether a log record should be shown in CLI output."""
    module = record["name"]
    level = record["level"].no
    if module in {"ares.cli_history", "__main__"}:
        return True
    return level >= 30


logger.remove()
logger.add(sys.stderr, filter=_cli_log_filter)


app = cyclopts.App(
    name="ares-history",
    help="Query historical operation data from the persistent store",
)


def _check_enabled():
    """Exit if the persistent store is not configured."""
    from ares.core.persistent_store import get_persistent_store_config

    config = get_persistent_store_config()
    if not config.is_enabled:
        print("Persistent store not enabled. Set ARES_DATABASE_URL environment variable.")
        sys.exit(1)


# =============================================================================
# Operations Commands
# =============================================================================


@app.command(name="list")
def list_operations(
    domain: Annotated[str | None, cyclopts.Parameter(help="Filter by target domain")] = None,
    has_da: Annotated[
        bool | None, cyclopts.Parameter(help="Filter by domain admin achieved")
    ] = None,
    since_days: Annotated[
        int | None, cyclopts.Parameter(help="Operations from last N days")
    ] = None,
    limit: Annotated[int, cyclopts.Parameter(help="Maximum results")] = 50,
    json_output: Annotated[bool, cyclopts.Parameter("--json", help="Output as JSON")] = False,
):
    """List historical operations."""
    _check_enabled()
    asyncio.run(_list_operations(domain, has_da, since_days, limit, json_output))


async def _list_operations(
    domain: str | None,
    has_da: bool | None,
    since_days: int | None,
    limit: int,
    json_output: bool,
):
    from datetime import timedelta

    from ares.core.persistent_store import HistoricalQueryService

    service = HistoricalQueryService()
    if not await service.initialize():
        print("Failed to connect to persistent store")
        return

    since = None
    if since_days:
        since = datetime.now(timezone.utc) - timedelta(days=since_days)

    try:
        operations = await service.list_operations(
            domain=domain,
            has_da=has_da,
            since=since,
            limit=limit,
        )

        if json_output:
            data = [
                {
                    "operation_id": op.operation_id,
                    "target_domain": op.target_domain,
                    "target_ip": op.target_ip,
                    "started_at": op.started_at.isoformat(),
                    "completed_at": op.completed_at.isoformat() if op.completed_at else None,
                    "has_domain_admin": op.has_domain_admin,
                    "has_golden_ticket": op.has_golden_ticket,
                    "duration": op.duration_str,
                    "credentials": op.credential_count,
                    "hashes": op.hash_count,
                    "hosts": op.host_count,
                    "vulnerabilities": op.vulnerability_count,
                }
                for op in operations
            ]
            print(json.dumps(data, indent=2))
        else:
            if not operations:
                print("No operations found")
                return

            print(
                f"\n{'OPERATION ID':<30} {'DOMAIN':<25} {'DA':<4} {'CREDS':<6} {'HASHES':<7} {'DURATION':<12}"
            )
            print("-" * 95)
            for op in operations:
                da_mark = "Y" if op.has_domain_admin else "N"
                domain_display = (op.target_domain or "")[:24]
                print(
                    f"{op.operation_id:<30} {domain_display:<25} {da_mark:<4} "
                    f"{op.credential_count:<6} {op.hash_count:<7} {op.duration_str:<12}"
                )
            print(f"\nTotal: {len(operations)} operations")

    finally:
        await service.close()


@app.command(name="get")
def get_operation(
    operation_id: Annotated[str, cyclopts.Parameter(help="Operation ID to retrieve")],
    json_output: Annotated[bool, cyclopts.Parameter("--json", help="Output as JSON")] = False,
):
    """Get detailed information about a specific operation."""
    _check_enabled()
    asyncio.run(_get_operation(operation_id, json_output))


async def _get_operation(operation_id: str, json_output: bool):
    from ares.core.persistent_store import HistoricalQueryService

    service = HistoricalQueryService()
    if not await service.initialize():
        print("Failed to connect to persistent store")
        return

    try:
        operation = await service.get_operation(operation_id)
        if not operation:
            print(f"Operation not found: {operation_id}")
            return

        if json_output:
            data = {
                "operation_id": operation.operation_id,
                "target_domain": operation.target_domain,
                "target_ip": str(operation.target_ip) if operation.target_ip else None,
                "environment": operation.environment,
                "started_at": operation.started_at.isoformat(),
                "completed_at": operation.completed_at.isoformat()
                if operation.completed_at
                else None,
                "has_domain_admin": operation.has_domain_admin,
                "has_golden_ticket": operation.has_golden_ticket,
                "domain_admin_path": operation.domain_admin_path,
                "credential_count": len(operation.credentials),
                "hash_count": len(operation.hashes),
                "host_count": len(operation.hosts),
                "vulnerability_count": len(operation.vulnerabilities),
            }
            print(json.dumps(data, indent=2))
        else:
            print(f"\nOperation: {operation.operation_id}")
            print("=" * 60)
            print(f"Target Domain:  {operation.target_domain or 'N/A'}")
            print(f"Target IP:      {operation.target_ip or 'N/A'}")
            print(f"Environment:    {operation.environment or 'N/A'}")
            print(f"Started:        {operation.started_at}")
            print(f"Completed:      {operation.completed_at or 'Running'}")
            print(f"Domain Admin:   {'Yes' if operation.has_domain_admin else 'No'}")
            print(f"Golden Ticket:  {'Yes' if operation.has_golden_ticket else 'No'}")
            if operation.domain_admin_path:
                print(f"DA Path:        {operation.domain_admin_path}")
            print()
            print(f"Credentials:    {len(operation.credentials)}")
            print(f"Hashes:         {len(operation.hashes)}")
            print(f"Hosts:          {len(operation.hosts)}")
            print(f"Users:          {len(getattr(operation, 'users', []))}")
            print(f"Vulnerabilities: {len(operation.vulnerabilities)}")

    finally:
        await service.close()


@app.command(name="report")
def get_report(
    operation_id: Annotated[str, cyclopts.Parameter(help="Operation ID")],
    output: Annotated[str | None, cyclopts.Parameter("-o", help="Output file path")] = None,
):
    """Get the final report for an operation."""
    _check_enabled()
    asyncio.run(_get_report(operation_id, output))


async def _get_report(operation_id: str, output: str | None):
    from ares.core.persistent_store import HistoricalQueryService

    service = HistoricalQueryService()
    if not await service.initialize():
        print("Failed to connect to persistent store")
        return

    try:
        report = await service.get_operation_report(operation_id)
        if not report:
            print(f"No report found for operation: {operation_id}")
            return

        if output:
            from pathlib import Path

            Path(output).write_text(report)
            print(f"Report saved to: {output}")
        else:
            print(report)

    finally:
        await service.close()


# =============================================================================
# Search Commands
# =============================================================================


@app.command(name="search-creds")
def search_credentials(
    domain: Annotated[str | None, cyclopts.Parameter(help="Filter by domain")] = None,
    username: Annotated[str | None, cyclopts.Parameter(help="Filter by username (partial)")] = None,
    admin_only: Annotated[bool, cyclopts.Parameter("--admin", help="Only admin accounts")] = False,
    limit: Annotated[int, cyclopts.Parameter(help="Maximum results")] = 50,
    json_output: Annotated[bool, cyclopts.Parameter("--json", help="Output as JSON")] = False,
):
    """Search credentials across all historical operations."""
    _check_enabled()
    asyncio.run(_search_credentials(domain, username, admin_only, limit, json_output))


async def _search_credentials(
    domain: str | None,
    username: str | None,
    admin_only: bool,
    limit: int,
    json_output: bool,
):
    from ares.core.persistent_store import HistoricalQueryService

    service = HistoricalQueryService()
    if not await service.initialize():
        print("Failed to connect to persistent store")
        return

    try:
        credentials = await service.search_credentials(
            domain=domain,
            username=username,
            is_admin=True if admin_only else None,
            limit=limit,
        )

        if json_output:
            print(json.dumps(credentials, indent=2))
        else:
            if not credentials:
                print("No credentials found")
                return

            print(f"\n{'USERNAME':<25} {'DOMAIN':<25} {'ADMIN':<6} {'OPERATION':<25}")
            print("-" * 85)
            for cred in credentials:
                admin_mark = "Y" if cred.get("is_admin") else "N"
                print(
                    f"{cred['username'][:24]:<25} {(cred.get('domain') or '')[:24]:<25} "
                    f"{admin_mark:<6} {cred['operation_id'][:24]:<25}"
                )
            print(f"\nTotal: {len(credentials)} credentials")

    finally:
        await service.close()


@app.command(name="search-hashes")
def search_hashes(
    domain: Annotated[str | None, cyclopts.Parameter(help="Filter by domain")] = None,
    username: Annotated[str | None, cyclopts.Parameter(help="Filter by username")] = None,
    hash_type: Annotated[
        str | None, cyclopts.Parameter(help="Filter by type (ntlm, asrep, kerberoast)")
    ] = None,
    cracked_only: Annotated[
        bool, cyclopts.Parameter("--cracked", help="Only cracked hashes")
    ] = False,
    limit: Annotated[int, cyclopts.Parameter(help="Maximum results")] = 50,
    json_output: Annotated[bool, cyclopts.Parameter("--json", help="Output as JSON")] = False,
):
    """Search hashes across all historical operations."""
    _check_enabled()
    asyncio.run(_search_hashes(domain, username, hash_type, cracked_only, limit, json_output))


async def _search_hashes(
    domain: str | None,
    username: str | None,
    hash_type: str | None,
    cracked_only: bool,
    limit: int,
    json_output: bool,
):
    from ares.core.persistent_store import HistoricalQueryService

    service = HistoricalQueryService()
    if not await service.initialize():
        print("Failed to connect to persistent store")
        return

    try:
        hashes = await service.search_hashes(
            domain=domain,
            username=username,
            hash_type=hash_type,
            cracked_only=cracked_only,
            limit=limit,
        )

        if json_output:
            print(json.dumps(hashes, indent=2))
        else:
            if not hashes:
                print("No hashes found")
                return

            print(
                f"\n{'USERNAME':<25} {'DOMAIN':<20} {'TYPE':<12} {'CRACKED':<8} {'OPERATION':<20}"
            )
            print("-" * 90)
            for h in hashes:
                cracked = "Y" if h.get("is_cracked") else "N"
                print(
                    f"{h['username'][:24]:<25} {(h.get('domain') or '')[:19]:<20} "
                    f"{(h.get('hash_type') or '')[:11]:<12} {cracked:<8} {h['operation_id'][:19]:<20}"
                )
            print(f"\nTotal: {len(hashes)} hashes")

    finally:
        await service.close()


# =============================================================================
# MITRE Coverage
# =============================================================================


@app.command(name="mitre-coverage")
def mitre_coverage(
    since_days: Annotated[
        int | None, cyclopts.Parameter(help="Operations from last N days")
    ] = None,
    json_output: Annotated[bool, cyclopts.Parameter("--json", help="Output as JSON")] = False,
):
    """Show MITRE ATT&CK technique coverage across operations."""
    _check_enabled()
    asyncio.run(_mitre_coverage(since_days, json_output))


async def _mitre_coverage(since_days: int | None, json_output: bool):
    from datetime import timedelta

    from ares.core.persistent_store import HistoricalQueryService

    service = HistoricalQueryService()
    if not await service.initialize():
        print("Failed to connect to persistent store")
        return

    since = None
    if since_days:
        since = datetime.now(timezone.utc) - timedelta(days=since_days)

    try:
        coverage = await service.get_mitre_coverage(since=since)

        if json_output:
            data = [
                {
                    "technique_id": c.technique_id,
                    "occurrence_count": c.occurrence_count,
                    "operations": c.operations,
                }
                for c in coverage
            ]
            print(json.dumps(data, indent=2))
        else:
            if not coverage:
                print("No MITRE techniques found")
                return

            print(f"\n{'TECHNIQUE':<15} {'COUNT':<8} {'OPERATIONS'}")
            print("-" * 70)
            for c in coverage[:30]:  # Top 30
                ops_str = ", ".join(c.operations[:3])
                if len(c.operations) > 3:
                    ops_str += f" (+{len(c.operations) - 3} more)"
                print(f"{c.technique_id:<15} {c.occurrence_count:<8} {ops_str}")
            print(f"\nTotal: {len(coverage)} techniques")

    finally:
        await service.close()


# =============================================================================
# Investigations
# =============================================================================


@app.command(name="investigate")
def create_investigation(
    name: Annotated[str, cyclopts.Parameter(help="Investigation name")],
    description: Annotated[str | None, cyclopts.Parameter("-d", help="Description")] = None,
    operations: Annotated[
        list[str] | None, cyclopts.Parameter("-o", help="Operation IDs to include")
    ] = None,
):
    """Create a new investigation linking multiple operations."""
    _check_enabled()
    asyncio.run(_create_investigation(name, description, operations or []))


async def _create_investigation(name: str, description: str | None, operations: list[str]):
    from ares.core.persistent_store import HistoricalQueryService

    service = HistoricalQueryService()
    if not await service.initialize():
        print("Failed to connect to persistent store")
        return

    try:
        investigation = await service.create_investigation(
            name=name,
            description=description,
            operation_ids=operations or None,
        )

        if investigation:
            print(f"Created investigation: {investigation.name}")
            print(f"ID: {investigation.id}")
            if operations:
                print(f"Linked operations: {len(operations)}")
        else:
            print("Failed to create investigation")

    finally:
        await service.close()


@app.command(name="investigations")
def list_investigations(
    status: Annotated[str | None, cyclopts.Parameter(help="Filter by status")] = None,
    json_output: Annotated[bool, cyclopts.Parameter("--json", help="Output as JSON")] = False,
):
    """List investigations."""
    _check_enabled()
    asyncio.run(_list_investigations(status, json_output))


async def _list_investigations(status: str | None, json_output: bool):
    from ares.core.persistent_store import HistoricalQueryService

    service = HistoricalQueryService()
    if not await service.initialize():
        print("Failed to connect to persistent store")
        return

    try:
        investigations = await service.list_investigations(status=status)

        if json_output:
            data = [
                {
                    "id": str(inv.id),
                    "name": inv.name,
                    "status": inv.status,
                    "operation_count": len(inv.operation_ids or []),
                    "created_at": inv.created_at.isoformat(),
                }
                for inv in investigations
            ]
            print(json.dumps(data, indent=2))
        else:
            if not investigations:
                print("No investigations found")
                return

            print(f"\n{'NAME':<30} {'STATUS':<12} {'OPS':<6} {'CREATED'}")
            print("-" * 70)
            for inv in investigations:
                ops_count = len(inv.operation_ids or [])
                created = inv.created_at.strftime("%Y-%m-%d %H:%M")
                print(f"{inv.name[:29]:<30} {inv.status:<12} {ops_count:<6} {created}")
            print(f"\nTotal: {len(investigations)} investigations")

    finally:
        await service.close()


# =============================================================================
# Database Management
# =============================================================================


@app.command(name="init-db")
def init_database():
    """Initialize database tables (for development/testing)."""
    _check_enabled()
    asyncio.run(_init_database())


async def _init_database():
    from ares.core.persistent_store import PersistentStore

    store = PersistentStore()
    if not await store.initialize():
        print("Failed to connect to persistent store")
        return

    try:
        await store.create_tables()
        print("Database tables created successfully")
    finally:
        await store.close()


@app.command(name="apply-retention")
def apply_retention():
    """Apply retention policies to delete old data."""
    _check_enabled()
    asyncio.run(_apply_retention())


async def _apply_retention():
    from ares.core.persistent_store import HistoricalQueryService

    service = HistoricalQueryService()
    if not await service.initialize():
        print("Failed to connect to persistent store")
        return

    try:
        deleted = await service.apply_retention_policy()
        print("Retention policy applied:")
        for table, count in deleted.items():
            print(f"  {table}: {count} records deleted")
    finally:
        await service.close()


def main():
    """Run the ares-history CLI application."""
    app()


if __name__ == "__main__":
    main()
