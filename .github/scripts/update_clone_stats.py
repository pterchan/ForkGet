#!/usr/bin/env python3
"""Merge GitHub clone traffic into a durable daily history and badge payload."""

from __future__ import annotations

import argparse
from datetime import date, datetime, timedelta, timezone
import json
from pathlib import Path
import sys
from typing import Any


class CloneStatsError(ValueError):
    """Raised when clone traffic cannot be merged without losing history."""


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--api-response", required=True, type=Path)
    parser.add_argument("--stats", required=True, type=Path)
    parser.add_argument("--badge", required=True, type=Path)
    parser.add_argument("--repository", required=True)
    return parser.parse_args(argv)


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise CloneStatsError(f"cannot read JSON from {path}: {error}") from error


def require_object(value: Any, context: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise CloneStatsError(f"{context} must be a JSON object")
    return value


def require_count(value: Any, context: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise CloneStatsError(f"{context} must be a non-negative integer")
    return value


def parse_utc_date(timestamp: Any) -> date:
    if not isinstance(timestamp, str):
        raise CloneStatsError("clone timestamp must be a string")
    normalized = timestamp[:-1] + "+00:00" if timestamp.endswith("Z") else timestamp
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as error:
        raise CloneStatsError(f"invalid clone timestamp: {timestamp}") from error
    if parsed.tzinfo is None:
        raise CloneStatsError(f"clone timestamp must include a UTC offset: {timestamp}")
    return parsed.astimezone(timezone.utc).date()


def parse_date(value: Any, context: str) -> date:
    if not isinstance(value, str):
        raise CloneStatsError(f"{context} must be an ISO date")
    try:
        return date.fromisoformat(value)
    except ValueError as error:
        raise CloneStatsError(f"{context} must be an ISO date: {value}") from error


def require_contiguous(days: set[date], context: str) -> None:
    if not days:
        raise CloneStatsError(f"{context} contains no daily records")
    current = min(days)
    while current <= max(days):
        if current not in days:
            raise CloneStatsError(
                f"{context} has an unrecoverable date gap at {current.isoformat()}"
            )
        current += timedelta(days=1)


def parse_api_response(payload: Any) -> dict[date, int]:
    api = require_object(payload, "API response")
    records = api.get("clones")
    if not isinstance(records, list):
        raise CloneStatsError("API response clones must be an array")

    daily: dict[date, int] = {}
    for index, value in enumerate(records):
        record = require_object(value, f"API clone record {index}")
        day = parse_utc_date(record.get("timestamp"))
        if day in daily:
            raise CloneStatsError(f"API response contains duplicate UTC date {day}")
        daily[day] = require_count(record.get("count"), f"clone count for {day}")
    require_contiguous(set(daily), "API response")
    return daily


def parse_existing_stats(payload: Any, repository: str) -> dict[date, int]:
    stats = require_object(payload, "existing clone stats")
    if stats.get("schema_version") != 1:
        raise CloneStatsError("existing clone stats schema_version must be 1")
    if stats.get("repository") != repository:
        raise CloneStatsError(
            f"existing clone stats repository must be {repository}"
        )
    records = stats.get("daily")
    if not isinstance(records, list):
        raise CloneStatsError("existing clone stats daily must be an array")

    daily: dict[date, int] = {}
    for index, value in enumerate(records):
        record = require_object(value, f"existing daily record {index}")
        day = parse_date(record.get("date"), f"date in existing daily record {index}")
        if day in daily:
            raise CloneStatsError(f"existing clone stats contains duplicate date {day}")
        daily[day] = require_count(record.get("count"), f"clone count for {day}")
    require_contiguous(set(daily), "existing clone stats")

    if parse_date(stats.get("tracking_since"), "tracking_since") != min(daily):
        raise CloneStatsError("tracking_since does not match the first daily record")
    if parse_date(stats.get("through"), "through") != max(daily):
        raise CloneStatsError("through does not match the last daily record")
    return daily


def build_outputs(
    repository: str, existing: dict[date, int], api: dict[date, int]
) -> tuple[dict[str, Any], dict[str, Any]]:
    merged = dict(existing)
    merged.update(api)
    require_contiguous(set(merged), "merged clone history")

    ordered_days = sorted(merged)
    daily = [{"date": day.isoformat(), "count": merged[day]} for day in ordered_days]
    total_clones = sum(record["count"] for record in daily)
    stats = {
        "schema_version": 1,
        "repository": repository,
        "tracking_since": ordered_days[0].isoformat(),
        "through": ordered_days[-1].isoformat(),
        "total_clones": total_clones,
        "daily": daily,
    }
    badge = {
        "schemaVersion": 1,
        "label": f"clones since {stats['tracking_since']}",
        "message": str(total_clones),
        "color": "blue",
    }
    return stats, badge


def render_json(payload: Any) -> str:
    return json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n"


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_json(payload), encoding="utf-8")


def run(args: argparse.Namespace) -> None:
    if args.stats.resolve() == args.badge.resolve():
        raise CloneStatsError("stats and badge paths must be different")
    api = parse_api_response(load_json(args.api_response))
    existing = (
        parse_existing_stats(load_json(args.stats), args.repository)
        if args.stats.exists()
        else {}
    )
    stats, badge = build_outputs(args.repository, existing, api)
    write_json(args.stats, stats)
    write_json(args.badge, badge)


def main(argv: list[str] | None = None) -> int:
    try:
        run(parse_args(argv))
    except CloneStatsError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
