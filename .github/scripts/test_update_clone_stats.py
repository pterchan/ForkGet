#!/usr/bin/env python3
"""Tests for the durable GitHub clone traffic merger."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("update_clone_stats.py")


def write_json(path: Path, payload: object) -> None:
    path.write_text(json.dumps(payload), encoding="utf-8")


class UpdateCloneStatsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        self.api = self.root / "api.json"
        self.stats = self.root / "clone-stats.json"
        self.badge = self.root / "badge.json"

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def run_script(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--api-response",
                str(self.api),
                "--stats",
                str(self.stats),
                "--badge",
                str(self.badge),
                "--repository",
                "pterchan/ForkGet",
            ],
            check=False,
            capture_output=True,
            text=True,
        )

    def test_creates_sorted_stats_and_shields_badge(self) -> None:
        write_json(
            self.api,
            {
                "count": 7,
                "uniques": 4,
                "clones": [
                    {"timestamp": "2026-11-15T00:00:00Z", "count": 5, "uniques": 3},
                    {"timestamp": "2026-11-15T00:30:00+01:00", "count": 2, "uniques": 1},
                ],
            },
        )

        result = self.run_script()

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            json.loads(self.stats.read_text()),
            {
                "schema_version": 1,
                "repository": "pterchan/ForkGet",
                "tracking_since": "2026-11-14",
                "through": "2026-11-15",
                "total_clones": 7,
                "daily": [
                    {"date": "2026-11-14", "count": 2},
                    {"date": "2026-11-15", "count": 5},
                ],
            },
        )
        self.assertEqual(
            json.loads(self.badge.read_text()),
            {
                "schemaVersion": 1,
                "label": "clones since 2026-11-14",
                "message": "7",
                "color": "blue",
            },
        )

    def test_upserts_overlap_and_recalculates_total(self) -> None:
        write_json(
            self.stats,
            {
                "schema_version": 1,
                "repository": "pterchan/ForkGet",
                "tracking_since": "2026-11-13",
                "through": "2026-11-14",
                "total_clones": 999,
                "daily": [
                    {"date": "2026-11-13", "count": 2},
                    {"date": "2026-11-14", "count": 3},
                ],
            },
        )
        write_json(
            self.api,
            {
                "clones": [
                    {"timestamp": "2026-11-14T00:00:00Z", "count": 4, "uniques": 3},
                    {"timestamp": "2026-11-15T00:00:00Z", "count": 5, "uniques": 4},
                ]
            },
        )

        result = self.run_script()

        self.assertEqual(result.returncode, 0, result.stderr)
        stats = json.loads(self.stats.read_text())
        self.assertEqual(stats["total_clones"], 11)
        self.assertEqual(stats["through"], "2026-11-15")
        self.assertEqual(stats["daily"][1]["count"], 4)

    def test_same_input_is_byte_for_byte_idempotent(self) -> None:
        write_json(
            self.api,
            {
                "clones": [
                    {"timestamp": "2026-11-14T00:00:00Z", "count": 2, "uniques": 1}
                ]
            },
        )
        self.assertEqual(self.run_script().returncode, 0)
        first_stats = self.stats.read_bytes()
        first_badge = self.badge.read_bytes()

        self.assertEqual(self.run_script().returncode, 0)

        self.assertEqual(self.stats.read_bytes(), first_stats)
        self.assertEqual(self.badge.read_bytes(), first_badge)

    def test_backfills_earlier_contiguous_dates(self) -> None:
        write_json(
            self.stats,
            {
                "schema_version": 1,
                "repository": "pterchan/ForkGet",
                "tracking_since": "2026-11-15",
                "through": "2026-11-16",
                "total_clones": 7,
                "daily": [
                    {"date": "2026-11-15", "count": 3},
                    {"date": "2026-11-16", "count": 4},
                ],
            },
        )
        write_json(
            self.api,
            {
                "clones": [
                    {"timestamp": "2026-11-13T00:00:00Z", "count": 1, "uniques": 1},
                    {"timestamp": "2026-11-14T00:00:00Z", "count": 2, "uniques": 2},
                    {"timestamp": "2026-11-15T00:00:00Z", "count": 3, "uniques": 2},
                ]
            },
        )

        result = self.run_script()

        self.assertEqual(result.returncode, 0, result.stderr)
        stats = json.loads(self.stats.read_text())
        self.assertEqual(stats["tracking_since"], "2026-11-13")
        self.assertEqual(stats["through"], "2026-11-16")
        self.assertEqual(stats["total_clones"], 10)

    def test_unrecoverable_gap_fails_without_overwriting_outputs(self) -> None:
        original_stats = {
            "schema_version": 1,
            "repository": "pterchan/ForkGet",
            "tracking_since": "2026-11-13",
            "through": "2026-11-14",
            "total_clones": 5,
            "daily": [
                {"date": "2026-11-13", "count": 2},
                {"date": "2026-11-14", "count": 3},
            ],
        }
        write_json(self.stats, original_stats)
        self.badge.write_text("existing badge\n", encoding="utf-8")
        write_json(
            self.api,
            {
                "clones": [
                    {"timestamp": "2026-11-17T00:00:00Z", "count": 4, "uniques": 3},
                    {"timestamp": "2026-11-18T00:00:00Z", "count": 5, "uniques": 4},
                ]
            },
        )
        stats_before = self.stats.read_bytes()
        badge_before = self.badge.read_bytes()

        result = self.run_script()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unrecoverable date gap at 2026-11-15", result.stderr)
        self.assertEqual(self.stats.read_bytes(), stats_before)
        self.assertEqual(self.badge.read_bytes(), badge_before)

    def test_api_internal_gap_is_rejected(self) -> None:
        write_json(
            self.api,
            {
                "clones": [
                    {"timestamp": "2026-11-14T00:00:00Z", "count": 2, "uniques": 1},
                    {"timestamp": "2026-11-16T00:00:00Z", "count": 3, "uniques": 2},
                ]
            },
        )

        result = self.run_script()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unrecoverable date gap at 2026-11-15", result.stderr)
        self.assertFalse(self.stats.exists())
        self.assertFalse(self.badge.exists())


if __name__ == "__main__":
    unittest.main()
