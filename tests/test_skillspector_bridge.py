from __future__ import annotations

import json
import subprocess
import sys

from pathlib import Path

import pytest

import scripts.skillspector_bridge as bridge


def test_skillspector_sample_report_shape() -> None:
    payload = bridge._sample_payload()
    report = bridge._run_bridge(payload, sample=True)

    assert report['ok'] is True
    assert report['tool_count'] >= 1
    assert 'mcp_summary' in report
    assert isinstance(report['mcp_summary']['tool_results'], list)
    assert report['mcp_summary']['tool_results']
    assert set(report['vulnerability_summary'].keys()) >= {'total', 'blocked_by_policy', 'by_severity'}


def test_skillspector_cli_json() -> None:
    cp = subprocess.run(
        [sys.executable, 'scripts/skillspector_bridge.py', '--sample', '--json'],
        cwd=Path(__file__).resolve().parents[1],
        text=True,
        capture_output=True,
        check=False,
    )
    assert cp.returncode == 0, cp.stderr or cp.stdout
    payload = json.loads(cp.stdout)
    assert payload['ok'] is True
    assert payload['tool_count'] == len(payload['mcp_summary']['tool_results'])

