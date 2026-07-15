"""Optional FastAPI service for hermes-security-suite diagnostics."""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys

from hermes_security_history_store import latest_runs, save_run

try:
    from fastapi import FastAPI
except Exception:
    FastAPI = None  # type: ignore

from doctor import ROOT, collect_run_report


def _run_doctor():
    cp = subprocess.run(
        [sys.executable, str(ROOT / 'scripts' / 'doctor.py'), '--format', 'json'],
        capture_output=True,
        text=True,
        timeout=120,
    )
    if cp.returncode == 0:
        try:
            payload = json.loads(cp.stdout)
            checks = payload.get('checks', []) if isinstance(payload, dict) else []
            return bool(payload.get('passed', False)), checks
        except Exception:
            pass
    return False, [
        {
            'name': 'doctor command',
            'ok': False,
            'fix': (cp.stderr or cp.stdout).strip()[:360] or 'doctor 运行失败',
        }
    ]


def create_app():
    if FastAPI is None:
        raise RuntimeError('请先安装 fastapi 与 uvicorn（pip install fastapi uvicorn）')

    app = FastAPI(title='hermes-security-suite', version='0.1.0')

    @app.get('/health')
    def health():
        return {'status': 'ok', 'service': 'hermes-security-suite'}

    @app.get('/diag')
    def diag():
        return collect_run_report(ROOT)

    @app.get('/diag/latest')
    def diag_latest(limit: int = 10):
        return latest_runs(limit=limit)

    @app.post('/diag/run')
    def diag_run():
        passed, checks = _run_doctor()
        report = collect_run_report(ROOT)
        run_id = hashlib.sha1((report['checked_at'] + str(report['checks'])).encode()).hexdigest()[:16]
        save_run(run_id=run_id, checks=checks, passed=passed)
        return {
            'run_id': run_id,
            'passed': passed,
            'checks': checks,
            'checks_total': len(checks),
            'failed_checks': len([c for c in checks if not c.get('ok')]),
        }

    return app


def main() -> int:
    if FastAPI is None:
        raise RuntimeError('请先安装 fastapi 与 uvicorn（pip install fastapi uvicorn）')
    parser = argparse.ArgumentParser(description='hermes-security-suite API')
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=8763)
    args = parser.parse_args()
    import uvicorn
    uvicorn.run(create_app(), host=args.host, port=args.port)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
