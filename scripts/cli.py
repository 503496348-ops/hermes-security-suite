#!/usr/bin/env python3
"""Unified CLI for hermes-security-suite. Delegates to doctor/scripts/hermes_doctor.py."""
import subprocess
import sys
import os

if __name__ == '__main__':
    script = os.path.join(os.path.dirname(__file__), '..', 'doctor', 'scripts', 'hermes_doctor.py')
    result = subprocess.run([sys.executable, script] + sys.argv[1:])
    sys.exit(result.returncode)
