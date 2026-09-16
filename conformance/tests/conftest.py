"""Pytest configuration for conformance harness tests.

Adds the ``conformance/`` directory to ``sys.path`` so the harness modules
(``run_tests``, ``app``) can be imported by tests without reorganising the
conformance layout into a package.

The conformance harness is intentionally not a Python package — it's a
standalone runner script and a FastAPI app. Tests for pure helpers inside
those scripts use this shim to import them.
"""

from pathlib import Path
import sys


CONFORMANCE_DIR = Path(__file__).parent.parent
if str(CONFORMANCE_DIR) not in sys.path:
    sys.path.insert(0, str(CONFORMANCE_DIR))

# ``scripts/`` holds standalone PEP 723 tools (e.g. rotate_conformance_token.py)
# whose pure helpers are unit-tested the same way.
SCRIPTS_DIR = CONFORMANCE_DIR / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))
