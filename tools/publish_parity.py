#!/usr/bin/env python3
"""Publishing-parity gate: prove the /py layout still packages what it shipped.

Builds a package's wheel from ``py/`` and diffs it against a baseline release
on PyPI. The version string and the free-text long description (the README) are
always ignored — they are expected to change.

The gate is **directional** by default, so it works as an ongoing per-PR check
without red-flagging normal library evolution:

* **Regressions (fail):** something the last release shipped is now gone or a
  different install shape — a DROPPED module, a REMOVED dependency, a changed
  package ``Name``, a changed wheel platform/purelib tag, or a removed entry
  point. These are the "the reorg/relocation silently changed publishing"
  signals this gate exists to catch.
* **Additions / changes (pass, reported as notes):** a new module, an added or
  re-constrained dependency, a changed ``Requires-Python`` or classifier. These
  are legitimate and are reviewed in the PR diff itself.

``--strict`` promotes every difference to a failure — use it for the one-time
relocation proof against a specific pre-move release.

Usage (from ``py/``):
    uv run python tools/publish_parity.py                       # core, vs latest
    uv run python tools/publish_parity.py --baseline 3.11.1 --strict
    uv run python tools/publish_parity.py --package fastapi-identity-model
"""

from __future__ import annotations

import argparse
import email.parser
import io
from pathlib import Path
import re
import shutil
import subprocess
import sys
import zipfile

import httpx


#: The Python package root. This driver lives in the repo-root tools/ tree, so
#: py/ is a sibling of that tree rather than its parent.
PY_ROOT = Path(__file__).resolve().parents[1] / "py"

# Metadata headers expected to differ release-to-release and that say nothing
# about what is installed — never compared.
_VOLATILE_HEADERS = frozenset(
    {"Version", "Description", "Description-Content-Type", "Metadata-Version"}
)

# Leading distribution name of a Requires-Dist line, e.g. "httpx>=0.28,<1" or
# "httpx (>=0.28) ; extra == 'x'" -> "httpx".
_DIST_NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")

# Lowest HTTP status treated as a retryable server error.
_HTTP_SERVER_ERROR = 500


def _run(cmd: list[str], cwd: Path) -> None:
    subprocess.run(cmd, cwd=cwd, check=True)


def build_wheel(package: str) -> Path:
    """Build ``package`` from py/ and return the freshly built wheel path."""
    out = PY_ROOT / "dist" / "parity"
    shutil.rmtree(out, ignore_errors=True)  # never compare a stale wheel
    _run(
        ["uv", "build", "--wheel", "--package", package, "--out-dir", str(out)],
        cwd=PY_ROOT,
    )
    wheels = list(out.glob(f"{package.replace('-', '_')}-*.whl"))
    if len(wheels) != 1:
        sys.exit(f"parity: expected exactly one wheel for {package}, got {wheels}")
    return wheels[0]


def _get(client: httpx.Client, url: str) -> httpx.Response:
    """GET with retries covering 5xx and timeouts, not just connect errors."""
    last: Exception | None = None
    for _attempt in range(4):
        try:
            resp = client.get(url)
            if resp.status_code >= _HTTP_SERVER_ERROR:
                last = httpx.HTTPStatusError(
                    f"{resp.status_code}", request=resp.request, response=resp
                )
                continue
            return resp
        except (httpx.TransportError, httpx.HTTPStatusError) as err:
            last = err
    sys.exit(f"parity: could not fetch {url}: {last}")


def download_baseline_wheel(package: str, baseline: str) -> tuple[str, bytes]:
    """Return ``(version, wheel_bytes)`` for the baseline PyPI release."""
    with httpx.Client(timeout=60.0, follow_redirects=True) as client:
        resp = _get(client, f"https://pypi.org/pypi/{package}/json")
        if resp.status_code == httpx.codes.NOT_FOUND:
            sys.exit(f"parity: package {package} not found on PyPI")
        data = resp.raise_for_status().json()
        version = data["info"]["version"] if baseline == "latest" else baseline
        files = data["releases"].get(version)
        if not files:
            sys.exit(f"parity: {package} {version} not found on PyPI")
        wheel = next((f for f in files if f["filename"].endswith(".whl")), None)
        if wheel is None:
            sys.exit(f"parity: {package} {version} has no wheel on PyPI")
        return version, _get(client, wheel["url"]).raise_for_status().content


def _module_tree(zf: zipfile.ZipFile) -> set[str]:
    """Shipped code paths inside the wheel, excluding dist-info."""
    return {
        name
        for name in zf.namelist()
        if not name.endswith("/") and ".dist-info/" not in name
    }


def _dist_info_message(zf: zipfile.ZipFile, filename: str) -> email.message.Message:
    name = next(
        (n for n in zf.namelist() if n.endswith(f".dist-info/{filename}")), None
    )
    text = zf.read(name).decode("utf-8") if name else ""
    return email.parser.Parser().parsestr(text)


def _stable_metadata(zf: zipfile.ZipFile) -> dict[str, list[str]]:
    """METADATA headers minus the volatile ones, each sorted."""
    msg = _dist_info_message(zf, "METADATA")
    names = {key for key in set(msg.keys()) if key not in _VOLATILE_HEADERS}
    return {name: sorted(msg.get_all(name, [])) for name in names}


def _wheel_shape(zf: zipfile.ZipFile) -> dict[str, list[str]]:
    """The install-shape fields of the WHEEL file (platform/ABI tag, purelib)."""
    msg = _dist_info_message(zf, "WHEEL")
    return {
        "Tag": sorted(msg.get_all("Tag", [])),
        "Root-Is-Purelib": sorted(msg.get_all("Root-Is-Purelib", [])),
    }


def _entry_point_lines(zf: zipfile.ZipFile) -> set[str]:
    name = next(
        (n for n in zf.namelist() if n.endswith(".dist-info/entry_points.txt")),
        None,
    )
    if name is None:
        return set()
    return {
        ln.strip() for ln in zf.read(name).decode("utf-8").splitlines() if ln.strip()
    }


def _dep_names(requires: list[str]) -> set[str]:
    out = set()
    for line in requires:
        m = _DIST_NAME.match(line)
        if m:
            out.add(m.group(1).lower().replace("_", "-"))
    return out


def compare(
    built: Path, baseline_bytes: bytes, version: str, *, strict: bool
) -> tuple[list[str], list[str]]:
    """Return ``(regressions, notes)`` comparing the built wheel to the baseline."""
    regressions: list[str] = []
    notes: list[str] = []

    def flag(*, regression: bool, msg: str) -> None:
        (regressions if regression or strict else notes).append(msg)

    with (
        zipfile.ZipFile(built) as bz,
        zipfile.ZipFile(io.BytesIO(baseline_bytes)) as pz,
    ):
        built_tree, base_tree = _module_tree(bz), _module_tree(pz)
        regressions.extend(
            f"module DROPPED vs {version}: {m}" for m in sorted(base_tree - built_tree)
        )
        for a in sorted(built_tree - base_tree):
            flag(regression=False, msg=f"module added vs {version}: {a}")

        built_md, base_md = _stable_metadata(bz), _stable_metadata(pz)
        for key in sorted(set(built_md) | set(base_md)):
            if built_md.get(key) == base_md.get(key):
                continue
            if key == "Name":
                regressions.append(
                    f"package Name changed: {base_md.get(key)} -> {built_md.get(key)}"
                )
            elif key == "Requires-Dist":
                dropped = _dep_names(base_md.get(key, [])) - _dep_names(
                    built_md.get(key, [])
                )
                if dropped:
                    regressions.append(
                        f"dependency REMOVED vs {version}: {sorted(dropped)}"
                    )
                flag(
                    regression=False,
                    msg=f"Requires-Dist changed: baseline={base_md.get(key)} "
                    f"built={built_md.get(key)}",
                )
            else:
                flag(
                    regression=False,
                    msg=f"metadata {key} changed: baseline={base_md.get(key)} "
                    f"built={built_md.get(key)}",
                )

        if _wheel_shape(bz) != _wheel_shape(pz):
            regressions.append(
                f"wheel install-shape changed (Tag/Root-Is-Purelib): "
                f"built={_wheel_shape(bz)} baseline({version})={_wheel_shape(pz)}"
            )

        built_ep, base_ep = _entry_point_lines(bz), _entry_point_lines(pz)
        regressions.extend(
            f"entry point REMOVED vs {version}: {removed}"
            for removed in sorted(base_ep - built_ep)
        )
        for added in sorted(built_ep - base_ep):
            flag(regression=False, msg=f"entry point added: {added}")

    return regressions, notes


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--package",
        default="py-identity-model",
        choices=["py-identity-model", "fastapi-identity-model"],
    )
    parser.add_argument(
        "--baseline",
        default="latest",
        help="PyPI version to compare against (default: latest published)",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="treat every difference (not just regressions) as a failure",
    )
    args = parser.parse_args()

    print(f"[parity] building {args.package} from py/ ...")
    built = build_wheel(args.package)
    print(f"[parity] built {built.name}")
    version, baseline_bytes = download_baseline_wheel(args.package, args.baseline)
    print(f"[parity] baseline: {args.package} {version} from PyPI")

    regressions, notes = compare(built, baseline_bytes, version, strict=args.strict)
    for note in notes:
        print(f"[parity] note: {note}")
    if regressions:
        mode = "strict" if args.strict else "regressions"
        print(f"\n[parity] GATE FAILED — {args.package} packaging {mode}:")
        for r in regressions:
            print(f"  - {r}")
        return 1
    print(
        f"[parity] GATE PASSED — {args.package} still ships everything PyPI "
        f"{version} did ({len(notes)} additive change(s) noted)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
