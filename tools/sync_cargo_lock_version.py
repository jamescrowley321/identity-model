#!/usr/bin/env python3
"""Keep ``rust/Cargo.lock``'s own entry for the crate in step with ``Cargo.toml``.

Cargo records the workspace's own crate in its lockfile like any dependency, so
a version bump in ``rust/Cargo.toml`` leaves the lock one version behind until
something regenerates it. ``cargo publish`` refuses to run against a working
tree with uncommitted changes, and ``cargo build`` rewrites the stale lock as
its first act — so a release commit that bumps only the manifest produces a tag
whose checkout dirties itself and fails to publish (exit 101,
``uncommitted changes: Cargo.lock``). Every ``rust-v*`` tag from 0.1.0 through
0.3.1 failed that way.

This script is python-semantic-release's ``build_command`` for the Rust track
(``py/tools/semantic-release-rust.toml``): PSR runs it after writing the new
version into ``rust/Cargo.toml`` but before creating the release commit, and
``rust/Cargo.lock`` is listed in ``assets`` so the synced lock lands in that
same commit. The tag therefore points at a tree cargo already agrees with.

It lives in the repo-root ``tools/`` tree, with the other cross-language repo
infrastructure (``spec_coverage_gate.py``), rather than under ``py/`` — it is
release machinery for the Rust crate, not part of the published Python package,
and its tests run outside the library suite (``make test-tools``).

``--check`` runs the same comparison without writing, and is the guard
``release-rust.yml`` uses at the tag before it builds or publishes.

Deliberately stdlib-only and cargo-free: it runs on the release runner, which
sets up Python but no Rust toolchain.
"""

from __future__ import annotations

import argparse
from pathlib import Path
import re
import sys


#: Repo root, resolved from this file (tools/x.py) rather than the cwd, so the
#: script behaves the same however PSR or a workflow step invokes it.
REPO_ROOT = Path(__file__).resolve().parents[1]

#: Exit codes. The guard distinguishes "the lock is stale" (actionable: the
#: release commit must carry both files) from "these files are not the shape
#: this script understands" (a bug here, or a cargo format change).
EXIT_OK = 0
EXIT_DRIFT = 1
EXIT_MALFORMED = 2

DEFAULT_CRATE = "rs-identity-model"
DEFAULT_MANIFEST = REPO_ROOT / "rust" / "Cargo.toml"
DEFAULT_LOCK = REPO_ROOT / "rust" / "Cargo.lock"

_VERSION_LINE = re.compile(r'^version\s*=\s*"(?P<version>[^"]*)"\s*$')
_NAME_LINE = re.compile(r'^name\s*=\s*"(?P<name>[^"]*)"\s*$')
_TABLE_HEADER = re.compile(r"^\s*\[")


class SyncError(Exception):
    """The manifest or lockfile did not have the shape this script requires."""


def read_manifest_version(manifest_text: str) -> str:
    """Return the ``[package] version`` declared in a ``Cargo.toml``.

    Only the ``[package]`` table is considered: a ``version`` key under
    ``[dependencies]`` or a ``[profile.*]`` table must never be mistaken for the
    crate's own version.
    """
    in_package = False
    for line in manifest_text.splitlines():
        stripped = line.strip()
        if _TABLE_HEADER.match(line):
            in_package = stripped == "[package]"
            continue
        if not in_package:
            continue
        match = _VERSION_LINE.match(stripped)
        if match:
            return match.group("version")
    raise SyncError("no [package] version found in the Cargo manifest")


def _package_blocks(lock_text: str) -> list[tuple[int, int]]:
    """Return (start, end) line-index bounds for each ``[[package]]`` block."""
    lines = lock_text.splitlines()
    starts = [i for i, line in enumerate(lines) if line.strip() == "[[package]]"]
    bounds: list[tuple[int, int]] = []
    for position, start in enumerate(starts):
        end = starts[position + 1] if position + 1 < len(starts) else len(lines)
        bounds.append((start, end))
    return bounds


def lock_version(lock_text: str, crate: str) -> str:
    """Return the version ``lock_text`` records for ``crate``."""
    lines = lock_text.splitlines()
    for start, end in _package_blocks(lock_text):
        block = lines[start:end]
        if not any(
            (m := _NAME_LINE.match(line.strip())) and m.group("name") == crate
            for line in block
        ):
            continue
        for line in block:
            match = _VERSION_LINE.match(line.strip())
            if match:
                return match.group("version")
        raise SyncError(f"the [[package]] entry for {crate!r} has no version")
    raise SyncError(f"no [[package]] entry for {crate!r} in the lockfile")


def sync_lock(lock_text: str, crate: str, version: str) -> str:
    """Return ``lock_text`` with ``crate``'s version set to ``version``.

    Rewrites the version line inside the crate's own ``[[package]]`` block and
    nothing else — dependency entries that happen to share the version string
    are left untouched. Preserves the file's trailing newline.
    """
    lines = lock_text.splitlines()
    for start, end in _package_blocks(lock_text):
        block = lines[start:end]
        if not any(
            (m := _NAME_LINE.match(line.strip())) and m.group("name") == crate
            for line in block
        ):
            continue
        for offset, line in enumerate(block):
            if _VERSION_LINE.match(line.strip()):
                lines[start + offset] = f'version = "{version}"'
                trailer = "\n" if lock_text.endswith("\n") else ""
                return "\n".join(lines) + trailer
        raise SyncError(f"the [[package]] entry for {crate!r} has no version")
    raise SyncError(f"no [[package]] entry for {crate!r} in the lockfile")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--crate",
        default=DEFAULT_CRATE,
        help="crate name to sync (default: %(default)s)",
    )
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--lock", type=Path, default=DEFAULT_LOCK)
    parser.add_argument(
        "--check",
        action="store_true",
        help="report drift and exit 1 instead of rewriting the lockfile",
    )
    args = parser.parse_args(argv)

    try:
        manifest_version = read_manifest_version(args.manifest.read_text())
        lock_text = args.lock.read_text()
        recorded = lock_version(lock_text, args.crate)
    except (OSError, SyncError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_MALFORMED

    if recorded == manifest_version:
        print(f"{args.crate} {manifest_version}: Cargo.lock already in sync")
        return EXIT_OK

    if args.check:
        print(
            f"error: {args.lock} records {args.crate} {recorded} but "
            f"{args.manifest} declares {manifest_version}. The release commit "
            f"must carry both files; `cargo publish` fails on the resulting "
            f"dirty tree.",
            file=sys.stderr,
        )
        return EXIT_DRIFT

    args.lock.write_text(sync_lock(lock_text, args.crate, manifest_version))
    print(f"{args.crate}: Cargo.lock {recorded} -> {manifest_version}")
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
