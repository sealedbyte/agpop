#!/usr/bin/env python3
"""Generate and verify release-manifest.json and SHA256SUMS for agpop releases."""

import argparse
import datetime
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

REQUIRED_ARTIFACTS = (
    "agpop-linux-amd64",
    "agpop-linux-arm64",
    "agpop-darwin-arm64",
    "agpop-windows-amd64.exe",
    "agpop-windows-arm64.exe",
)

EXPECTED_DRAFT_FILES = (
    *REQUIRED_ARTIFACTS,
    *(f"{name}.sha256" for name in REQUIRED_ARTIFACTS),
    "SHA256SUMS",
    "release-manifest.json",
)

ALLOWED_MANIFEST_KEYS = frozenset(
    {
        "schema_version",
        "version",
        "tag",
        "prerelease",
        "commit",
        "published_at",
        "artifacts",
    }
)
IDEMPOTENT_MANIFEST_KEYS = (
    "schema_version",
    "version",
    "tag",
    "prerelease",
    "commit",
    "artifacts",
)

TAG_RE = re.compile(r"^v([0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?)$")
SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def parse_cargo_version(cargo_toml: Path) -> str:
    text = cargo_toml.read_text(encoding="utf-8")
    m = re.search(r'^version\s*=\s*"([^"]+)"', text, re.MULTILINE)
    if not m:
        raise ValueError(f"failed to parse package version from {cargo_toml}")
    return m.group(1)


def verify_binary_version(bin_path: Path, expected_version: str) -> None:
    out = subprocess.check_output([str(bin_path), "--version"], text=True).strip()
    expected = f"agpop {expected_version}"
    if out != expected:
        raise ValueError(
            f"binary --version mismatch for {bin_path}: expected '{expected}', got '{out}'"
        )


def validate_manifest_schema(manifest: object) -> dict:
    if not isinstance(manifest, dict):
        raise ValueError("release-manifest.json root must be a JSON object")

    unknown_keys = sorted(set(manifest.keys()) - ALLOWED_MANIFEST_KEYS)
    if unknown_keys:
        raise ValueError(f"manifest contains unknown fields: {unknown_keys}")

    schema_version = manifest.get("schema_version")
    if type(schema_version) is not int or schema_version != 1:
        raise ValueError(
            f"unsupported manifest schema_version: {schema_version!r} (expected integer 1)"
        )

    version = manifest.get("version")
    tag = manifest.get("tag")
    prerelease = manifest.get("prerelease")
    commit = manifest.get("commit")
    published_at = manifest.get("published_at", "")
    artifacts = manifest.get("artifacts")

    if not isinstance(version, str) or not version:
        raise ValueError("manifest 'version' must be a non-empty string")
    if not isinstance(tag, str) or not TAG_RE.fullmatch(tag):
        raise ValueError(f"manifest 'tag' has invalid format: {tag!r}")
    if tag != f"v{version}":
        raise ValueError(f"manifest tag '{tag}' does not match version '{version}'")
    expected_prerelease = "-" in version
    if type(prerelease) is not bool or prerelease != expected_prerelease:
        raise ValueError(
            f"manifest 'prerelease' must be {expected_prerelease} for version '{version}', got {prerelease!r}"
        )
    if not isinstance(published_at, str):
        raise ValueError("manifest 'published_at' must be a string")
    if not isinstance(commit, str) or not SHA1_RE.fullmatch(commit):
        raise ValueError(
            f"manifest 'commit' must be a 40-char lowercase hex SHA: {commit!r}"
        )
    if not isinstance(artifacts, dict) or set(artifacts.keys()) != set(REQUIRED_ARTIFACTS):
        raise ValueError("manifest 'artifacts' keys do not match REQUIRED_ARTIFACTS")

    for name in REQUIRED_ARTIFACTS:
        meta = artifacts[name]
        if not isinstance(meta, dict) or set(meta.keys()) != {"size", "sha256"}:
            raise ValueError(f"artifact '{name}' must have exact keys {{'size', 'sha256'}}")
        if type(meta.get("size")) is not int or meta["size"] <= 0:
            raise ValueError(f"artifact '{name}' has invalid size: {meta.get('size')!r}")
        if not isinstance(meta.get("sha256"), str) or not SHA256_RE.fullmatch(meta["sha256"]):
            raise ValueError(f"artifact '{name}' has invalid sha256: {meta.get('sha256')!r}")

    return manifest


def build_manifest(
    dist_dir: Path,
    tag: str,
    commit: str,
    cargo_toml: Path,
    verify_bin: Path | None = None,
) -> dict:
    if not TAG_RE.fullmatch(tag):
        raise ValueError(f"release tag has invalid format (got '{tag}')")
    version = tag[1:]

    cargo_ver = parse_cargo_version(cargo_toml)
    if cargo_ver != version:
        raise ValueError(
            f"tag/Cargo.toml version mismatch: tag='{tag}' ({version}) vs Cargo.toml='{cargo_ver}'"
        )

    commit_clean = commit.strip().lower()
    if not SHA1_RE.fullmatch(commit_clean):
        raise ValueError(f"commit must be a 40-char hex SHA (got '{commit}')")

    if verify_bin is not None:
        verify_binary_version(verify_bin, version)

    artifacts: dict[str, dict[str, int | str]] = {}
    sha256sums_lines: list[str] = []

    for name in REQUIRED_ARTIFACTS:
        bin_path = dist_dir / name
        sha_path = dist_dir / f"{name}.sha256"
        if not bin_path.is_file():
            raise FileNotFoundError(f"missing required release binary: {bin_path}")
        size = bin_path.stat().st_size
        if size <= 0:
            raise ValueError(f"release binary is empty (0 bytes): {bin_path}")
        actual_sha = sha256_file(bin_path)

        if not sha_path.is_file():
            raise FileNotFoundError(f"missing required checksum file: {sha_path}")
        recorded_sha = sha_path.read_text(encoding="utf-8").strip().split()[0].lower()
        if recorded_sha != actual_sha:
            raise ValueError(
                f"checksum mismatch for {name}: {sha_path} has {recorded_sha}, actual is {actual_sha}"
            )

        artifacts[name] = {
            "size": size,
            "sha256": actual_sha,
        }
        sha256sums_lines.append(f"{actual_sha}  {name}\n")

    published_at = (
        datetime.datetime.now(datetime.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
    manifest = {
        "schema_version": 1,
        "version": version,
        "tag": tag,
        "prerelease": "-" in version,
        "commit": commit_clean,
        "published_at": published_at,
        "artifacts": artifacts,
    }
    validate_manifest_schema(manifest)

    (dist_dir / "SHA256SUMS").write_text("".join(sha256sums_lines), encoding="utf-8")
    (dist_dir / "release-manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )
    return manifest


def verify_idempotent_manifests(existing_path: Path, new_path: Path) -> None:
    old_m = validate_manifest_schema(
        json.loads(existing_path.read_text(encoding="utf-8"))
    )
    new_m = validate_manifest_schema(json.loads(new_path.read_text(encoding="utf-8")))
    for key in IDEMPOTENT_MANIFEST_KEYS:
        if old_m.get(key) != new_m.get(key):
            raise ValueError(
                f"conflicting release manifest for {new_m.get('tag')}: field '{key}' differs "
                f"(existing={old_m.get(key)} vs new={new_m.get(key)})"
            )


def verify_draft_assets(assets_json_path: Path, dist_dir: Path) -> None:
    data = json.loads(assets_json_path.read_text(encoding="utf-8"))
    assets = {a["name"]: a["size"] for a in data.get("assets", [])}
    for fname in EXPECTED_DRAFT_FILES:
        local_file = dist_dir / fname
        if not local_file.is_file():
            raise FileNotFoundError(f"missing local file in dist: {local_file}")
        expected_size = local_file.stat().st_size
        if fname not in assets:
            raise ValueError(f"draft release is missing asset '{fname}'")
        if assets[fname] != expected_size:
            raise ValueError(
                f"draft asset '{fname}' size mismatch: remote={assets[fname]}, local={expected_size}"
            )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dist-dir", type=Path, help="Directory containing built artifacts")
    parser.add_argument("--tag", help="Release tag (e.g. v0.5.0-beta)")
    parser.add_argument("--commit", help="40-char git commit SHA")
    parser.add_argument("--cargo-toml", type=Path, default=Path("Cargo.toml"))
    parser.add_argument("--verify-bin", type=Path, help="Runnable binary to verify --version")
    parser.add_argument(
        "--verify-idempotent",
        nargs=2,
        metavar=("EXISTING_MANIFEST", "NEW_MANIFEST"),
        type=Path,
        help="Verify that an existing release manifest matches the newly generated manifest",
    )
    parser.add_argument(
        "--verify-draft-assets",
        type=Path,
        help="Path to JSON output of `gh release view <tag> --json assets`",
    )
    args = parser.parse_args()

    try:
        if args.verify_idempotent:
            verify_idempotent_manifests(args.verify_idempotent[0], args.verify_idempotent[1])
            return 0
        if args.verify_draft_assets:
            if not args.dist_dir:
                raise ValueError("--dist-dir is required with --verify-draft-assets")
            verify_draft_assets(args.verify_draft_assets, args.dist_dir)
            return 0
        if not (args.dist_dir and args.tag and args.commit):
            raise ValueError("--dist-dir, --tag, and --commit are required to build manifest")
        build_manifest(
            dist_dir=args.dist_dir,
            tag=args.tag,
            commit=args.commit,
            cargo_toml=args.cargo_toml,
            verify_bin=args.verify_bin,
        )
        return 0
    except Exception as exc:
        print(f"release-manifest error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
