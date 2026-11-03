"""Detached release manifests and Ed25519 verification for built wheels."""

from __future__ import annotations

import hashlib
import io
import json
import os
import stat
import zipfile
import zlib
from email.parser import Parser
from pathlib import Path

import jsonschema
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

SCHEMA_VERSION = "1.0"
LOCKS = ("upstreams.json", "pylock.toml")
MAX_RELEASE_FILE_BYTES = 256 * 1024 * 1024
MAX_WHEEL_MEMBER_BYTES = 1024 * 1024


class ReleaseError(ValueError):
    """Invalid release manifest, signature, or artifact identity."""


def _regular_file(path: str | Path) -> tuple[Path, bytes]:
    if (
        not getattr(os, "O_NOFOLLOW", 0)
        or not getattr(os, "O_DIRECTORY", 0)
        or os.open not in os.supports_dir_fd
    ):
        raise ReleaseError(
            "Safe no-follow release reads are unavailable on this platform"
        )
    requested = Path(path).expanduser().absolute()
    if requested.is_symlink():
        raise ReleaseError(f"Symlink refused: {requested}")
    try:
        parent = requested.parent.resolve(strict=True)
        parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            opened_parent, named_parent = os.fstat(parent_fd), os.stat(parent)
            if (opened_parent.st_dev, opened_parent.st_ino) != (
                named_parent.st_dev,
                named_parent.st_ino,
            ):
                raise ReleaseError("Release file directory changed while opening")
            fd = os.open(
                requested.name,
                os.O_RDONLY
                | os.O_NOFOLLOW
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NONBLOCK", 0),
                dir_fd=parent_fd,
            )
            try:
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode):
                    raise ReleaseError(f"Expected a regular file: {requested}")
                if info.st_size > MAX_RELEASE_FILE_BYTES:
                    raise ReleaseError(
                        f"Release file exceeds {MAX_RELEASE_FILE_BYTES} bytes: {requested}"
                    )
                data = bytearray()
                while chunk := os.read(
                    fd, min(1024 * 1024, MAX_RELEASE_FILE_BYTES + 1 - len(data))
                ):
                    data.extend(chunk)
                    if len(data) > MAX_RELEASE_FILE_BYTES:
                        raise ReleaseError(
                            f"Release file exceeds {MAX_RELEASE_FILE_BYTES} bytes: {requested}"
                        )
                after = os.fstat(fd)
                if (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns) != (
                    after.st_dev,
                    after.st_ino,
                    after.st_size,
                    after.st_mtime_ns,
                ) or len(data) != info.st_size:
                    raise ReleaseError(f"File changed while reading: {requested}")
                return parent / requested.name, bytes(data)
            finally:
                os.close(fd)
        finally:
            os.close(parent_fd)
    except OSError as error:
        raise ReleaseError(
            f"Could not safely read release file: {requested}"
        ) from error


def _read_wheel_member(archive: zipfile.ZipFile, name: str) -> bytes:
    info = archive.getinfo(name)
    if info.file_size > MAX_WHEEL_MEMBER_BYTES:
        raise ReleaseError(
            f"Wheel member exceeds {MAX_WHEEL_MEMBER_BYTES} bytes: {name}"
        )
    contents = bytearray()
    try:
        with archive.open(info) as member:
            while chunk := member.read(
                min(64 * 1024, MAX_WHEEL_MEMBER_BYTES + 1 - len(contents))
            ):
                contents.extend(chunk)
                if len(contents) > MAX_WHEEL_MEMBER_BYTES:
                    raise ReleaseError(
                        f"Wheel member exceeds {MAX_WHEEL_MEMBER_BYTES} bytes: {name}"
                    )
    except (
        OSError,
        RuntimeError,
        EOFError,
        NotImplementedError,
        zlib.error,
        zipfile.BadZipFile,
    ) as error:
        raise ReleaseError(f"Wheel member is invalid: {name}") from error
    if len(contents) != info.file_size:
        raise ReleaseError(
            f"Wheel member size does not match its ZIP directory entry: {name}"
        )
    return bytes(contents)


def _wheel_identity(wheel: Path, raw: bytes) -> tuple[dict, dict[str, str]]:
    if not wheel.name.endswith(".whl"):
        raise ReleaseError("Release artifact must be a wheel")
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            metadata_name = next(
                name
                for name in archive.namelist()
                if name.endswith(".dist-info/METADATA")
            )
            wheel_name = metadata_name.removesuffix("METADATA") + "WHEEL"
            metadata = Parser().parsestr(
                _read_wheel_member(archive, metadata_name).decode("utf-8")
            )
            wheel_metadata = Parser().parsestr(
                _read_wheel_member(archive, wheel_name).decode("utf-8")
            )
            bundled_locks = {}
            for lock in LOCKS:
                matches = [
                    name
                    for name in archive.namelist()
                    if name.endswith(f".data/data/share/anti-rea/locks/{lock}")
                ]
                if len(matches) != 1:
                    raise ReleaseError(
                        f"Wheel must contain exactly one packaged {lock}"
                    )
                bundled_locks[lock] = hashlib.sha256(
                    _read_wheel_member(archive, matches[0])
                ).hexdigest()
    except (
        OSError,
        KeyError,
        StopIteration,
        UnicodeDecodeError,
        zipfile.BadZipFile,
        zlib.error,
    ) as error:
        raise ReleaseError(
            "Wheel metadata or packaged dependency locks are invalid"
        ) from error
    tags = wheel_metadata.get_all("Tag", [])
    if (
        metadata.get("Name", "").lower().replace("_", "-") != "anti-rea"
        or not metadata.get("Version")
        or not metadata.get("Requires-Python")
        or not tags
    ):
        raise ReleaseError(
            "Wheel metadata is missing product identity, Python requirement, or wheel tags"
        )
    return (
        {
            "filename": wheel.name,
            "sha256": hashlib.sha256(raw).hexdigest(),
            "size": len(raw),
            "tags": sorted(tags),
            "requires_python": metadata["Requires-Python"],
            "lock_sha256": bundled_locks,
        },
        {"name": "anti-rea", "version": metadata["Version"]},
    )


def create_manifest(wheel: str | Path, output: str | Path) -> dict:
    wheel_path, wheel_bytes = _regular_file(wheel)
    artifact, product = _wheel_identity(wheel_path, wheel_bytes)
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "record_type": "anti_rea_release",
        "product": product,
        "artifact": artifact,
    }
    _validate_manifest(manifest)
    encoded = (
        json.dumps(
            manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode()
        + b"\n"
    )
    _write_new(output, encoded, 0o644)
    return manifest


def sign_manifest(
    manifest: str | Path, private_key: str | Path, signature: str | Path
) -> dict:
    _, data = _regular_file(manifest)
    _, key_bytes = _regular_file(private_key)
    try:
        key = serialization.load_pem_private_key(key_bytes, password=None)
    except (TypeError, ValueError) as error:
        raise ReleaseError(
            "Private key must be an unencrypted PEM Ed25519 key"
        ) from error
    if not isinstance(key, Ed25519PrivateKey):
        raise ReleaseError("Release signing requires an Ed25519 private key")
    signed = key.sign(data)
    _write_new(signature, signed, 0o644)
    return {
        "status": "signed",
        "signature": str(Path(signature).resolve()),
        "signature_sha256": hashlib.sha256(signed).hexdigest(),
    }


def verify_release(
    manifest: str | Path,
    signature: str | Path,
    public_key: str | Path,
    wheel: str | Path,
) -> dict:
    manifest_path, data = _regular_file(manifest)
    _, signature_bytes = _regular_file(signature)
    _, key_bytes = _regular_file(public_key)
    wheel_path, wheel_bytes = _regular_file(wheel)
    try:
        key = serialization.load_pem_public_key(key_bytes)
    except (TypeError, ValueError) as error:
        raise ReleaseError("Public key must be PEM encoded") from error
    if not isinstance(key, Ed25519PublicKey):
        raise ReleaseError("Release verification requires an Ed25519 public key")
    try:
        key.verify(signature_bytes, data)
    except (InvalidSignature, ValueError) as error:
        raise ReleaseError("Release manifest signature is invalid") from error
    try:
        record = json.loads(data)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise ReleaseError("Signed release manifest is not valid JSON") from error
    if not isinstance(record, dict):
        raise ReleaseError("Signed release manifest must be an object")
    _validate_manifest(record)
    artifact = record.get("artifact", {}) if isinstance(record, dict) else {}
    actual, product = _wheel_identity(wheel_path, wheel_bytes)
    if (
        record.get("schema_version") != SCHEMA_VERSION
        or record.get("record_type") != "anti_rea_release"
        or record.get("product") != product
        or artifact != actual
        or artifact.get("filename") != wheel_path.name
    ):
        raise ReleaseError("Wheel identity does not match the signed release manifest")
    return {
        "status": "verified",
        "manifest": str(manifest_path),
        "wheel": wheel_path.name,
        "sha256": actual["sha256"],
        "signature": "ed25519",
    }


def _write_new(path: str | Path, data: bytes, mode: int) -> None:
    destination = Path(path).expanduser()
    if (
        destination.exists()
        or destination.is_symlink()
        or destination.parent.is_symlink()
        or not destination.parent.is_dir()
    ):
        raise ReleaseError("Output must be a new file in an existing real directory")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(destination, flags, mode)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except OSError as error:
        raise ReleaseError(f"Could not create release output: {destination}") from error


def _validate_manifest(record: dict) -> None:
    schema_path = (
        Path(__file__).resolve().parents[1] / "schemas/release-manifest-v1.schema.json"
    )
    try:
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        jsonschema.validate(record, schema)
    except (OSError, json.JSONDecodeError, jsonschema.ValidationError) as error:
        raise ReleaseError(
            "Release manifest does not match its versioned schema"
        ) from error
