import os
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile
import jsonschema
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from core import release


class ReleaseManifestTests(unittest.TestCase):
    def _wheel(self, path, extra=b"content", lock=b"lock"):
        metadata="Metadata-Version: 2.4\nName: anti-rea\nVersion: 0.1.0\nRequires-Python: >=3.11\n\n"
        wheel="Wheel-Version: 1.0\nGenerator: fixture\nRoot-Is-Purelib: true\nTag: py3-none-any\n\n"
        with zipfile.ZipFile(path,"w") as archive:
            archive.writestr("anti_rea-0.1.0.dist-info/METADATA",metadata)
            archive.writestr("anti_rea-0.1.0.dist-info/WHEEL",wheel)
            archive.writestr("anti_rea-0.1.0.data/data/share/anti-rea/locks/upstreams.json",b"{}")
            archive.writestr("anti_rea-0.1.0.data/data/share/anti-rea/locks/pylock.toml",lock)
            archive.writestr("fixture.bin",extra)

    def test_signed_manifest_binds_wheel_metadata_and_embedded_locks(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);wheel=root/"anti_rea-0.1.0-py3-none-any.whl"
            manifest=root/"release.json";signature=root/"release.sig"
            private=root/"private.pem";public=root/"public.pem"
            self._wheel(wheel)
            key=Ed25519PrivateKey.generate()
            private.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
            public.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo))
            record=release.create_manifest(wheel,manifest)
            jsonschema.validate(record,json.loads((Path(__file__).parents[1]/"schemas/release-manifest-v1.schema.json").read_text()))
            self.assertEqual(record["artifact"]["sha256"],hashlib.sha256(wheel.read_bytes()).hexdigest())
            self.assertEqual(set(record["artifact"]["lock_sha256"]),{"upstreams.json","pylock.toml"})
            release.sign_manifest(manifest,private,signature)
            result=release.verify_release(manifest,signature,public,wheel)
            self.assertEqual(result["status"],"verified")

    def test_signature_and_wheel_tampering_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);wheel=root/"anti_rea-0.1.0-py3-none-any.whl"
            manifest=root/"release.json";signature=root/"release.sig"
            private=root/"private.pem";public=root/"public.pem"
            self._wheel(wheel)
            key=Ed25519PrivateKey.generate()
            private.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
            public.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo))
            release.create_manifest(wheel,manifest);release.sign_manifest(manifest,private,signature)
            saved=manifest.read_bytes();manifest.write_bytes(saved+b" ")
            with self.assertRaisesRegex(release.ReleaseError,"signature is invalid"):
                release.verify_release(manifest,signature,public,wheel)
            manifest.write_bytes(saved)
            changed=root/"anti_rea-0.1.0-py3-none-any.whl";self._wheel(changed,b"different artifact")
            with self.assertRaisesRegex(release.ReleaseError,"does not match"):
                release.verify_release(manifest,signature,public,changed)

    def test_wheel_member_uncompressed_size_is_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);wheel=root/"anti_rea-0.1.0-py3-none-any.whl"
            metadata="Metadata-Version: 2.4\nName: anti-rea\nVersion: 0.1.0\nRequires-Python: >=3.11\n\n"
            wheel_metadata="Wheel-Version: 1.0\nGenerator: fixture\nRoot-Is-Purelib: true\nTag: py3-none-any\n\n"
            with zipfile.ZipFile(wheel,"w",compression=zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("anti_rea-0.1.0.dist-info/METADATA",metadata)
                archive.writestr("anti_rea-0.1.0.dist-info/WHEEL",wheel_metadata)
                archive.writestr("anti_rea-0.1.0.data/data/share/anti-rea/locks/upstreams.json",b"{}")
                archive.writestr("anti_rea-0.1.0.data/data/share/anti-rea/locks/pylock.toml",
                                 b"x"*(release.MAX_WHEEL_MEMBER_BYTES+1))
            self.assertLess(wheel.stat().st_size,release.MAX_WHEEL_MEMBER_BYTES)
            with self.assertRaisesRegex(release.ReleaseError,"Wheel member exceeds"):
                release.create_manifest(wheel,root/"manifest.json")

    def test_wheel_identity_uses_the_authenticated_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);wheel=root/"anti_rea-0.1.0-py3-none-any.whl"
            self._wheel(wheel,b"original")
            authenticated=wheel.read_bytes()
            replacement=root/"replacement.whl";self._wheel(replacement,b"replacement",b"other lock")
            wheel.write_bytes(replacement.read_bytes())
            artifact,_=release._wheel_identity(wheel,authenticated)
            self.assertEqual(artifact["sha256"],hashlib.sha256(authenticated).hexdigest())
            self.assertEqual(artifact["lock_sha256"]["pylock.toml"],hashlib.sha256(b"lock").hexdigest())

    def test_outputs_do_not_overwrite_existing_files_or_follow_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);wheel=root/"anti_rea-0.1.0-py3-none-any.whl"
            self._wheel(wheel);manifest=root/"release.json"
            release.create_manifest(wheel,manifest)
            with self.assertRaisesRegex(release.ReleaseError,"new file"):
                release.create_manifest(wheel,manifest)
            linked=root/"linked.whl";linked.symlink_to(wheel)
            with self.assertRaisesRegex(release.ReleaseError,"Symlink refused"):
                release.create_manifest(linked,root/"linked.json")

    def test_release_reads_fail_closed_without_nofollow(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);wheel=root/"anti_rea-0.1.0-py3-none-any.whl"
            self._wheel(wheel)
            with patch.object(release.os, "O_NOFOLLOW", 0):
                with self.assertRaisesRegex(release.ReleaseError, "no-follow release reads"):
                    release.create_manifest(wheel,root/"release.json")

    @unittest.skipUnless(hasattr(os, "mkfifo"), "named pipes are POSIX-only")
    def test_release_reader_rejects_fifo_without_blocking(self):
        with tempfile.TemporaryDirectory() as directory:
            fifo = Path(directory) / "release.whl"
            os.mkfifo(fifo)
            result = subprocess.run(
                [sys.executable, "-c",
                 "import sys; from core.release import _regular_file; _regular_file(sys.argv[1])",
                 str(fifo)], capture_output=True, text=True, timeout=2,
                cwd=Path(__file__).parents[1])
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Expected a regular file", result.stderr)

    def test_cli_creates_signs_and_verifies_release(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);wheel=root/"anti_rea-0.1.0-py3-none-any.whl"
            manifest=root/"release.json";signature=root/"release.sig"
            private=root/"private.pem";public=root/"public.pem"
            self._wheel(wheel);key=Ed25519PrivateKey.generate()
            private.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
            public.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo))
            cli=Path(__file__).parents[1]/"interfaces/cli/anti_rea.py"
            for args in (("create",wheel,manifest),("sign",manifest,private,signature),
                         ("verify",manifest,signature,public,wheel)):
                result=subprocess.run([sys.executable,str(cli),"release-manifest",*map(str,args)],
                                      capture_output=True,text=True)
                self.assertEqual(result.returncode,0,result.stdout+result.stderr)


if __name__ == "__main__":
    unittest.main()
