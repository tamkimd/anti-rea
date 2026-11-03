# Verify Anti-REA's Python package before distribution

This page is for maintainers distributing **Anti-REA itself**. It creates a SHA-256 manifest for Anti-REA's Python wheel, optionally signs that manifest with Ed25519, and verifies that the wheel still matches. It does not sign, harden, or verify an application that Anti-REA analyzes. If you only use Anti-REA on your app, you can skip this page.

The repository does not currently publish a trusted signing identity. Until maintainers configure one and consumers trust its public key, these commands do not establish an authenticated release; an unsigned manifest is only a checksum record.

Create a detached manifest after building the exact wheel that will be distributed:

```sh
anti-rea release-manifest create releases/0.1.32/anti_rea-0.1.32-py3-none-any.whl releases/0.1.32/manifest.json
anti-rea release-manifest sign releases/0.1.32/manifest.json /secure/release-ed25519-private.pem releases/0.1.32/manifest.sig
anti-rea release-manifest verify releases/0.1.32/manifest.json releases/0.1.32/anti_rea-0.1.32-py3-none-any.whl
```

The manifest records wheel filename, SHA-256, size, wheel tags, `Requires-Python`, product version, and the hashes of the dependency locks embedded in the wheel. Verification checks the detached Ed25519 signature and independently inspects the supplied wheel bytes and embedded lockfiles. Output files are created without overwriting existing files.

Manifest creation, signing, and verification require no-follow, directory-relative opens for every input file; they fail closed when the platform cannot provide them.

Keep the private signing key outside the repository and restrict access through the organization's key or CI secret-management system. Distribute the public key through a channel independent of the wheel and manifest. A signature made with an untrusted key proves only possession of that key; this repository does not provide a trusted release identity or signing key. Do not describe a release as authenticated until its public key is trusted by the consumer.

`release-manifest create` is useful before a signing identity is configured, but an unsigned manifest only provides a comparison value when obtained through a trusted channel. Release acceptance remains incomplete until the release owner signs and verifies the exact final artifact using the trusted key.
