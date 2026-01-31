---
name: skillsign
version: 1.1.0
description: Sign and verify agent skill folders with ed25519 keys. Detect tampering, manage trusted authors, revoke compromised keys, and track provenance chains (isnād).
---

# skillsign

Cryptographic signing and verification for agent skill folders using ed25519 keys. Protects your skills from tampering and lets you verify who wrote them.

## Install

```bash
pip3 install cryptography
```

That's the only dependency. The tool is a single Python file.

## Commands

### Generate a signing identity
```bash
python3 skillsign.py keygen
python3 skillsign.py keygen --name myagent
```
Creates an ed25519 keypair in `~/.skillsign/keys/`. Share the `.pub` file. Keep the `.pem` file secret.

### Sign a skill folder
```bash
python3 skillsign.py sign ./my-skill/
python3 skillsign.py sign ./my-skill/ --key ~/.skillsign/keys/myagent.pem
```
Hashes every file (SHA-256), builds a manifest, signs it with your private key. Creates `.skillsig/` inside the folder.

### Verify a skill folder
```bash
python3 skillsign.py verify ./my-skill/
```
Detects modified, added, or removed files. Verifies the cryptographic signature. Checks if the signer has been revoked. Shows whether the signer is trusted.

### Inspect signature metadata
```bash
python3 skillsign.py inspect ./my-skill/
```
Shows signer fingerprint, timestamp, file count, and all covered files with their hashes.

### Trust an author
```bash
python3 skillsign.py trust ./their-key.pub
```
Adds a public key to your local trusted authors list.

### List trusted authors
```bash
python3 skillsign.py trusted
```

### View provenance chain (isnād)
```bash
python3 skillsign.py chain ./my-skill/
```
Shows the full signing history — every author who signed the folder, in order.

### Revoke a compromised key
```bash
python3 skillsign.py revoke --key ~/.skillsign/keys/myagent.pem
python3 skillsign.py revoke --key ~/.skillsign/keys/myagent.pem --reason "Key leaked"
```
Creates a self-signed revocation statement. Automatically removes the key from trusted authors. After revocation:
- Signatures made **after** revocation → rejected by verify
- Signatures made **before** revocation → pass with a warning

### List revoked keys
```bash
python3 skillsign.py revoked
```

## When to Use

- **After installing a new skill** — verify it hasn't been tampered with
- **Before running untrusted code** — check who signed it and whether you trust them
- **Periodically** — re-verify your skill folders to detect unauthorized modifications
- **When publishing skills** — sign your work so others can verify it came from you
- **When a key is compromised** — revoke it immediately to prevent abuse
- **When auditing your agent's integrity** — run verify on all your skill folders

## Example Workflow

```bash
# First time: create your identity
python3 skillsign.py keygen --name parker

# Sign your skills
python3 skillsign.py sign ~/.openclaw/skills/my-skill/

# Later: check nothing changed
python3 skillsign.py verify ~/.openclaw/skills/my-skill/
# ✅ Verified — 14 files intact.
#    Signer: ca3458e92b73e432 [TRUSTED]

# Someone tampers with a file:
python3 skillsign.py verify ~/.openclaw/skills/my-skill/
# ❌ TAMPERED — Files changed since signing:
#    ~ main.py (modified)

# Trust another agent's key
python3 skillsign.py trust ./other-agent.pub

# View full provenance
python3 skillsign.py chain ~/.openclaw/skills/my-skill/

# Key compromised? Revoke it:
python3 skillsign.py revoke --key ~/.skillsign/keys/parker.pem --reason "Key leaked"
# 🔴 Revoked: ca3458e92b73e432
#    Signatures made after this timestamp will fail verification.
```
