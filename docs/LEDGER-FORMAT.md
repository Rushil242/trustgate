# Ledger format

TrustGate writes one JSON object per line to `audit.jsonl`. Each line carries
the hash of the line before it. This page is enough to write a verifier in any
language.

## Version 2 (signed)

Written by the guard room daemon, which holds a machine key. A version 2 entry
has `"v": 2`, a `key_id`, a `sig`, and its time in `ts_ms`.

**Canonical bytes.** Take the entry, remove `entry_hash` and `sig`, and
serialise it as JSON with keys sorted by code point, no spaces (`,` and `:`
separators), and every non-ASCII character written as a lower-case `\uXXXX`
escape (UTF-16 surrogate pairs above U+FFFF). Values may be strings, integers,
`true`, `false`, `null`, arrays and objects. Floats are not allowed anywhere,
and every key is ASCII. That is why time is whole milliseconds in `ts_ms`.

**Hash.** `entry_hash` is the lower-case hex SHA-256 of the canonical bytes
followed directly by the previous entry's `entry_hash` (the empty string for
the first entry), encoded as UTF-8.

**Signature.** `sig` is the base64 Ed25519 signature, by the machine key, over
the ASCII bytes of `entry_hash`. `key_id` is `ed25519:` plus the first 16 hex
characters of the SHA-256 of the raw 32-byte public key.

**Chain rules.** `seq` starts at 0 and goes up by one. `prev_hash` equals the
previous line's `entry_hash`. Once a signed entry appears, every later entry
must be signed too.

**Test vectors.** `tests/vectors/ledger_v2.json` holds a key seed, its public
key, two entries and the exact canonical bytes of the first. A verifier in
another language should reproduce both hashes and accept both signatures.

## Version 1 (original)

Entries without `v`. Same chain rules and hash construction, but `ts` is a
float in seconds and there is no signature. Python prints floats in a way
other languages may not match, so version 1 is only reliably checked by
TrustGate itself.

## Kinds

`decision` (the gate's verdict on one action) and `resolution` (how an
escalation was answered). Field meanings are documented on `AuditEntry` and
`ResolutionEntry` in `trustgate/core/models.py`.
