# Independent minimal checker

`check.py` is the different-language checker for the frozen
`github-deployment-v1` accountability slice. It accepts released canonical
mandate bytes and explicit bindings; it does not serialize protocol objects or
perform network/storage I/O. Python's standard library independently computes
the tagged SHA-256 digest and OpenSSL verifies the detached Ed25519 signature.

Run it with `python3 tools/independent-checker/check.py VECTOR.json`. Exit zero
means valid. Rejections exit one and emit a stable JSON reason code.

This is deliberately a minimal checker, not a second source of protocol
meaning. Unsupported profiles and malformed or unavailable replay state fail
closed.
