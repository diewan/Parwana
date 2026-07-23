# Accountability Verification Corpus v0.1

This corpus indexes deterministic, test-only first-slice vectors. The source
tests construct canonical protocol objects through `csv-accountability`; the
manifest records the expected verifier disposition and stable reason code.

These fixtures are conformance inputs, not claims that a deployment occurred.
Contradiction, custody, and preservation-renewal vectors exercise their
canonical protocol objects. Preservation vectors retain the original bytes,
reject historical rewrites, and evaluate algorithm status only through the
hash-addressed policy supplied to the pure verifier.
