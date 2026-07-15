# csv-remote

Remote chain-dispatch adapter for the Parwana (WASM-REMOTE-001).

A browser or thin-client coordinator runs client-side validation, proof
verification, and the execution journal locally, but the concrete chain adapters
cannot compile to wasm and must not run in a browser tab. `RemoteChainAdapter`
implements the `ChainAdapter` port by encoding each call into a versioned
`csv-wire` envelope and forwarding it — over a `RemoteTransport` (bundled
`reqwest` HTTP transport, or any custom transport) — to a **user-owned native
host** (the `csv` daemon) that owns the real adapter registry.

The host (`csv runtime serve`) decodes the envelope with `host::dispatch` and
executes the exact registry call; it is a dumb port-forwarder, not a second
decision-maker. Finality and proof verification stay in the client coordinator,
and **no private key material crosses the wire** in either direction.
