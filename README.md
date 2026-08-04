# kotobase-client

Canonical, portable **ClojureScript client for the kotobase.net tenant Datom
plane** (`ai.gftd.apps.kotobase.datomic.*`) plus its byte-exact CACAO auth and
CID/graph derivation:

**Disambiguation (ADR-2607050900):** not to be confused with
[`kotobase`](https://github.com/kotoba-lang/kotobase) (the server-side
`IStore` port / umbrella datom database this client talks to) or
[`kotoba-client`](https://github.com/kotoba-lang/kotoba-client) (a separate,
*generic, non-CACAO* CID-verified block ingest/hydrate client over kotoba's
content graph, consumed by `p2p` — no relation to the CACAO-authed
kotobase.net tenant plane this repo is specific to).

- `kotobase.client` — `q` / `datoms` / `pull` reads, `transact` writes, and
  `fold` (D1 maintenance: compacts accumulated novelty into a fresh indexed
  snapshot — head-mutating like `transact`, but with no `:retry?` opt-in of
  its own) over the operator db, minting `datom:read` / `datom:transact`
  CACAOs. Transient 5xx from the kotoba-wasm tenant worker (its "Invalid
  array buffer length" db-load flake) are retried on idempotent reads;
  `transact` opts in via `:retry?` for idempotent keyed re-asserts.
- `kotobase.cacao` — SIWE/EIP-4361 message + Ed25519 did:key CACAO, DAG-CBOR
  encoded. The SAME source the cljs PDS verifies with, so client and server
  can't drift.
- `kotobase.cid` — did:key ⇄ Ed25519 pubkey, base58btc/base32/base36,
  `ipns-name->ed25519-pub` / `ipns-name-matches-pub?`, and
  `canonical-graph` (operator's `kotobase/db/<did>/<db-name>` CID).
- `kotobase.ipns` — sign/verify a signed IPNS head record
  (ADR-2607061800), the `:cljs` counterpart to `kotoba-lang/tech-ipfs-
  specs-ipns`'s `:clj`-only `ipns.head`. Verified byte-identical to the
  JVM side for the same seed+record (canonical dag-cbor payload +
  deterministic Ed25519 signature) against a real JVM-signed fixture,
  not just cljs self-consistency.

  **`verify-head` resolves the authoritative key from the name.** A `k51…`
  name IS `pubkey->name` of its Ed25519 key, so a record's own
  `:public_key_multibase` is only ever a restatement of it. Until
  2026-08-04 this checked the signature and not that binding, so any
  keypair could sign a record carrying somebody else's name and have it
  verify — and `kotobase-server`'s publish endpoint, whose only other gate
  is sequence monotonicity, accepted it. `ipns_test/name-takeover-is-
  refused` reproduces that against the unpatched code. See superproject
  **ADR-2608047000**.

  `kotobase.cid`'s base36/IPNS-name decode is a deliberate second
  implementation of `ipns.core`'s portable `.cljc` one: this library is
  consumed as a bare shadow-cljs `:source-path`, so a `deps.edn` git dep
  here would not resolve in consumer builds. The golden vectors in
  `cid_test` — including `ipns.core-test`'s own real-Kubo-node vector —
  are what keeps the two copies from drifting.

Runs in the browser SPA and the cljs Cloudflare Workers (workerd/node) — global
`fetch` + Web Crypto in both.

## Why this repo exists

`kotobase.client/cacao/cid` used to be **hand-copied byte-for-byte** into
`app-aozora`, `app-aozora-boundary`, and `kami-genko`. A fix in one copy (e.g.
the transient-5xx retry) silently skipped the others. This repo is the single
source of truth; consumers add its `src` to their shadow-cljs `:source-paths`
and delete their embedded copy.

## Use (consumer shadow-cljs.edn)

```clojure
:source-paths ["src" "test"
               "../../../../kotoba-lang/kotobase-client/src"]  ; west checkout
```

Consumers provide the npm deps (`@noble/curves` v1, `@noble/hashes`,
`@ipld/dag-cbor`) in their own `package.json`.

## Standalone test

```bash
npm install
npm test        # shadow-cljs :node-test — client (+retry, +fold) / cacao / cid / ipns
```
