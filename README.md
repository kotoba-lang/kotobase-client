# kotobase-client

Canonical, portable **ClojureScript client for the kotobase.net tenant Datom
plane** (`ai.gftd.apps.kotobase.datomic.*`) plus its byte-exact CACAO auth and
CID/graph derivation:

- `kotobase.client` — `q` / `datoms` / `pull` reads and `transact` writes over
  the operator db, minting `datom:read` / `datom:transact` CACAOs. Transient
  5xx from the kotoba-wasm tenant worker (its "Invalid array buffer length"
  db-load flake) are retried on idempotent reads; `transact` opts in via
  `:retry?` for idempotent keyed re-asserts.
- `kotobase.cacao` — SIWE/EIP-4361 message + Ed25519 did:key CACAO, DAG-CBOR
  encoded. The SAME source the cljs PDS verifies with, so client and server
  can't drift.
- `kotobase.cid` — did:key ⇄ Ed25519 pubkey, base58btc/base32, and
  `canonical-graph` (operator's `kotobase/db/<did>/<db-name>` CID).

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
npm test        # shadow-cljs :node-test — client (+retry) / cacao / cid
```
