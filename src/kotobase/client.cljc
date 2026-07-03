(ns kotobase.client
  "Promise-based ClojureScript client for the kotobase.net tenant Datom plane
  (`ai.gftd.apps.kotobase.datomic.*`). Runs in both the browser SPA and the
  cljs Workers (workerd/node) — global `fetch` + Web Crypto are present in both.

  Reads (`q`/`datoms`/`pull`) mint a `datom:read` CACAO by default (the
  operator yoro-social db is private); pass `:public? true` to skip auth when
  the graph is registered Public. Writes (`transact`) mint a
  `datom:transact`+`tx:create` CACAO. The single client identity IS the
  operator Ed25519 key, so `canonical-graph` resolves the operator's own
  `kotobase/db/<operator-did>/<db-name>` (the only writable namespace)."
  (:require ["@noble/curves/ed25519.js" :refer [ed25519]]
            [clojure.string :as str]
            [kotobase.cid :as cid]
            [kotobase.cacao :as cacao]))

(def ^:private datomic-ns "ai.gftd.apps.kotobase.datomic")

(defn make-client
  "opts: :endpoint (e.g. \"https://kotobase.net\"), :operator-did (CACAO
  audience, e.g. \"did:web:kotobase.net\"), and an identity — either
  :secret-key (32-byte Uint8Array seed = operator write identity) or, for a
  read-only AppView against a Public graph, :did (the operator DID, used only
  to derive the graph CID) + :public-reads? true. :fetch-fn optional."
  [{:keys [endpoint secret-key operator-did fetch-fn did public-reads?]}]
  (when (and (nil? secret-key) (nil? did))
    (throw (js/Error. "make-client needs :secret-key or :did")))
  {:endpoint (str/replace endpoint #"/+$" "")
   :secret-key secret-key
   :operator-did operator-did
   :public-reads? (boolean public-reads?)
   :fetch (or fetch-fn js/fetch)
   :did (or did (cid/did-key-from-ed25519-pub (.getPublicKey ed25519 secret-key)))})

(defn- read-cacao
  "A datom:read CACAO for `graph`, or nil when the client reads Public graphs /
  has no signing key (then the request is sent unauthenticated)."
  [client graph]
  (when (and (not (:public-reads? client)) (:secret-key client))
    (:cacao-b64 (cacao/mint-cacao {:secret-key (:secret-key client)
                                   :aud (:operator-did client)
                                   :capability "datom:read"
                                   :graph graph}))))

(defn- post
  "POST one datomic method. Returns a Promise of the parsed JSON body, or
  rejects with the HTTP status + text on non-2xx (the edge/pod return
  text/plain for auth/guard rejections, so we surface status before parsing).
  ALSO rejects on a 2xx response whose parsed body carries `\"ok\":false`
  (the handler dispatch shape every kotobase XRPC method uses for a LOGICAL
  failure — e.g. transact's ConcurrentWriteConflict on a lost head-CAS race —
  served over an ordinary HTTP 200, since the request itself was handled
  fine). A caller checking only `res.ok`/HTTP status, as this fn used to,
  treats that as success: confirmed live 2026-07-03, an etzhayyim actor
  mass-identify's createRecord calls kept returning a fabricated 200+uri+cid
  while the underlying transact had actually failed and reported so in its
  own body — every downstream caller (aozora.pds.repo/create-record chief
  among them) built its response from LOCALLY computed values instead of the
  transact result, masking the failure end-to-end. Fixing it here, once,
  covers every caller of transact/datoms/q/pull uniformly."
  [client method body cacao-b64]
  (let [{:keys [endpoint fetch did]} client
        headers #js {"content-type" "application/json"}
        full-body (cond-> body cacao-b64 (assoc :cacao_b64 cacao-b64))]
    (when cacao-b64
      (aset headers "authorization" (str "CACAO " cacao-b64))
      (aset headers "x-kotoba-did" did))
    (-> (fetch (str endpoint "/xrpc/" datomic-ns "." method)
               #js {:method "POST"
                    :headers headers
                    :body (js/JSON.stringify (clj->js full-body))})
        (.then (fn [^js res]
                 (.then (.text res)
                        (fn [text]
                          (if-not (.-ok res)
                            (let [e (js/Error. (str method " " (.-status res) ": " text))]
                              (set! (.-status e) (.-status res))
                              (throw e))
                            (let [^js parsed (if (seq text) (js/JSON.parse text) #js {})]
                              (if (false? (.-ok parsed))
                                (let [e (js/Error. (str method " " (.-status res) " ok:false "
                                                        (or (.-error parsed) "LogicalFailure")
                                                        (when (.-message parsed) (str ": " (.-message parsed)))))]
                                  (set! (.-status e) (.-status res))
                                  (set! (.-body e) parsed)
                                  (throw e))
                                parsed))))))))))

;; A graph with no Datomic/IPNS head yet (never written) reads as empty rather
;; than an error — mirrors kotoba.cljc fetchDatoms' 404 handling.
(defn- empty-on-404 [empty-val p]
  (.catch p (fn [^js err] (if (= 404 (.-status err)) empty-val (throw err)))))

;; The kotoba-wasm tenant worker intermittently 500s with "Invalid array buffer
;; length" while (re)loading a growing graph's blocks from R2 — a transient
;; fault in the WASM db-load allocation, fast-failing (~0.2 s) and uncorrelated
;; across isolates (ADR-2607022330 addendum; net-kotobase kotoba-wasm). Reads are
;; idempotent, so retrying a transient 5xx a few times turns the ~40% flake into
;; effectively 0 without touching the engine. Writes opt in (`:retry?`) and MUST
;; be idempotent (keyed re-assert) to be safe.
(defn- transient-5xx? [^js err]
  (let [s (.-status err)] (and (number? s) (>= s 500))))

(defn- jittered
  "backoff-ms ± up to 40%, so concurrent retriers don't hammer the same warm
  isolate in lockstep."
  [backoff-ms]
  (max 0 (long (* backoff-ms (+ 0.8 (* 0.4 (js/Math.random)))))))

(defn- with-retry
  "Retry a Promise-returning thunk on transient 5xx. Non-5xx (e.g. 404/403/401)
  reject immediately so empty-on-404 and auth handling are unaffected.

  Kept LIGHT on purpose. Measured behaviour: the wasm worker's failures are
  CORRELATED within any feasible synchronous window — spacing 5 retries over
  ~10 s failed at the SAME ~25% rate as a sub-second burst, just far slower. So
  aggressive backoff only adds latency; it can't break the floor (the graph is
  near the isolate memory limit and ~1-in-4 full-loads fail regardless of
  timing). This retry catches the genuinely-independent transients (smoothing
  the 40-90% spikes to the ~25% floor) while failing fast; jitter avoids
  lockstep. The durable fix is server-side (ADR-2607022330 addendum): the wasm
  worker must honour components_edn/limit (it ignores them today) or stream the
  export / compact the graph, so a read stops rehydrating the whole DB."
  ([thunk] (with-retry thunk 3 250))
  ([thunk tries backoff-ms]
   (-> (thunk)
       (.catch (fn [^js err]
                 (if (and (> tries 1) (transient-5xx? err))
                   (-> (js/Promise. (fn [res] (js/setTimeout res (jittered backoff-ms))))
                       (.then (fn [_] (with-retry thunk (dec tries)
                                        (min 1200 (* 2 backoff-ms))))))
                   (throw err)))))))

;; ── reads ────────────────────────────────────────────────────────────────────

(defn q
  "Datalog query (EDN string) against the operator's `db-name`."
  ([client db-name query-edn] (q client db-name query-edn nil))
  ([client db-name query-edn {:keys [limit offset public?]}]
   (let [graph (cid/canonical-graph (:did client) db-name)
         body (cond-> {:graph graph :query_edn query-edn}
                limit (assoc :limit limit)
                offset (assoc :offset offset))
         cacao (when-not public? (read-cacao client graph))]
     (empty-on-404 #js {:rows_edn #js []}
                   (with-retry #(post client "q" body cacao))))))

(defn datoms
  "Index scan (`:eavt` / `:aevt` / `:avet` / `:vaet`) over the operator db.
  `components` is an optional vector of EDN-string prefix components."
  ([client db-name index] (datoms client db-name index nil))
  ([client db-name index {:keys [components limit public?]}]
   (let [graph (cid/canonical-graph (:did client) db-name)
         body (cond-> {:graph graph :index index}
                (seq components) (assoc :components_edn (vec components))
                limit (assoc :limit limit))
         cacao (when-not public? (read-cacao client graph))]
     (empty-on-404 #js {:datoms #js []}
                   (with-retry #(post client "datoms" body cacao))))))

(defn pull
  "Pull `pattern-edn` for `entity` from the operator db."
  ([client db-name entity pattern-edn] (pull client db-name entity pattern-edn nil))
  ([client db-name entity pattern-edn {:keys [public?]}]
   (let [graph (cid/canonical-graph (:did client) db-name)
         body (cond-> {:graph graph :entity entity}
                pattern-edn (assoc :pattern_edn pattern-edn))
         cacao (when-not public? (read-cacao client graph))]
     (empty-on-404 #js {}
                   (with-retry #(post client "pull" body cacao))))))

;; ── writes ───────────────────────────────────────────────────────────────────

(defn transact
  "Transact an EDN tx-data string into the operator's `db-name`. The edge binds
  the write to `kotobase/db/<operator-did>/<db-name>` regardless of any
  client-supplied graph.

  `:retry?` retries a transient 5xx (the kotoba-wasm db-load flake). Set it ONLY
  when the tx is idempotent — a keyed re-assert (cardinality-one upsert) applied
  twice is a no-op, but an append with a fresh monotonic key (e.g. firehose seq)
  would duplicate. Default off."
  ([client db-name tx-edn] (transact client db-name tx-edn nil))
  ([client db-name tx-edn {:keys [ttl-sec retry?] :or {ttl-sec 300}}]
   (when-not (:secret-key client)
     (throw (js/Error. "transact needs a :secret-key (write) client")))
   (let [graph (cid/canonical-graph (:did client) db-name)
         cacao-b64 (:cacao-b64 (cacao/mint-cacao {:secret-key (:secret-key client)
                                                  :aud (:operator-did client)
                                                  :capability "datom:transact"
                                                  :extra-capabilities ["tx:create"]
                                                  :graph graph
                                                  :ttl-sec ttl-sec}))
         do-post #(post client "transact" {:db_name db-name :tx_edn tx-edn} cacao-b64)]
     (if retry? (with-retry do-post) (do-post)))))

;; ── EDN scalar decode (rows_edn / v_edn cells → cljs values) ─────────────────

(defn decode-edn-scalar
  "Parse one EDN scalar cell from a datomic.q/datoms result into a cljs value:
  \"string\" -> string, 42 -> number, true/false -> bool, nil -> nil,
  :kw -> \":kw\" (kept as-is). Mirrors the SDK's decodeEdnScalar."
  [cell]
  (if-not (string? cell)
    cell
    (let [s (str/trim cell)]
      (cond
        (zero? (count s)) s
        (= (first s) \") (try (js/JSON.parse s) (catch :default _ s))
        (= s "true") true
        (= s "false") false
        (= s "nil") nil
        (re-matches #"[+-]?\d+" s) (let [n (js/Number s)]
                                     (if (js/Number.isSafeInteger n) n s))
        (re-matches #"[+-]?\d*\.\d+([eE][+-]?\d+)?" s) (js/Number s)
        :else s))))
