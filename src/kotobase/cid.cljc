(ns kotobase.cid
  "Deterministic graph-CID + did:key derivation for kotobase.net.

  Byte-identical to the kotobase.net edge (net-kotobase worker/src/app.cljc:
  base32LowerNoPad / graphCidFromName) and the @gftd/kotobase-datomic SDK
  (net-kotobase/sdk/kotobase-datomic/src/index.cljc). A graph handle is the
  CIDv1/dag-cbor/sha2-256 of the name `kotobase/db/<did>/<db-name>`, so the
  edge can recompute exactly this from the caller DID + db_name and pin it
  into every write (a client-supplied graph can never override it).

  ClojureScript-only (not .cljc): the SHA-256 seam is @noble/hashes, which has
  no JVM analogue here. All ops are synchronous (noble sha256 is sync), unlike
  the SDK's async crypto.subtle path."
  (:require [clojure.string :as str]
            ["@noble/hashes/sha2.js" :refer [sha256]]))

(def ^:private b58-alphabet
  "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")

(def ^:private b32-alphabet
  "abcdefghijklmnopqrstuvwxyz234567")

(defn ^js text->bytes [^string s]
  (.encode (js/TextEncoder.) s))

(defn base58btc
  "base58btc(multibase 'z' payload). Port of the edge's base58btcEncode."
  [^js bytes]
  (let [len (alength bytes)
        zeros (loop [i 0]
                (if (and (< i len) (zero? (aget bytes i))) (recur (inc i)) i))
        digits (array)]
    (loop [i zeros]
      (when (< i len)
        (let [carry (volatile! (aget bytes i))]
          (dotimes [j (alength digits)]
            (let [c (+ @carry (bit-shift-left (aget digits j) 8))]
              (aset digits j (mod c 58))
              (vreset! carry (quot c 58))))
          (while (pos? @carry)
            (.push digits (mod @carry 58))
            (vreset! carry (quot @carry 58))))
        (recur (inc i))))
    (str (apply str (repeat zeros "1"))
         (apply str (map #(nth b58-alphabet %)
                         (reverse (array-seq digits)))))))

(defn base32-lower-no-pad
  "CIDv1 base32-lower, no padding (multibase 'b' payload). Port of the edge's
  base32LowerNoPad — 32-bit accumulator, drains 5-bit groups MSB-first."
  [^js bytes]
  (let [st (reduce
            (fn [{:keys [bits value out]} b]
              (let [value (bit-or (bit-shift-left value 8) b)
                    bits (+ bits 8)]
                (loop [bits bits out out]
                  (if (>= bits 5)
                    (recur (- bits 5)
                           (str out (nth b32-alphabet
                                         (bit-and (unsigned-bit-shift-right value (- bits 5)) 31))))
                    {:bits bits :value value :out out}))))
            {:bits 0 :value 0 :out ""}
            (array-seq bytes))
        {:keys [bits value out]} st]
    (if (pos? bits)
      (str out (nth b32-alphabet (bit-and (bit-shift-left value (- 5 bits)) 31)))
      out)))

(defn base58btc-decode
  "Inverse of base58btc: base58 string → Uint8Array. Throws on bad chars."
  [^string s]
  (let [idx (into {} (map-indexed (fn [i c] [c i]) b58-alphabet))
        zeros (count (take-while #(= % \1) s))
        b256 (array)]
    (doseq [c (drop zeros s)]
      (let [carry (volatile! (or (get idx c)
                                 (throw (js/Error. (str "base58: bad char " c)))))]
        (dotimes [j (alength b256)]
          (let [x (+ (* (aget b256 j) 58) @carry)]
            (aset b256 j (bit-and x 0xff))
            (vreset! carry (bit-shift-right x 8))))
        (while (pos? @carry)
          (.push b256 (bit-and @carry 0xff))
          (vreset! carry (bit-shift-right @carry 8)))))
    (let [n (alength b256)
          out (js/Uint8Array. (+ zeros n))]
      (dotimes [j n] (aset out (+ zeros j) (aget b256 (- n 1 j))))  ; b256 is little-endian
      out)))

(defn did-key->ed25519-pub
  "did:key:z<base58btc(0xed 0x01 || pub32)> → the 32-byte Ed25519 public key,
  or nil when the DID isn't an Ed25519 did:key."
  [^string did]
  (when (str/starts-with? did "did:key:z")
    (let [mc (base58btc-decode (subs did (count "did:key:z")))]
      (when (and (>= (alength mc) 34) (= 0xed (aget mc 0)) (= 0x01 (aget mc 1)))
        (.slice mc 2 34)))))

(defn did-key-from-ed25519-pub
  "did:key:z<base58btc(0xed 0x01 || pub32)> for an Ed25519 public key."
  [^js pub]
  (when (not= 32 (alength pub))
    (throw (js/Error. "Ed25519 public key must be 32 bytes")))
  (let [mc (js/Uint8Array. 34)]
    (aset mc 0 0xed)
    (aset mc 1 0x01)
    (.set mc pub 2)
    (str "did:key:z" (base58btc mc))))

(defn graph-cid-from-name
  "KotobaCid::from_bytes(name).to_multibase(): SHA-256(name) behind a
  CIDv1/dag-cbor/sha2-256 header (0x01 0x71 0x12 0x20), base32-lower 'b'."
  [^string name]
  (let [hash (sha256 (text->bytes name))
        cid (js/Uint8Array. 36)]
    (aset cid 0 0x01)
    (aset cid 1 0x71)
    (aset cid 2 0x12)
    (aset cid 3 0x20)
    (.set cid hash 4)
    (str "b" (base32-lower-no-pad cid))))

(defn canonical-graph
  "The deterministic graph CID for one of your databases. The edge recomputes
  exactly this from your DID + db-name and pins it into every write."
  [^string did ^string db-name]
  (graph-cid-from-name (str "kotobase/db/" did "/" db-name)))
