(ns kotobase.cid-test
  (:require [cljs.test :refer-macros [deftest is testing]]
            [clojure.string :as str]
            ["@noble/curves/ed25519.js" :refer [ed25519]]
            [kotobase.cid :as cid]))

;; Deterministic 32-byte Ed25519 seed (0,1,2,...,31).
(def seed (js/Uint8Array.from (clj->js (range 32))))

(deftest did-key-format
  (testing "Ed25519 did:key has the z6Mk multicodec prefix"
    (let [pub (.getPublicKey ed25519 seed)
          did (cid/did-key-from-ed25519-pub pub)]
      ;; 0xed01 multicodec on a 32-byte key always base58btc-encodes to z6Mk…
      (is (str/starts-with? did "did:key:z6Mk"))
      ;; ed25519 did:key is "did:key:" (8) + ~48-char base58 payload.
      (is (<= 55 (count did) 57)))))

(deftest did-key-rejects-bad-length
  (is (thrown? js/Error (cid/did-key-from-ed25519-pub (js/Uint8Array. 31)))))

(deftest graph-cid-format
  (testing "CIDv1/dag-cbor/sha2-256 graph handle is base32 'bafyrei…'"
    (let [g (cid/graph-cid-from-name "kotobase/db/did:key:zTest/people")]
      ;; 0x01 0x71 0x12 0x20 header → base32-lower always starts 'bafyrei'.
      (is (str/starts-with? g "bafyrei"))
      ;; 'b' + base32(36 bytes) = 1 + ceil(36*8/5) = 1 + 58 = 59 chars.
      (is (= 59 (count g))))))

(deftest base58-decode-roundtrip
  (let [b (js/Uint8Array.from (clj->js [0 0 1 2 250 255 13 7 0]))]
    (is (= (vec (array-seq b))
           (vec (array-seq (cid/base58btc-decode (cid/base58btc b)))))
        "leading zeros preserved")))

(deftest did-key-pub-roundtrip
  (let [pub (.getPublicKey ed25519 seed)
        did (cid/did-key-from-ed25519-pub pub)]
    (is (= (vec (array-seq pub)) (vec (array-seq (cid/did-key->ed25519-pub did))))
        "pub → did:key → pub round-trips")
    (is (nil? (cid/did-key->ed25519-pub "did:web:x")) "non-did:key → nil")))

(deftest did-key-with-malformed-base58-payload-returns-nil
  (testing "a did:key:z... string whose base58 payload contains a
            character outside the base58btc alphabet (base58btc-decode
            itself throws) must still resolve to nil, per this fn's own
            \"or nil when the DID isn't an Ed25519 did:key\" contract --
            not propagate a raw uncaught exception"
    (is (nil? (cid/did-key->ed25519-pub "did:key:zInvalid0DID")))
    (is (nil? (cid/did-key->ed25519-pub "did:key:zOI0lIllegalChars")))))

(deftest graph-cid-deterministic
  (let [a (cid/canonical-graph "did:key:zABC" "people")
        b (cid/canonical-graph "did:key:zABC" "people")
        c (cid/canonical-graph "did:key:zABC" "places")]
    (is (= a b) "same name → same CID")
    (is (not= a c) "different db-name → different CID")))
