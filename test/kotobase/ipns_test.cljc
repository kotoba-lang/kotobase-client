(ns kotobase.ipns-test
  "Cross-checked against a REAL JVM-signed fixture, not just cljs
  self-consistency: `jvm-signed-fixture` below was produced by running
  `kotoba-lang/tech-ipfs-specs-ipns`'s `ipns.head/sign` (ADR-2607061800)
  on the JVM with the seed `(byte-array (range 32))`, proving this
  namespace's canonical dag-cbor payload is byte-identical to the JVM
  side's (both must hash/verify the exact same bytes for cross-platform
  actors to interoperate)."
  (:require [cljs.test :refer-macros [deftest is testing]]
            ["@noble/curves/ed25519.js" :refer [ed25519]]
            [kotobase.ipns :as ipns]))

(def seed (js/Uint8Array.from (clj->js (range 32))))

;; produced on the JVM: (ipns.head/sign seed {:name (ipns.core/pubkey->name
;; (ed25519.core/pubkey-from-seed seed)) :value "bafyreicid-example"
;; :sequence 1 :valid_until "2027-01-01T00:00:00Z"})
(def jvm-signed-fixture
  {:name "k51qzi5uqu5dg9ufswxt229ntzdy7p4125xzv5rtyjso89ajdujg6csfxcj260"
   :value "bafyreicid-example"
   :sequence 1
   :valid_until "2027-01-01T00:00:00Z"
   :public_key_multibase "did:key:z6MkehRgf7yJbgaGfYsdoAsKdBPE3dj2CYhowQdcjqSJgvVd"
   :signature_multibase "z4413bbTmMZLycZpYKgiz8Dp6WsJ9oPzBQ58Fgfy1X4xH7XmzAeNh2ahDsyeo12UKzpqAJFiXeHwcyN2YfYAYQ81j"})

(deftest verify-head-accepts-a-real-jvm-signed-record
  (is (= {:valid? true :name (:name jvm-signed-fixture)}
         (ipns/verify-head jvm-signed-fixture))
      "byte-identical canonical dag-cbor payload to the JVM ipns.head/sign side"))

(deftest verify-head-rejects-tampering
  (is (= false (:valid? (ipns/verify-head (assoc jvm-signed-fixture :sequence 2))))))

(deftest sign-head-and-verify-head-roundtrip
  (let [record {:name "k51qzi5uqu5d-placeholder" :value "bafyrei-other" :sequence 7
                :valid_until "2028-01-01T00:00:00Z"}
        signed (ipns/sign-head seed record)]
    (testing "round-trips through sign then verify"
      (is (= {:valid? true :name (:name record)} (ipns/verify-head signed))))
    (testing "tampering with a signed field invalidates it"
      (is (= false (:valid? (ipns/verify-head (assoc signed :sequence 8))))))))

(deftest sign-head-matches-the-jvm-side-for-the-same-inputs
  (let [record {:name (:name jvm-signed-fixture) :value (:value jvm-signed-fixture)
                :sequence (:sequence jvm-signed-fixture) :valid_until (:valid_until jvm-signed-fixture)}
        signed (ipns/sign-head seed record)]
    (is (= jvm-signed-fixture signed)
        "cljs sign-head reproduces the exact JVM ipns.head/sign output for the same seed+record")))
