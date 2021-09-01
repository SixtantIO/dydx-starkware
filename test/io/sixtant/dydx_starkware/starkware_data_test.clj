(ns io.sixtant.dydx-starkware.starkware-data-test
  (:require [clojure.test :refer :all]

            [io.sixtant.dydx-starkware.starkware-data :refer :all]
            [io.sixtant.dydx-starkware.starkware-ecdsa :as ecdsa]

            [taoensso.encore :as enc]))


;;; Unit tests


(deftest fact-to-condition-test
  (testing "Starkware transfer condition"
    (testing "From test vector at https://github.com/dydxprotocol/dydx-v3-python/blob/master/tests/starkex/test_helpers.py#L34"
      (let [registry "0xe4a295420b58a4a7aa5c98920d6e8a0ef875b17a"
            fact "0xcf9492ae0554c642b57f5d9cabee36fb512dd6b6629bdc51e60efb3118b8c2d8"
            hex (fn [^BigInteger i] (.toString i 16))]
        (is (= (hex (fact-to-condition registry fact))
               "4d794792504b063843afdf759534f5ed510a3ca52e7baba2e999e02349dd24"))))))


;;; Comprehensive tests, including signatures.


;;; Test vectors from https://github.com/dydxprotocol/dydx-v3-python/blob/4b5d9a92dc183e25ce926ee702787f1e639f72ae/tests/starkex/test_conditional_transfer.py#L41


; dydx format for the request
(def fast-withdrawal
  {:debitAmount "49.478023"
   :debitAsset "USDC"
   :lpPositionId "67890"
   :expiration #inst"2020-09-17T04:15:55.028Z"
   :clientId "This is an ID that the client came up with to describe this transfer"
   :positionId "12345"
   :lpStarkPublicKey "05135ef87716b0faecec3ba672d145a6daad0aa46437c365d490022115aba674"

   :creditAsset "USDC"
   :creditAmount "49.478023"
   :toAddress "0x123"})


; Because they construct the starkware data directly, and we build it from a
; dydx request, I can't construct test input with the same transfer condition
; (because I would need to know the preimage of their mock `fact` value), so
; I'm just injecting it directly into the starkware data, overriding the
; transfer condition which corresponds to the fast withdrawal request above,
; but leaving everything else the same.
(def mock-transfer-condition
  (let [registry "0x12aa12aa12aa12aa12aa12aa12aa12aa12aa12aa"
        fact "0x12ff12ff12ff12ff12ff12ff12ff12ff12ff12ff12ff12ff12ff12ff12ff12ff"]
    (fact-to-condition registry fact)))


(deftest sign-conditional-transfer-test
  (let [mock-key (biginteger 0x58c7d5a90b1776bde86ebac077e053ed85b0f7164f53b080304a531947f46e3)
        mock-meta {:>asset-id {"USDC" (biginteger 0x02c04d8b650f44092278a7cb1e1028c82025dff622db96c934b611b84cc8de5a)}
                   :>lots {"USDC" (biginteger 1e6)}
                   :token-contracts {"USDC" "0x8707A5bf4C2842d46B31A405Ba41b858C0F876c4"}
                   :contracts {:fact-registry "0x12aa12aa12aa12aa12aa12aa12aa12aa12aa12aa"}}

        ct (-> fast-withdrawal
               (conditional-transfer mock-meta)
               (assoc :condition mock-transfer-condition))]
    (is
      (= (ecdsa/sign (hash-conditional-transfer ct) mock-key)
         (str "04814c5d3501863134108802cab5d12df4b959654332103b837252549d24e9a6"
              "06bc01225e9f1690b08b63de2a3b179fb2927d4564b3440bbb0da4c37caf597e")))))


;;; I generated these test using the dydx-v3-python client. I went in and added
;;; print statements for important incremental values (order hash, k-value,
;;; signature) and then ran their test suite in test_order.py[1] to collect test
;;; vectors.
;;; [1] https://github.com/dydxprotocol/dydx-v3-python/blob/979b82c9a2d1c468de850cc82e58fd71d2531724/tests/starkex/test_order.py#L47


(def test-dydx-order
  {:position-id              12345
   :client-id                "This is an ID that the client came up with to describe this order"
   :market                   "ETH-USD"
   :side                     "BUY"
   :human-size               "145.0005"
   :human-price              "350.00067"
   :human-limit-fee          "0.125"
   :expiration-epoch-seconds (-> #inst"2020-09-17T04:15:55.028Z" inst-ms (/ 1000.0))})


(def test-asset-meta-data
  {:collateral-asset "USDC"
   :>synthetic-asset {"BTC-USD"  "BTC"
                      "ETH-USD"  "ETH"
                      "LINK-USD" "LINK"}
   :>asset-id        (enc/map-vals
                       biginteger
                       {"USDC" 0x02c04d8b650f44092278a7cb1e1028c82025dff622db96c934b611b84cc8de5a
                        "BTC"  0
                        "ETH"  1
                        "LINK" 2})
   :>lots            (enc/map-vals
                       biginteger
                       {"USDC" 1e6M
                        "BTC"  1e10M
                        "ETH"  1e8M
                        "LINK" 1e7M})})


(def test-stark-private-key
  (biginteger 0x58c7d5a90b1776bde86ebac077e053ed85b0f7164f53b080304a531947f46e3))


(deftest starkware-hash-test
  (testing "Starkware order hashing"
    (is (= (-> test-dydx-order
               (order test-asset-meta-data)
               (hash-order))
           468272172109181336803312317501369707487713970735758239472271225903708635371))))


(deftest rfc6979-k-value-test
  (testing "Deterministic K value for starkware's variant of rfc6979"
    (is (= (-> test-dydx-order
               (order test-asset-meta-data)
               (hash-order)
               (ecdsa/rfc6979-k-value test-stark-private-key nil))
           867564722697804464741614425870660902803104828803103503995359423111403488547))))


;; Again, test vector generated from signature.py in the dydx reference impl
(deftest starkware-ecdsa-sign-test
  (testing "Signature for starkware's variation on classic ECDSA"
    (is (= (-> test-dydx-order
               (order test-asset-meta-data)
               (hash-order)
               (ecdsa/sign* test-stark-private-key))
           [616954775982296391160882844161258813786265994107035176522819024983509178213
            2012400508829625117113497372803723033205432147592659566158038339509616442554])
        "(r, s) signature pair matches")

    (is (= (-> test-dydx-order
               (order test-asset-meta-data)
               (hash-order)
               (ecdsa/sign test-stark-private-key))
           (str "015d2f1c7f68f2dc7c8f2557e0cd9cf6"
                "f9cf62c53f2747acc4cce3b6ef241765"
                "0472fa737331754017aad07e08d6bb09"
                "4cba54780ea86bbccfc4d130ec04fcba"))
        "encoded signature matches")))
