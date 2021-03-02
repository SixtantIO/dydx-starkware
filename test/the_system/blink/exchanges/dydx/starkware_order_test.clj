(ns the-system.blink.exchanges.dydx.starkware-order-test
  (:require [clojure.test :refer :all]

            [the-system.blink.exchanges.dydx.starkware-order :refer :all]
            [the-system.blink.exchanges.dydx.starkware-ecdsa :as ecdsa]
            [the-system.utils :as utils]

            [taoensso.encore :as enc]))


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
   :expiration-epoch-seconds (utils/inst-s #inst"2020-09-17T04:15:55.028Z")})


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
               (starkware-order test-asset-meta-data)
               (starkware-hash))
           468272172109181336803312317501369707487713970735758239472271225903708635371))))


(deftest rfc6979-k-value-test
  (testing "Deterministic K value for starkware's variant of rfc6979"
    (is (= (-> test-dydx-order
               (starkware-order test-asset-meta-data)
               (starkware-hash)
               (ecdsa/rfc6979-k-value test-stark-private-key nil))
           867564722697804464741614425870660902803104828803103503995359423111403488547))))


;; Again, test vector generated from signature.py in the dydx reference impl
(deftest starkware-ecdsa-sign-test
  (testing "Signature for starkware's variation on classic ECDSA"
    (is (= (-> test-dydx-order
               (starkware-order test-asset-meta-data)
               (starkware-hash)
               (ecdsa/sign* test-stark-private-key))
           [616954775982296391160882844161258813786265994107035176522819024983509178213
            2012400508829625117113497372803723033205432147592659566158038339509616442554])
        "(r, s) signature pair matches")

    (is (= (-> test-dydx-order
               (starkware-order test-asset-meta-data)
               (starkware-hash)
               (ecdsa/sign test-stark-private-key))
           (str "015d2f1c7f68f2dc7c8f2557e0cd9cf6"
                "f9cf62c53f2747acc4cce3b6ef241765"
                "0472fa737331754017aad07e08d6bb09"
                "4cba54780ea86bbccfc4d130ec04fcba"))
        "encoded signature matches")))
