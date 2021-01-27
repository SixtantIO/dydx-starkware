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
           3154775399676678995470264281518126064051472251509888173914995108585914642867))))


(deftest rfc6979-k-value-test
  (testing "Deterministic K value for starkware's variant of rfc6979"
    (is (= (-> test-dydx-order
               (starkware-order test-asset-meta-data)
               (starkware-hash)
               (ecdsa/rfc6979-k-value test-stark-private-key nil))
           1115822616333141798463954779743658169683537934892904112369972317061051500562))))


;; Again, test vector generated from signature.py in the dydx reference impl
(deftest starkware-ecdsa-sign-test
  (testing "Signature for starkware's variation on classic ECDSA"
    (is (= (-> test-dydx-order
               (starkware-order test-asset-meta-data)
               (starkware-hash)
               (ecdsa/sign* test-stark-private-key))
           [1625778508818496282682107048148572594505233577840638874374271828073761936765
            781955849053684862513006295926905325331578140826503008919123218167739764436])
        "(r, s) signature pair matches")

    (is (= (-> test-dydx-order
               (starkware-order test-asset-meta-data)
               (starkware-hash)
               (ecdsa/sign test-stark-private-key))
           (str "0398287472161cba0e6386ff0b2f25f39ba37"
                "c646b7bbadace80eee6b8e7157d01ba924272"
                "e1e42b3211b96bbbe012e7e8101e1b3e5b83e"
                "a90d161ad11fcced4"))
        "encoded signature matches")))
