(ns the-system.blink.exchanges.dydx.sign-test
  (:require [clojure.test :refer :all]
            [the-system.blink.exchanges.dydx.sign :refer :all]))


(def test-dydx-order
  {:position-id 1
   :client-id "91364379829165"
   :market "BTC-USD"
   :side "SELL"
   :human-size 100M
   :human-price 18000M
   :human-limit-fee 0.015M
   :expiration-epoch-seconds 1671658220})


(def test-stark-private-key
  (biginteger 0x10df7f0ca8e3c1e1bd56693bb2725342c3fe08d7042ee6a4d2dad592b9a90c3))


;; I generated these test vectors though the dydx/starkware python clients.
;; >>> from dydx3.starkex.order import SignableOrder
;; >>> o = SignableOrder(position_id=1, client_id="91364379829165", market="BTC-USD", side="SELL", human_size="100", human_price="18000", human_limit_fee="0.015", expiration_epoch_seconds=1671658220)
;; >>> o._calculate_hash()
(deftest starkware-hash-test
  (testing "Starkware order hashing"
    (is (= (-> test-dydx-order
               (starkware-order starkware-constants)
               (starkware-hash starkware-constants))
           0x706608d10cb2c2b8f7be81f23468ae37452c45bdf579b276f5d6870a6a966cd))))


;; I modified the sign method in signature.py to print the chosen K value, and
;; then ran o.sign('0x10df7f0ca8e3c1e1bd56693bb2725342c3fe08d7042ee6a4d2dad592b9a90c3')
;; to check the K value.
(deftest rfc6979-k-value-test
  (testing "Deterministic K value for starkware's variant of rfc6979"
    (is (= (-> test-dydx-order
               (starkware-order starkware-constants)
               (starkware-hash starkware-constants)
               (rfc6979-k-value test-stark-private-key nil))
           826191475741237249337586902222325815624295015428541147040892596733507827303))))


;; Again, test vector generated from signature.py in the dydx reference impl
(deftest starkware-sign-test
  (testing "Signature for starkware's variation on classic ECDSA"
    (is (= (-> test-dydx-order
               (starkware-order starkware-constants)
               (starkware-hash starkware-constants)
               (starkware-sign test-stark-private-key))
           [1147880685947926282563952332969533863428191652304924879656374215031587701320
            1613647208029372355060822186979972378103961091500099929751858255667859304961])
        "(r, s) signature pair matches")

    (is (= (-> test-dydx-order
               (starkware-order starkware-constants)
               (starkware-hash starkware-constants)
               (starkware-sign test-stark-private-key)
               (encode-sig))
           "0289ad6d0177bf3ddbdbaf655ee1ef705be79c1a19cab995de25fcb09f05824803914abd7d995c03a0bf601812fd76dd6205b01976a0e7d1158c0929a5343201")
        "encoded signature matches")))
