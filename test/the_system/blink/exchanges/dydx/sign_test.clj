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


(deftest starkware-hash-test
  (testing "Hashing of Starkware order submission"
    ;; I got this test case by placing an order through their python client
    (is (= (-> test-dydx-order
               (starkware-order starkware-constants)
               (starkware-hash starkware-constants))
           0x706608d10cb2c2b8f7be81f23468ae37452c45bdf579b276f5d6870a6a966cd))))
