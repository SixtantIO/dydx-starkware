(ns the-system.blink.exchanges.dydx.pedersen-test
  (:require [clojure.test :refer :all]
            [the-system.blink.exchanges.dydx.pedersen :refer [pedersen-hash]]))


;; Test cases taken from:
;; https://github.com/starkware-libs/starkex-resources/blob/0f08e6c55ad88c93499f71f2af4a2e7ae0185cdf/crypto/starkware/crypto/signature/signature_test_data.json#L85
(deftest pedersen-hash-test
  (testing "dYdX/Starkware version of Pedersen hashing"
    (is (= (pedersen-hash
             0x3d937c035c878245caf64531a5756109c53068da139362728feb561405371cb
             0x208a0a10250e382e1e4bbe2880906c2791bf6275695e02fbbc6aeff9cd8b31a)
           0x30e480bed5fe53fa909cc0f8c4d99b8f9f2c016be4c41e13a4848797979c662))

    (is (= (pedersen-hash
             0x58f580910a6ca59b28927c08fe6c43e2e303ca384badc365795fc645d479d45
             0x78734f65a067be9bdb39de18434d71e79f7b6466a4b66bbd979ab9e7515fe0b)
           0x68cc0b76cddd1dd4ed2301ada9b7c872b23875d5ff837b3a87993e0d9996b87))))
