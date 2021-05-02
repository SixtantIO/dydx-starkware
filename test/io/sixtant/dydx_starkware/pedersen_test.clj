(ns io.sixtant.dydx-starkware.pedersen-test
  (:require [clojure.test :refer :all]
            [io.sixtant.dydx-starkware.pedersen :refer :all]))


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


(deftest ec-add-test
  (let [field 0x800000000000011000000000000000000000000000000000000000000000001
        p0 (>point
             field
             0x1ef15c18599971b7beced415a40f0c7deacfd9b0d1819e03d723d8bc943cfca
             0x5668060aa49730b7be4801df46ec62de53ecd11abe43a32873000c36e8dc1f)
        p1 (>point
             field
             0x234287dcbaffe7f969c748655fca9e58fa8120b6d56eb0c1080d17957ebe47b
             0x3b056f100f96fb21e889527d41f4e39940135dd7a6c94cc6ed0268ee89e5615)]
    (is
      (= (>affine (ec-add p0 p1))
         [0x6bf1086f12f02d647bf4dba8926603cd9581600e4741bf99c164e0f05b1e302
          0x64fb5043d75d8262e81b14b44489425b464164ead414454df6c90d0befe208a]))))
