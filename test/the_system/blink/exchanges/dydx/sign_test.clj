(ns the-system.blink.exchanges.dydx.sign-test
  (:require [clojure.test :refer :all]
            [the-system.blink.exchanges.dydx.sign :refer :all]
            [clojure.data.json :as json]
            [taoensso.encore :as enc]))


(def asset-meta-data
  ;; TODO: Move this up into dydx.clj when writing the exchange namespace, and
  ;;       just pass it in from there.
  "Right now this is fixed, but we should treat this data as if we could get it
  from an endpoint."
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
               (starkware-order asset-meta-data)
               (starkware-hash))
           0x706608d10cb2c2b8f7be81f23468ae37452c45bdf579b276f5d6870a6a966cd))))


;; I modified the sign method in signature.py to print the chosen K value, and
;; then ran o.sign('0x10df7f0ca8e3c1e1bd56693bb2725342c3fe08d7042ee6a4d2dad592b9a90c3')
;; to check the K value.
(deftest rfc6979-k-value-test
  (testing "Deterministic K value for starkware's variant of rfc6979"
    (is (= (-> test-dydx-order
               (starkware-order asset-meta-data)
               (starkware-hash)
               (rfc6979-k-value test-stark-private-key nil))
           826191475741237249337586902222325815624295015428541147040892596733507827303))))


;; Again, test vector generated from signature.py in the dydx reference impl
(deftest starkware-sign-test
  (testing "Signature for starkware's variation on classic ECDSA"
    (is (= (-> test-dydx-order
               (starkware-order asset-meta-data)
               (starkware-hash)
               (starkware-sign test-stark-private-key))
           [1147880685947926282563952332969533863428191652304924879656374215031587701320
            1613647208029372355060822186979972378103961091500099929751858255667859304961])
        "(r, s) signature pair matches")

    (is (= (-> test-dydx-order
               (starkware-order asset-meta-data)
               (starkware-hash)
               (starkware-sign test-stark-private-key)
               (encode-sig))
           "0289ad6d0177bf3ddbdbaf655ee1ef705be79c1a19cab995de25fcb09f05824803914abd7d995c03a0bf601812fd76dd6205b01976a0e7d1158c0929a5343201")
        "encoded signature matches")))


(def test-request
  {:path   "/v3/orders"
   :method :post
   :inst   #inst "2021-01-23T17:38:04.039Z"
   :body   (json/write-str
             ;; Ensure the same JSON string as the one I generated in the
             ;; reference implementation
             (array-map
               :market "BTC-USD",
               :side "SELL",
               :type "LIMIT",
               :timeInForce "GTT",
               :size "100",
               :price "18000",
               :limitFee "0.015",
               :expiration "2022-12-21T21:30:20.200Z",
               :postOnly false,
               :clientId "91364379829165",
               :signature "0289ad6d0177bf3ddbdbaf655ee1ef705be79c1a19cab995de25fcb09f05824803914abd7d995c03a0bf601812fd76dd6205b01976a0e7d1158c0929a5343201"))})


(def test-dydx-private-key
  (biginteger 0x2a709f4253e841f274d192b8270d7a7c41503c037b556509d399dddf79400b1))


(deftest sign-request-test
  (testing "dydx request signature"
    (is (= (-> test-request (sign-request test-dydx-private-key) :sig)
           "05bdd9f24ad4ecec1a34efdf8f05a6765240ba6b1a5e49d9352fbda41968e22205db4f23bf03a58e2c5ad8ece4aefa4799e35306454a4fa3e3a14a782e9dfa65"))))
