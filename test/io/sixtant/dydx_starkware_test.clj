(ns io.sixtant.dydx-starkware-test
  (:require [io.sixtant.dydx-starkware :refer :all]
            [clojure.test :refer :all]))


;;; The test cases here were generated using the dydx3-python client


(deftest dydx-hmac-signature-test
  (is (= (request-signature
           "B6_eKDmHrm9L-DdVVRU75LC9W_k67TI4tCgoeN5a"
           {:method :get
            :path "/v3/users"
            :body ""
            :inst #inst"2021-02-23T17:30:56.025Z"})
         "E34zOt4tX_bC4pvh1GSm-_93-RBNHPqttriShOZoHZw=")))


(def mock-start-privkey
  (biginteger
    0x10df7f0ca8e3c1e1bd56693bb2725342c3fe08d7042ee6a4d2dad592b9a90c3))


(def mock-order-request
  {:positionId 1
   :clientId "91364379829165"
   :market "BTC-USD"
   :side "SELL"
   :size "100"
   :price "18000"
   :limitFee "0.015"
   :expiration #inst"2022-12-21T21:30:20.200Z"

   :type "LIMIT"
   :postOnly false
   :timeInForce "GTT"})


(def mock-signed-request
  {:clientId "91364379829165"
   :limitFee "0.015"
   :expiration "2022-12-21T21:30:20.200Z"
   :signature (str "007862c2e36e36bb0c16fdf452a7ebc8c43f908"
                   "056d8d6a940ecd7efc19110f2068dd07a9af4bdd"
                   "d47bd09b819c17f782f5f3f10234dc34c64a9aff4766b1b35")
   :postOnly false
   :type "LIMIT"
   :size "100"
   :side "SELL"
   :market "BTC-USD",
   :timeInForce "GTT"
   :price "18000"})


(deftest sign-order-test
  (testing "dydx order signature"
    (let [amd asset-meta-data-testnet
          signed (sign-order mock-start-privkey mock-order-request amd)]
      (is (= (:signature signed) (:signature mock-signed-request))
          "signature matches the one produced by dydx3-python")

      (is (= signed mock-signed-request) "the rest of the request matches"))))
