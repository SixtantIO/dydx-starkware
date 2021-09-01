(ns io.sixtant.dydx-starkware
  "Creation, hashing, and signing of requests for dYdX / Starkware's L2."
  (:require [io.sixtant.dydx-starkware.starkware-data :as stark]
            [io.sixtant.dydx-starkware.starkware-ecdsa :as ecdsa]
            [io.sixtant.dydx-starkware.time :as t]

            [clojure.string :as string]
            [clojure.data.json :as json]

            [pandect.algo.sha256 :as hmac]
            [taoensso.encore :as enc])
  (:import (java.util Base64)))


(set! *warn-on-reflection* true)


(defn sign-order
  "Order requests need to be signed by a separate API key *before* being signed
  like a normal request (for starkware proofs).

  Takes dYdX order data and returns a signed order request."
  [stark-private-key dydx-order asset-meta-data]
  (let [signature (-> dydx-order
                      (stark/order asset-meta-data)
                      (stark/hash-order)
                      (ecdsa/sign stark-private-key))]
    (-> dydx-order
        (assoc :signature signature)
        (dissoc :positionId) ; just used for signing, not a valid request field
        (update :expiration t/pr-inst-iso))))


(defn sign-fast-withdrawal
  "Fast withdrawal requests need to be signed by a separate API key *before*
  being signed like a normal request (for starkware proofs).

  Takes dYdX fast withdrawal data and returns a signed fast withdrawal request."
  [stark-private-key dydx-fast-withdrawal asset-meta-data]
  ;; TODO
  #_(let [signature (-> dydx-fast-withdrawal
                      (sw/fast-withdrawal asset-meta-data)
                      (sw/hash-fast-withdrawal)
                      (ecdsa/sign stark-private-key))]
    (-> dydx-fast-withdrawal
        (assoc :signature signature)
        (dissoc :positionId :lpStarkPublicKey) ; just used for signing
        (update :expiration t/pr-inst-iso))))


;; For now this data is hardcoded, though we're hoping they'll add it to the
;; API.
(def asset-meta-data
  "Parameters which are necessary to construct / sign the starkware orders."
  {:collateral-asset "USDC"
   :>synthetic-asset {"BTC-USD"   "BTC"
                      "ETH-USD"   "ETH"
                      "LINK-USD"  "LINK"

                      "AAVE-USD"  "AAVE"
                      "UNI-USD"   "UNI"
                      "SUSHI-USD" "SUSHI"
                      "SOL-USD"   "SOL"
                      "YFI-USD"   "YFI"
                      "1INCH-USD" "1INCH"

                      "AVAX-USD"  "AVAX"
                      "SNX-USD"   "SNX"
                      "CRV-USD"   "CRV"
                      "UMA-USD"   "UMA"
                      "DOT-USD"   "DOT"
                      "DOGE-USD"  "DOGE"

                      "MATIC-USD" "MATIC"
                      "MKR-USD"   "MKR"
                      "FIL-USD"   "FIL"
                      "ADA-USD"   "ADA"
                      "ATOM-USD"  "ATOM"
                      "COMP-USD"  "COMP"
                      "BCH-USD"   "BCH"
                      "LTC-USD"   "LTC"
                      "EOS-USD"   "EOS"
                      "ALGO-USD"  "ALGO"
                      "ZRX-USD"   "ZRX"
                      "XMR-USD"   "XMR"
                      "ZEC-USD"   "ZEC"}
   :>asset-id        (enc/map-vals
                       biginteger
                       {"USDC"  0x02893294412a4c8f915f75892b395ebbf6859ec246ec365c3b1f56f47c3a0a5d
                        "BTC"   0x4254432d3130000000000000000000
                        "ETH"   0x4554482d3900000000000000000000
                        "LINK"  0x4c494e4b2d37000000000000000000

                        "AAVE"  0x414156452d38000000000000000000
                        "UNI"   0x554e492d3700000000000000000000
                        "SUSHI" 0x53555348492d370000000000000000
                        "SOL"   0x534f4c2d3700000000000000000000
                        "YFI"   0x5946492d3130000000000000000000
                        "1INCH" 0x31494e43482d370000000000000000

                        "AVAX"  0x415641582d37000000000000000000
                        "SNX"   0x534e582d3700000000000000000000
                        "CRV"   0x4352562d3600000000000000000000
                        "UMA"   0x554d412d3700000000000000000000
                        "DOT"   0x444f542d3700000000000000000000
                        "DOGE"  0x444f47452d35000000000000000000

                        "MATIC" 0x4d415449432d360000000000000000
                        "MKR"   0x4d4b522d3900000000000000000000
                        "FIL"   0x46494c2d3700000000000000000000
                        "ADA"   0x4144412d3600000000000000000000
                        "ATOM"  0x41544f4d2d37000000000000000000
                        "COMP"  0x434f4d502d38000000000000000000
                        "BCH"   0x4243482d3800000000000000000000
                        "LTC"   0x4c54432d3800000000000000000000
                        "EOS"   0x454f532d3600000000000000000000
                        "ALGO"  0x414c474f2d36000000000000000000
                        "ZRX"   0x5a52582d3600000000000000000000
                        "XMR"   0x584d522d3800000000000000000000
                        "ZEC"   0x5a45432d3800000000000000000000})
   :>lots            (enc/map-vals
                       biginteger
                       {"USDC"  1e6M
                        "BTC"   1e10M
                        "ETH"   1e9M
                        "LINK"  1e7M

                        "AAVE"  1e8M
                        "UNI"   1e7M
                        "SUSHI" 1e7M
                        "SOL"   1e7M
                        "YFI"   1e10M
                        "1INCH" 1e7M

                        "AVAX"  1e7M
                        "SNX"   1e7M
                        "CRV"   1e6M
                        "UMA"   1e7M
                        "DOT"   1e7M
                        "DOGE"  1e5M

                        "MATIC" 1e6M
                        "MKR"   1e9M
                        "FIL"   1e7M
                        "ADA"   1e6M
                        "ATOM"  1e7M
                        "COMP"  1e8M
                        "BCH"   1e8M
                        "LTC"   1e8M
                        "EOS"   1e6M
                        "ALGO"  1e6M
                        "ZRX"   1e6M
                        "XMR"   1e8M
                        "ZEC"   1e8M})
   :token-contracts {"USDC" "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"}
   :contracts {:fact-registry "0xBE9a129909EbCb954bC065536D2bfAfBd170d27A"}})


(def asset-meta-data-testnet
  "Same as `asset-meta-data`, except with testnet contracts."
  (let [addr 0x02c04d8b650f44092278a7cb1e1028c82025dff622db96c934b611b84cc8de5a]
    (-> asset-meta-data
        (assoc-in [:>asset-id "USDC"] (biginteger addr))
        (assoc-in [:token-contracts "USDC"] "0x8707A5bf4C2842d46B31A405Ba41b858C0F876c4")
        (assoc-in [:contracts :fact-registry] "0x8Fb814935f7E63DEB304B500180e19dF5167B50e"))))


(defn bytes->urlb64 [^bytes b] (String. (.encode (Base64/getUrlEncoder) b)))
(defn urlb64->bytes [^String s] (.decode (Base64/getUrlDecoder) (.getBytes s)))


(defn request-signature
  "Generate the request signature for a dYdX API request."
  [api-secret {:keys [path method body inst]
               :or   {body ""}}]
  (let [iso-ts (t/pr-inst-iso inst)
        method (string/upper-case (name method))
        message (str iso-ts method path body)]
    (-> message
        (hmac/sha256-hmac-bytes (urlb64->bytes api-secret))
        (bytes->urlb64))))


(defn sign-request
  "Take method/path/body and return a (signed) RING request map."
  [{:keys [method base-url path body] :as req} now {:keys [key secret passphrase]}]
  (let [body (if (seq body) (json/write-str body) "")
        req (assoc req :body body :inst now)
        sig (request-signature secret req)]
    {:method       (keyword (string/lower-case (name method)))
     :url          (str base-url path)
     :accept       "application/json"
     :content-type "application/json"
     :body         body
     :headers      {"User-Agent"      "sixtant/dydx-starkware"
                    "DYDX-SIGNATURE"  sig
                    "DYDX-API-KEY"    key
                    "DYDX-TIMESTAMP"  (t/pr-inst-iso now)
                    "DYDX-PASSPHRASE" passphrase}}))


(comment
  ;; Example usage:

  (require '[io.sixtant.dydx-starkware :as dydx])

  ; (1) Construct order request data (see https://docs.dydx.exchange/#create-a-new-order)
  (def order
    {:positionId  1
     :clientId    "91364379829165"
     :market      "BTC-USD"
     :side        "SELL"
     :size        "100"
     :price       "18000"
     :limitFee    "0.015"
     :expiration  #inst"2022-12-21T21:30:20.200Z"

     :type        "LIMIT"
     :postOnly    false
     :timeInForce "GTT"})

  ; (2) Sign the order data with the Starkware private key
  (def signed-order
    (let [stark-priv (biginteger 0x10df7f0ca8e3c1e1bd56693bb2725342c3fe08d7042ee6a4d2dad592b9a90c3)]
      (dydx/sign-order stark-priv order dydx/asset-meta-data)))


  ; (3) Sign the request data second time with the dYdX api credentials
  (let [creds {:key        "11f3726d-72c9-f3c7-eed9-980655c369d6"
               :secret     "B6_eKDmHrm9L-DdVVRU75LC9W_k67TI4tCgoeN5a"
               :passphrase "TvsLWDMQGA2-9MXwxV-e"}]
    (dydx/sign-request
      {:method   :post
       :base-url "https://api.dydx.exchange"
       :path     "/v3/orders"
       :accept   "application/json"
       :body     signed-order}
      (java.util.Date.)
      creds))

  ; Done -- you now have a signed request
  {:method       :post
   :url          "https://api.dydx.exchange/v3/orders"
   :accept       "application/json"
   :content-type "application/json"
   :body         "{\"clientId\":\"91364379829165\",\"limitFee\":\"0.015\",\"expiration\":\"2022-12-21T21:30:20.200Z\",\"signature\":\"02c23b2b028e53251e615eb1a686e8b3e1ce735b7e0fa3fdf0b45772eb9d1bf9061a7881b83f6a6c26fa9810a9b17f91756f829956e193e04217626e88b34e4e\",\"postOnly\":false,\"type\":\"LIMIT\",\"size\":\"100\",\"side\":\"SELL\",\"market\":\"BTC-USD\",\"timeInForce\":\"GTT\",\"price\":\"18000\"}"
   :headers      {"User-Agent"      "sixtant/dydx-starkware"
                  "DYDX-SIGNATURE"  "6nDdDFAfBi2x4BsfRolT-1631f1zXCdar3-o1ifMk6s="
                  "DYDX-API-KEY"    "11f3726d-72c9-f3c7-eed9-980655c369d6"
                  "DYDX-TIMESTAMP"  "2021-05-02T19:58:03.591Z"
                  "DYDX-PASSPHRASE" "TvsLWDMQGA2-9MXwxV-e"}})
