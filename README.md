# dydx-starkware

A Clojure library for the creation, hashing, and signing of orders with 
Starkware's L2 as used by dYdX.

Includes:
- Starkware's Pedersen hash algorithm [[1](src/io/sixtant/dydx_starkware/pedersen.clj)]
- Starkware's version of ECDSA [[2](src/io/sixtant/dydx_starkware/starkware_ecdsa.clj)]
- Hashing algorithm for Startkware's L2 limit order data structure [[3](src/io/sixtant/dydx_starkware/starkware_order.clj)]
- High level utilities for dYdX order and request signing [[4](src/io/sixtant/dydx_starkware.clj)]

## Usage

```clojure 
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

; Done -- you now have a signed RING request
{:method       :post
 :url          "https://api.dydx.exchange/v3/orders"
 :accept       "application/json"
 :content-type "application/json"
 :body         "{\"clientId\":\"91364379829165\",\"limitFee\":\"0.015\",\"expiration\":\"2022-12-21T21:30:20.200Z\",\"signature\":\"02c23b2b028e53251e615eb1a686e8b3e1ce735b7e0fa3fdf0b45772eb9d1bf9061a7881b83f6a6c26fa9810a9b17f91756f829956e193e04217626e88b34e4e\",\"postOnly\":false,\"type\":\"LIMIT\",\"size\":\"100\",\"side\":\"SELL\",\"market\":\"BTC-USD\",\"timeInForce\":\"GTT\",\"price\":\"18000\"}"
 :headers      {"User-Agent"      "sixtant/dydx-starkware"
                "DYDX-SIGNATURE"  "6nDdDFAfBi2x4BsfRolT-1631f1zXCdar3-o1ifMk6s="
                "DYDX-API-KEY"    "11f3726d-72c9-f3c7-eed9-980655c369d6"
                "DYDX-TIMESTAMP"  "2021-05-02T19:58:03.591Z"
                "DYDX-PASSPHRASE" "TvsLWDMQGA2-9MXwxV-e"}}
```

## License

This program and the accompanying materials are made available under the
terms of the Eclipse Public License 2.0 which is available at
http://www.eclipse.org/legal/epl-2.0.

This Source Code may also be made available under the following Secondary
Licenses when the conditions for such availability set forth in the Eclipse
Public License, v. 2.0 are satisfied: GNU General Public License as published by
the Free Software Foundation, either version 2 of the License, or (at your
option) any later version, with the GNU Classpath Exception which is available
at https://www.gnu.org/software/classpath/license.html.
