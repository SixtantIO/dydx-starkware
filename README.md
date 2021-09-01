# dydx-starkware

A Clojure library for the creation, hashing, and signing of orders with 
Starkware's L2 as used by dYdX.

Includes:
- Starkware's Pedersen hash algorithm [[1](src/io/sixtant/dydx_starkware/pedersen.clj)]
- Starkware's version of ECDSA [[2](src/io/sixtant/dydx_starkware/starkware_ecdsa.clj)]
- Hashing algorithms for Startkware's L2 data structures [[3](src/io/sixtant/dydx_starkware/starkware_data.clj)]
- Clojure implementation of `web3.solidityKeccak` / Ethereum ABI encoding[[4](src/io/sixtant/dydx_starkware/solidity_keccak.clj)]
- High level utilities for dYdX order, withdrawal, and request signing [[5](src/io/sixtant/dydx_starkware.clj)]

## Usage

```clojure 
(require '[io.sixtant.dydx-starkware :as dydx])

;;; # Order placement (see https://docs.dydx.exchange/#create-a-new-order)

; (1) Construct order request data
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


; (3) Sign the request data a second time with the dYdX api credentials
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
                "DYDX-PASSPHRASE" "TvsLWDMQGA2-9MXwxV-e"}}

;;; # Fast withdrawal
;;; (see https://docs.dydx.exchange/#get-fast-withdrawal-liquidity and
;;; https://docs.dydx.exchange/#create-fast-withdrawal)

; (1) Construct the fast withdrawal data. This is still missing the
; :debitAmount, which is decided by the liquidity provider for the withdrawal,
; who quotes you a :debitAmount for which the LP is willing to send you
; :creditAmount. I.e. if :creditAmount is 1000 and the LP quotes a
; :debitAmount of 1001, you pay a fee of $1.
(def fast-withdrawal
  {:creditAmount "1000" ; the amount you receive net of fees
   :creditAsset "USDC"

   ; your position id and address
   :positionId "12345"
   :toAddress "0x0000000000000000000000000000000000000123"

   ; id for the txn
   :clientId "13f3ea90-27a7-4b78-b27a-54ae69791ec5"

   ; must be at least 7 days in the future
   :expiration #inst"2021-09-09"})

; (2) Get fast withdrawal liquidity (fee paid + provider data).
(def liquidity
  (let [base "https://api.dydx.exchange"
        path "/v3/fast-withdrawals?creditAsset=USDC&creditAmount="
        amount (:creditAmount fast-withdrawal)
        resp (clojure.data.json/read-str (slurp (str base path amount)))
        ; Take the first quote returned, IRL you might want to check for the
        ; lowest fee. Fee is the difference between debit and credit amounts.
        [lpPositionId lpData] (first (get resp "liquidityProviders"))]

    (assert lpPositionId "There is a liquidity provider available.")
    (assert
      (> (bigdec (get lpData "availableFunds")) (bigdec amount))
      "The LP has funds available to satisfy the requested amount.")

    {:lpPositionId lpPositionId
     :lpStarkPublicKey (get lpData "starkKey")
     :debitAmount (get-in lpData ["quote" "debitAmount"])
     :debitAsset "USDC"}))

;=>
{:lpPositionId "2",
 :lpStarkPublicKey "020ce2e0a138d6ba48b7d4a22ee0b0913501de38795c187408372e54ec86199a",
 :debitAmount "1063.660000",
 :debitAsset "USDC"}

; (3) If the fee is acceptable, merge the data into the request.
(def full-fast-withdrawal
  (merge fast-withdrawal liquidity))

; (4) Sign the order data with the Starkware private key
(def signed-withdrawal
  (let [stark-priv (biginteger 0x10df7f0ca8e3c1e1bd56693bb2725342c3fe08d7042ee6a4d2dad592b9a90c3)]
    (sign-fast-withdrawal stark-priv full-fast-withdrawal dydx/asset-meta-data)))

; (5) You now have the withdrawal data to use with `dydx/sign-request`
signed-withdrawal
{:debitAsset "USDC",
 :clientId "13f3ea90-27a7-4b78-b27a-54ae69791ec5",
 :toAddress "0x0000000000000000000000000000000000000123",
 :expiration "2021-09-09T00:00:00.000Z",
 :signature "007d8b9e47a727bbf0ec397a15043557e0246d60c0c10cc647f688c1e665e8790364b0bb2f7feaa6b736a7443bf8e5bca5384443c2a4aa54374cf1bec48640f9",
 :creditAmount "1000",
 :creditAsset "USDC",
 :debitAmount "1063.660000",
 :lpPositionId "2"}
```
