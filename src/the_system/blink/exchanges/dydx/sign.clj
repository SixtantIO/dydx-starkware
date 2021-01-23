(ns the-system.blink.exchanges.dydx.sign
  "Signature schemes for STARK and dYdX.

  See: https://docsv3.dydx.exchange/#authentication"
  (:require [clojure.data.json :as json]
            [pandect.algo.sha256 :as sha256]
            [the-system.blink.exchanges.dydx.pedersen :as pedersen]
            [taoensso.encore :as enc]
            [clojure.walk :as walk]
            [taoensso.tufte :as tufte]
            [io.sixtant.rfc6979 :as rfc6979])
  (:import (java.math RoundingMode)
           (org.bouncycastle.math.ec ECCurve$Fp)))


(set! *warn-on-reflection* true)


(comment
  (def test-stark-priv "0x10df7f0ca8e3c1e1bd56693bb2725342c3fe08d7042ee6a4d2dad592b9a90c3")

  (json/read-str "{\"market\": \"BTC-USD\", \"side\": \"SELL\", \"type\": \"LIMIT\", \"timeInForce\": \"GTT\", \"size\": \"100\", \"price\": \"18000\", \"limitFee\": \"0.015\", \"expiration\": \"2022-12-21T21:30:20.200Z\", \"cancelId\": null, \"triggerPrice\": null, \"trailingPercent\": null, \"postOnly\": false, \"clientId\": \"91364379829165\", \"signature\": \"0289ad6d0177bf3ddbdbaf655ee1ef705be79c1a19cab995de25fcb09f05824803914abd7d995c03a0bf601812fd76dd6205b01976a0e7d1158c0929a5343201\"}")

  {"trailingPercent" nil,
   "limitFee" "0.015",
   "side" "SELL",
   "triggerPrice" nil,
   "cancelId" nil,
   "signature" "0289ad6d0177bf3ddbdbaf655ee1ef705be79c1a19cab995de25fcb09f05824803914abd7d995c03a0bf601812fd76dd6205b01976a0e7d1158c0929a5343201",
   "postOnly" false,
   "clientId" "91364379829165",
   "type" "LIMIT",
   "expiration" "2022-12-21T21:30:20.200Z",
   "size" "100",
   "price" "18000",
   "timeInForce" "GTT",
   "market" "BTC-USD"}
  )


(comment
  ;; order_to_sign = SignableOrder(
  ;;                               position_id=position_id,
  ;;                               client_id=client_id,
  ;;                               market=market,
  ;;                               side=side,
  ;;                               human_size=size,
  ;;                               human_price=price,
  ;;                               human_limit_fee=limit_fee,
  ;;                               expiration_epoch_seconds=iso_to_epoch_seconds(expiration),
  ;;                               )
  ;; order_signature = order_to_sign.sign(self.stark_private_key)

  (long (/ (inst-ms #inst"2022-12-21T21:30:20.200Z") 1000))

  {:position-id 1
   :client-id "91364379829165"
   :market "BTC-USD"
   :side "SELL"
   :human-size 100M
   :human-price 18000M
   :human-limit-fee 0.015M
   :expiration-epoch-seconds 1671658220}

  ; from dydx3.starkex.order import SignableOrder
  ; o = SignableOrder(position_id=1, client_id="91364379829165", market="BTC-USD", side="SELL", human_size="100", human_price="18000", human_limit_fee="0.015", expiration_epoch_seconds=1671658220)
  ; Message: ["LIMIT_ORDER_WITH_FEES", 0, 1244395526148093605117595054168172062218752879259769683800039479765231001178, 1244395526148093605117595054168172062218752879259769683800039479765231001178, 1000000000000, 1800000000000, 15000, false, 1, 841357518, 1671658220]

  ; o.sign('0x10df7f0ca8e3c1e1bd56693bb2725342c3fe08d7042ee6a4d2dad592b9a90c3')
  ; '0289ad6d0177bf3ddbdbaf655ee1ef705be79c1a19cab995de25fcb09f05824803914abd7d995c03a0bf601812fd76dd6205b01976a0e7d1158c0929a5343201'

  ; o._calculate_hash()
  ; 3177457393241883988643079605937866346697240808070109220974724930828805695181

  )


(defn to-quantums
  ([n quantums-per-n]
   (to-quantums n quantums-per-n RoundingMode/UNNECESSARY))
  ([n quantums-per-n ^RoundingMode rounding]
   (try
     (.toBigInteger
       (.setScale
         ^BigDecimal (* (bigdec n) (bigdec quantums-per-n))
         0 rounding))
     (catch ArithmeticException _
       (->> {:n n :quantums-per-n quantums-per-n}
            (ex-info (format "No integer value from %s * %s" n quantums-per-n))
            (throw))))))


(def starkware-constants
  {:collateral-asset     "USDC"
   :>synthetic-asset     {"BTC-USD"  "BTC"
                          "ETH-USD"  "ETH"
                          "LINK-USD" "LINK"}
   :>asset-id            (enc/map-vals
                           biginteger
                           {"USDC" 0x02c04d8b650f44092278a7cb1e1028c82025dff622db96c934b611b84cc8de5a
                            "BTC"  0
                            "ETH"  1
                            "LINK" 2})
   :>lots                (enc/map-vals
                           biginteger
                           {"USDC" 1e6M
                            "BTC"  1e10M
                            "ETH"  1e8M
                            "LINK" 1e7M})
   :field-bit-lengths    {:asset-id-synthetic       128
                          :asset-id-collateral      250
                          :asset-id-fee             250
                          :quantums-amount          64
                          :nonce                    32
                          :position-id              64
                          :expiration-epoch-seconds 32}
   :order-prefix         3
   :order-padding-bits   17
   :n-element-bits-ecdsa 251
   :ec-curve-order       (biginteger 3618502788666131213697322783095070105526743751716087489154079457884512865583)})


;; Starkware pads the message hash for consistency with the elliptic.js library
(defn- ^BigInteger pad-msg-hash [^BigInteger msg-hash]
  (let [bit-length (.bitLength msg-hash)]
    (if (and (<= 1 (rem bit-length 8) 4) (>= bit-length 248))
      (.multiply msg-hash (biginteger 16))
      msg-hash)))


(defn rfc6979-k-value
  [^BigInteger msg-hash ^BigInteger private-key extra-entropy]
  (first
    (rfc6979/generate-ks
      {:curve-order (:ec-curve-order starkware-constants)
       :private-key private-key
       :data (.toByteArray (pad-msg-hash msg-hash))
       :hash-digest (rfc6979/sha-256-digest)
       :extra-entropy (if extra-entropy
                        (.toByteArray ^BigInteger extra-entropy)
                        (byte-array []))})))


(defn ^BigInteger ec-multiply
  "Multiply the generator point on the stark curve by `k`, returning the X
  coordinate of the resulting point."
  [k]
  (let [field-prime (biginteger 3618502788666131213697322783095070105623107215331596699973092056135872020481)
        field-alpha BigInteger/ONE
        field-beta (biginteger 3141592653589793238462643383279502884197169399375105820974944592307816406665)
        curve (ECCurve$Fp. field-prime field-alpha field-beta)

        generator-point-affine
        [(biginteger 874739451078007766457464989774322083649278607533249481151382481072868806602)
         (biginteger 152666792071518830868575557812948353041420400780739481342941381225525861407)]

        generator-point (.createPoint curve (first generator-point-affine) (second generator-point-affine))]
    (-> (.multiply generator-point k)
        .normalize
        .getAffineXCoord
        .toBigInteger)))


;;; N.B. it's probably worth reviewing [1] for the following code segments
;;; [1] https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm


(defn modular-multiplicative-inverse ; nb. called div-mod in dydx reference code
  "Find x in [0, p) such that (m * x) % p = n"
  [n m p]
  (let [n (biginteger n)
        m (biginteger m)
        p (biginteger p)]
    (-> (.modInverse m p)
        (.multiply n)
        (.mod p))))


(defn- invalid-signature?
  [^BigInteger k ^BigInteger r ^BigInteger s ^BigInteger msg-hash ^BigInteger private-key]
  (let [max-value (.subtract
                    (.pow BigInteger/TWO (:n-element-bits-ecdsa starkware-constants))
                    BigInteger/ONE)]
    (or
      (not (<= 1 r max-value))
      (not (<= 1 s max-value))
      (zero?
        (.mod
          (.add (.multiply r private-key) msg-hash)
          (:ec-curve-order starkware-constants))))))


;; Note: sign & encode benchmarked at 1.281ms compared to 19.348ms in the
;; reference implementation :)
(defn starkware-sign [^BigInteger msg-hash ^BigInteger private-key]
  (assert
    (and
      (pos? msg-hash)
      (< msg-hash (Math/pow 2 (:n-element-bits-ecdsa starkware-constants)))))

  ;; In the starkware version of ECDSA, not every k value is valid. If a k value
  ;; is thrown out, a new one is generated using monotonically increasing
  ;; entropy as a k' value in accordance with the variant of RFC 6979 described
  ;; in [section 3.6](https://tools.ietf.org/html/rfc6979#section-3.6)
  (loop [extra-entropy nil] ; They use: nil, 1, 2, ...
    (let [k (rfc6979-k-value msg-hash private-key extra-entropy)
          ;; Difference: in classical ECDSA, r = (mod (ec-multiply k) n)
          r (ec-multiply k)
          ; n.b. `s` is called `w` in dydx reference implementation (this is
          ; an intermediate s in their version of ECDSA)
          s (modular-multiplicative-inverse
              k
              (.add (.multiply r private-key) msg-hash)
              (:ec-curve-order starkware-constants))]
      (if (invalid-signature? k r s msg-hash private-key)
        (recur (inc (or extra-entropy 0)))
        (let [s (modular-multiplicative-inverse
                  BigInteger/ONE
                  s
                  (:ec-curve-order starkware-constants))]
          [r s])))))


;; Instead of DER encoding, they just concat the hex strings
(defn encode-sig [[r s]]
  (let [hex32str (fn [^BigInteger n] (format "%064x" n))]
    (str (hex32str r) (hex32str s))))


(let [nonce-bit-length (get-in starkware-constants [:field-bit-lengths :nonce])
      max-nonce (.shiftLeft BigInteger/ONE nonce-bit-length)]
  (defn nonce-from-cid [cid]
    (.mod (BigInteger. ^String (sha256/sha256 cid) 16) max-nonce)))


(defn starkware-order
  [{:keys [position-id client-id market side human-size human-price
           human-limit-fee expiration-epoch-seconds]}
   {:keys [collateral-asset >synthetic-asset >asset-id >lots]}]
  (let [is-buying-synthetic (= side "BUY")
        synthetic-asset (>synthetic-asset market)
        quantums-amount-synthetic (to-quantums human-size (>lots synthetic-asset))
        quantums-amount-fee (to-quantums human-limit-fee (>lots collateral-asset))
        human-cost (* (bigdec human-size) (bigdec human-price))
        quantums-amount-collateral (to-quantums
                                     human-cost
                                     (>lots collateral-asset)
                                     (if is-buying-synthetic
                                       RoundingMode/UP
                                       RoundingMode/DOWN))]
    {:type "LIMIT_ORDER_WITH_FEES"
     :asset-ids {:synthetic (>asset-id synthetic-asset)
                 :collateral (>asset-id collateral-asset)
                 :fee (>asset-id collateral-asset)}
     :quantums {:synthetic quantums-amount-synthetic
                :collateral quantums-amount-collateral
                :fee quantums-amount-fee}
     :buying-synthetic? is-buying-synthetic
     :position-id (biginteger position-id)
     :nonce (nonce-from-cid client-id)
     :expiration-epoch-seconds expiration-epoch-seconds}))


(defn- shift-plus [^BigInteger i n-bits ^BigInteger plus-i]
  (-> i (.shiftLeft n-bits) (.add plus-i)))


(defn- shift-left [^BigInteger i n-bits] (.shiftLeft i n-bits))


(defn starkware-merkle-tree
  "Build a Merkle tree with named nodes from the starkware order attributes.

  Node names correspond to the variable names used in the dYdX reference
  implementation, which constructs the tree and hashes it at the same time,
  whereas here it is split out to clarify (slightly) what is going on."
  [{:keys [asset-ids quantums buying-synthetic? position-id nonce expiration-epoch-seconds]}
   {:keys [field-bit-lengths order-prefix order-padding-bits]}]
  (let [[buyq sellq buya sella]
        (if buying-synthetic?
          [(:synthetic quantums) (:collateral quantums)
           (:synthetic asset-ids) (:collateral asset-ids)]
          [(:collateral quantums) (:synthetic quantums)
           (:collateral asset-ids) (:synthetic asset-ids)])
        ;field bit length
        fbl (fn [f] (get field-bit-lengths f))]
    [[{:name :assets-hash
       :value [[{:name :asset-id-sell :value sella}
                {:name :asset-id-buy :value buya}]
               {:name :asset-id-fee :value (get asset-ids :fee)}]}
      {:name :part-1
       :value (-> sellq
                  (shift-plus (fbl :quantums-amount) buyq)
                  (shift-plus (fbl :quantums-amount) (:fee quantums))
                  (shift-plus (fbl :nonce) nonce))}]
     {:name :part-2
      :value (-> (biginteger order-prefix)
                 (shift-plus (fbl :position-id) position-id)
                 (shift-plus (fbl :position-id) position-id)
                 (shift-plus (fbl :position-id) position-id)
                 (shift-plus (fbl :expiration-epoch-seconds)
                             (biginteger expiration-epoch-seconds))
                 (shift-left order-padding-bits))}]))


(defn hash-merkle-tree
  "Collapse the Merkle tree `t` whose nodes are {:name _, :value _}, using
  the hash function `h` to hash sibling nodes."
  [t h]
  (walk/postwalk
    (fn [node]
      (cond
        (map? node) (:value node)
        (and (vector? node) (not (map-entry? node))) (apply h node)
        :else node))
    t))


(defn starkware-hash
  "The hash that needs to be signed for an order placement.

  Note: This is slow. Benchmarked at 4.116ms (35.251ms in the dYdX reference
  client)."
  [starkware-order starkware-constants]
  (-> starkware-order
      (starkware-merkle-tree starkware-constants)
      (hash-merkle-tree pedersen/pedersen-hash)))


(comment

  (require 'criterium.core)

  (def dydx-order
    {:position-id 1
     :client-id "91364379829165"
     :market "BTC-USD"
     :side "SELL"
     :human-size 100M
     :human-price 18000M
     :human-limit-fee 0.015M
     :expiration-epoch-seconds 1671658220})

  (def stark-order
    (starkware-order dydx-order starkware-constants))

  (def stark-merkle
    (starkware-merkle-tree stark-order starkware-constants))

  (def stark-hash
    (starkware-hash stark-order starkware-constants))

  priv
  (enc/qb
    100
    (starkware-hash stark-order starkware-constants)
    (starkware-hash-fast stark-order starkware-constants))



  ;; Reference client with 1000 runs took 35.251 ms per run
  ;; Clojure client took 4.116 ms per run
  (criterium.core/quick-bench
    (starkware-hash stark-order starkware-constants))

  (tufte/add-basic-println-handler! {})
  (tufte/profile {}
    (dotimes [_ 100]
      (starkware-hash stark-order starkware-constants)))

  (enc/qb
    100
    (starkware-order dydx-order starkware-constants)
    (starkware-merkle-tree stark-order starkware-constants)
    (hash-merkle-tree stark-merkle pedersen/pedersen-hash))

  (starkware-hash
    (starkware-order
      {:position-id 1
       :client-id "91364379829165"
       :market "BTC-USD"
       :side "SELL"
       :human-size 100M
       :human-price 18000M
       :human-limit-fee 0.015M
       :expiration-epoch-seconds 1671658220}
      starkware-constants)
    starkware-constants)

  (starkware-merkle-tree *2 starkware-constants)
  (= *1 stark-merkle)

  (= *1 3177457393241883988643079605937866346697240808070109220974724930828805695181)

  (.toString *1 16)

  )
