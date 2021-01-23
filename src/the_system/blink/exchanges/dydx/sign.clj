;; TODO: Once this is all cleaned up, benchmark standard order placement in this
;;       implementation and in the reference implementation.
;; TODO: Figure out how 'constants' should be organized and split out. (And,
;;       which are really constant? Seems like asset ids, etc. might change,
;;       whereas message protocol level stuff should stay the same?)
(ns the-system.blink.exchanges.dydx.sign
  "Signature schemes for STARK and dYdX.

  See: https://docsv3.dydx.exchange/#authentication"
  (:require [clojure.data.json :as json]
            [pandect.algo.sha256 :as sha256]
            [the-system.blink.exchanges.dydx.pedersen :as pedersen]
            [taoensso.encore :as enc]
            [clojure.walk :as walk]
            [taoensso.tufte :as tufte]
            [io.sixtant.rfc6979 :as rfc6979]
            [the-system.utils :as utils]
            [clojure.string :as string])
  (:import (java.math RoundingMode)
           (org.bouncycastle.math.ec ECCurve$Fp)))


(set! *warn-on-reflection* true)


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


(defn modular-multiplicative-inverse ; nb called div-mod in dydx reference code
  "Find x in [0, p) such that (m * x) % p = n"
  [n m p]
  (let [n (biginteger n)
        m (biginteger m)
        p (biginteger p)]
    (-> (.modInverse m p)
        (.multiply n)
        (.mod p))))


(defn- invalid-signature?
  [^BigInteger r ^BigInteger s ^BigInteger msg-hash ^BigInteger private-key]
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
          ; in classical ECDSA, r = (mod (ec-multiply k) n)
          r (ec-multiply k)
          ; n.b. `s` is called `w` in dydx reference implementation (this is
          ; an intermediate s in their version of ECDSA)
          s (modular-multiplicative-inverse
              k
              (.add (.multiply r private-key) msg-hash)
              (:ec-curve-order starkware-constants))]
      (if (invalid-signature? r s msg-hash private-key)
        (recur (inc (or extra-entropy 0)))
        (let [s (modular-multiplicative-inverse
                  BigInteger/ONE
                  s
                  (:ec-curve-order starkware-constants))]
          [r s])))))


;; Instead of DER encoding, they just concat the hex strings
(defn encode-sig [[r s]] (format "%064x%064x" r s))


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


;; TODO: Depending on what else needs to happen, this stuff can probably happen
;;       directly in the endpoint
(defn dydx-order
  [{:keys [market side ^BigDecimal qty ^BigDecimal price iid post-only?]}
   ^BigDecimal limit-fee
   expiration]
  {:market      (utils/show-upper market "-")
   :side        (case side :bids "BUY" :asks "SELL")
   :type        "LIMIT"
   :postOnly    (if post-only? true false)
   :size        (.toPlainString (.stripTrailingZeros qty))
   :price       (.toPlainString (.stripTrailingZeros price))
   :limitFee    (.toPlainString (.stripTrailingZeros limit-fee))
   :expiration  expiration
   :timeInForce "GTT"
   :clientId    iid})


(defn sign-order [dydx-order stark-private-key]
  (-> {:position-id              1
       :client-id                (:clientId dydx-order)
       :market                   (:market dydx-order)
       :side                     (:side dydx-order)
       :human-size               (:size dydx-order)
       :human-price              (:price dydx-order)
       :human-limit-fee          (:limitFee dydx-order)
       :expiration-epoch-seconds (utils/inst-s (:expiration dydx-order))}
      (starkware-order starkware-constants)
      (starkware-hash starkware-constants)
      (starkware-sign stark-private-key)
      (encode-sig)))


(defn sign-request [{:keys [path method inst body] :as req} dydx-private-key]
  (let [iso-ts (utils/pr-inst-iso inst)
        method (string/upper-case (name method))
        message (str iso-ts method path body)
        mhash (-> ^String (sha256/sha256 message)
                  (BigInteger. 16)
                  (.shiftRight 5))
        sig (encode-sig (starkware-sign mhash dydx-private-key))]
    (assoc req :sig sig)))
