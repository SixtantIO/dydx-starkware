(ns io.sixtant.dydx-starkware.starkware-order
  "For creating & hashing Starkware orders.

  Order creation goes through the L2 (Starkware), so order placement requests
  are hashed and signed with Starkware API keys, before being sent to dYdX as
  HTTP requests which are signed with dYdX API keys.

  See: https://docsv3.dydx.exchange/#authentication"
  (:require [io.sixtant.dydx-starkware.pedersen :as pedersen]
            [io.sixtant.dydx-starkware.starkware-constants :as const]

            [clojure.walk :as walk]

            [pandect.algo.sha256 :as sha256])
  (:import (java.math RoundingMode)))


(set! *warn-on-reflection* true)


;;; Starkware order creation


(defn to-quantums
  "Opposite of quantize -- get the number of quantums that compose a quantized
  value."
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


;;; Nonces are deterministic from CIDs
(def ^:const max-nonce (.shiftLeft BigInteger/ONE (const/bitlen :nonce)))
(defn nonce-from-cid [cid]
  (.mod (BigInteger. ^String (sha256/sha256 cid) 16) max-nonce))


(defn starkware-order
  "Build a Starkware order, which must be hashed and signed to compute the
  :signature to include in the dYdX order. The Starkware order only includes
  some of the dYdX fields."
  [{:keys [position-id client-id market side human-size human-price
           human-limit-fee expiration-epoch-seconds]}
   {:keys [collateral-asset >synthetic-asset >asset-id >lots]}]
  (let [is-buying-synthetic (= side "BUY")
        synthetic-asset (>synthetic-asset market)
        quantums-amount-synthetic (to-quantums human-size (>lots synthetic-asset))
        human-cost (* (bigdec human-size) (bigdec human-price))
        quantums-amount-collateral (to-quantums
                                     human-cost
                                     (>lots collateral-asset)
                                     (if is-buying-synthetic
                                       RoundingMode/UP
                                       RoundingMode/DOWN))
        quantums-amount-fee (.toBigInteger
                              (.setScale
                                ^BigDecimal
                                (* (bigdec human-limit-fee)
                                   quantums-amount-collateral)
                                0 RoundingMode/UP))

        ;; They add this buffer to make sure orders are still valid when matched
        ;; on-chain. We'll use the same buffer for signature consistency.
        expiration-buffer-hours (* 24 7)
        seconds-per-hour 3600
        exp-hours (Math/ceil
                    (+ (/ expiration-epoch-seconds seconds-per-hour)
                       expiration-buffer-hours))]
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
     :expiration-epoch-hours (long exp-hours)}))


;;; Starkware order hashing, which involves hashing successive pairs of order
;;; attributes via their Pedersen has algorithm.


(defn- shift-left [^BigInteger i n-bits] (.shiftLeft i n-bits))
(defn- shift-plus [^BigInteger i n-bits ^BigInteger plus-i]
  (-> i (.shiftLeft n-bits) (.add plus-i)))


(defn starkware-merkle-tree
  "Build a Merkle tree with named nodes from the starkware order attributes.

  Node names correspond to the variable names used in the dYdX reference
  implementation, which constructs the tree and hashes it at the same time,
  whereas here it is split out to clarify (slightly) what is going on."
  [{:keys [asset-ids quantums buying-synthetic? position-id nonce expiration-epoch-hours]}]
  (let [[buyq sellq buya sella]
        (if buying-synthetic?
          [(:synthetic quantums) (:collateral quantums)
           (:synthetic asset-ids) (:collateral asset-ids)]
          [(:collateral quantums) (:synthetic quantums)
           (:collateral asset-ids) (:synthetic asset-ids)])]
    [[{:name :assets-hash
       :value [[{:name :asset-id-sell :value sella}
                {:name :asset-id-buy :value buya}]
               {:name :asset-id-fee :value (get asset-ids :fee)}]}
      {:name :part-1
       :value (-> sellq
                  (shift-plus (const/bitlen :quantums-amount) buyq)
                  (shift-plus (const/bitlen :quantums-amount) (:fee quantums))
                  (shift-plus (const/bitlen :nonce) nonce))}]
     {:name :part-2
      :value (-> (biginteger const/order-prefix)
                 (shift-plus (const/bitlen :position-id) position-id)
                 (shift-plus (const/bitlen :position-id) position-id)
                 (shift-plus (const/bitlen :position-id) position-id)
                 (shift-plus (const/bitlen :expiration-epoch-hours)
                             (biginteger expiration-epoch-hours))
                 (shift-left const/order-padding-bits))}]))


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
  [starkware-order]
  (-> starkware-order
      (starkware-merkle-tree)
      (hash-merkle-tree pedersen/pedersen-hash)))
