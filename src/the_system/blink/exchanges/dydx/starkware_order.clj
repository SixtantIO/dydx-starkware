(ns the-system.blink.exchanges.dydx.starkware-order
  "For creating & hashing Starkware orders.

  Order creation goes through the L2 (Starkware), so order placement requests
  are hashed and signed with Starkware API keys, before being sent to dYdX as
  HTTP requests which are signed with dYdX API keys.

  See: https://docsv3.dydx.exchange/#authentication"
  (:require [the-system.blink.exchanges.dydx.pedersen :as pedersen]
            [the-system.blink.exchanges.dydx.starkware-constants :as const]
            [the-system.utils :as utils]

            [clojure.walk :as walk]
            [clojure.string :as string]

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
  [{:keys [asset-ids quantums buying-synthetic? position-id nonce expiration-epoch-seconds]}]
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
                 (shift-plus (const/bitlen :expiration-epoch-seconds)
                             (biginteger expiration-epoch-seconds))
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


(comment
  ;; TODO: This can happen directly in dydx.clj
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


  ;; TODO: Benchmark this vs reference implementation
  (defn sign-order [dydx-order asset-meta-data stark-private-key]
    (-> {:position-id              1
         :client-id                (:clientId dydx-order)
         :market                   (:market dydx-order)
         :side                     (:side dydx-order)
         :human-size               (:size dydx-order)
         :human-price              (:price dydx-order)
         :human-limit-fee          (:limitFee dydx-order)
         :expiration-epoch-seconds (utils/inst-s (:expiration dydx-order))}
        (starkware-order asset-meta-data)
        (starkware-hash)
        (starkware-sign stark-private-key)
        (encode-sig)))


  ;; TODO: Benchmark this vs reference implementation
  (defn sign-request [{:keys [path method inst body] :as req} dydx-private-key]
    (let [iso-ts (utils/pr-inst-iso inst)
          method (string/upper-case (name method))
          message (str iso-ts method path body)
          mhash (-> ^String (sha256/sha256 message)
                    (BigInteger. 16)
                    (.shiftRight 5))
          sig (encode-sig (starkware-sign mhash dydx-private-key))]
      (assoc req :sig sig)))


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
                           "05bdd9f24ad4ecec1a34efdf8f05a6765240ba6b1a5e49d9352fbda41968e22205db4f23bf03a58e2c5ad8ece4aefa4799e35306454a4fa3e3a14a782e9dfa65")))))
