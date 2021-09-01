(ns io.sixtant.dydx-starkware.starkware-data
  "For creating & hashing Starkware data.

  Transactions on the Starkware L2 need to be signed with the stark keys.
  Transactional dYdX API calls need to affect the L2, and therefore need to
  include a stark signature that the dYdX API uses to interact with the L2 on
  the requester's behalf.

  The process of making any such request is:
    1. Take some request data in a shape that the dYdX API understands.
    2. Translate that request data into a shape that Starkware understands,
       hash it, and sign it with the stark keys.
    3. Take the resulting signature and include it in the original request data
       to get the final request data.
    4. Sign the final request data with the dYdX API keys and broadcast it to
       the dYdX API.

  This namespace handles step (2).

  See also: https://docsv3.dydx.exchange/#authentication"
  (:require [io.sixtant.dydx-starkware.pedersen :as pedersen]
            [io.sixtant.dydx-starkware.starkware-constants :as const]
            [io.sixtant.dydx-starkware.solidity-keccak :as abi]
            [io.sixtant.dydx-starkware.time :as t]

            [clojure.walk :as walk]

            [pandect.algo.sha256 :as sha256]
            [pandect.algo.keccak-256 :as k256])
  (:import (java.math RoundingMode)
           (org.bouncycastle.util.encoders Hex)))


(set! *warn-on-reflection* true)


;;; Helpers


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
(def ^:const max-nonce (.shiftLeft BigInteger/ONE (const/obits :nonce)))
(defn nonce-from-cid [cid]
  (.mod (BigInteger. ^String (sha256/sha256 cid) 16) max-nonce))


(defn exp-hours
  "For some expiration inst, calculate an integer :expiration-epoch-hours field
  consistent with the one that dYdX uses."
  [expiration expiration-buffer-hours]
  (let [seconds-per-hour 3600
        expiration-epoch-seconds (t/inst-s expiration)]
    (long
      (Math/ceil
        (+ (/ expiration-epoch-seconds seconds-per-hour)
           ;; They add this buffer to make sure orders are still valid when
           ;; matched on-chain. We'll use the same buffer for signature
           ;; consistency.
           expiration-buffer-hours)))))


;;; Starkware order creation


(defn order
  "Build the Starkware order which corresponds to some dYdX placement request.

  The Starkware order only includes a subset of the dYdX fields."
  [{:keys [positionId clientId market side size price limitFee expiration]}
   {:keys [collateral-asset >synthetic-asset >asset-id >lots]}]
  (let [is-buying-synthetic (= side "BUY")
        synthetic-asset (>synthetic-asset market)
        quantums-amount-synthetic (to-quantums size (>lots synthetic-asset))
        human-cost (* (bigdec size) (bigdec price))
        quantums-amount-collateral (to-quantums
                                     human-cost
                                     (>lots collateral-asset)
                                     (if is-buying-synthetic
                                       RoundingMode/UP
                                       RoundingMode/DOWN))
        quantums-amount-fee (.toBigInteger
                              (.setScale
                                ^BigDecimal
                                (* (bigdec limitFee) quantums-amount-collateral)
                                0 RoundingMode/UP))]
    {:type "LIMIT_ORDER_WITH_FEES"
     :asset-ids {:synthetic (>asset-id synthetic-asset)
                 :collateral (>asset-id collateral-asset)
                 :fee (>asset-id collateral-asset)}
     :quantums {:synthetic quantums-amount-synthetic
                :collateral quantums-amount-collateral
                :fee quantums-amount-fee}
     :buying-synthetic? is-buying-synthetic
     :position-id (biginteger positionId)
     :nonce (nonce-from-cid clientId)
     :expiration-epoch-hours (exp-hours expiration (* 24 7))}))


;;; Starkware order hashing, which involves hashing successive pairs of order
;;; attributes via their Pedersen has algorithm.


(defn- shift-left [^BigInteger i n-bits] (.shiftLeft i n-bits))
(defn- shift-plus [^BigInteger i n-bits ^BigInteger plus-i]
  (-> i (.shiftLeft n-bits) (.add plus-i)))


(defn order-merkle-tree
  "Build a Merkle tree with named nodes from the Starkware order attributes.

  Node names correspond to the variable names used in the dYdX reference
  implementation, which constructs the tree and hashes it at the same time,
  whereas here it is split out to clarify what is going on."
  [{:keys [asset-ids quantums buying-synthetic? position-id nonce
           expiration-epoch-hours]}]
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
                  (shift-plus (const/obits :quantums-amount) buyq)
                  (shift-plus (const/obits :quantums-amount) (:fee quantums))
                  (shift-plus (const/obits :nonce) nonce))}]
     {:name :part-2
      :value (-> (biginteger const/order-prefix)
                 (shift-plus (const/obits :position-id) position-id)
                 (shift-plus (const/obits :position-id) position-id)
                 (shift-plus (const/obits :position-id) position-id)
                 (shift-plus
                   (const/obits :expiration-epoch-hours)
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


(defn hash-order
  "Hash the Starkware order, returning the signable data.

  Note: This is slow. Benchmarked at 4.116ms (35.251ms in the dYdX reference
  client)."
  [starkware-order]
  (-> starkware-order
      (order-merkle-tree)
      (hash-merkle-tree pedersen/pedersen-hash)))


;;; Starkware conditional transfer (dYdX fast withdrawal) creation


(defn transfer-erc20-fact
  [{:keys [toAddress creditAmount creditAsset clientId]} asset-meta-data]
  (let [token-amount
        (-> (bigdec creditAmount)
            ^BigDecimal (* (get-in asset-meta-data [:>lots creditAsset]))
            (.toBigIntegerExact))
        hex-int (fn [^String addr] (BigInteger. (subs addr 2) 16))]
    (abi/solidity-keccak
      (abi/address (hex-int toAddress))
      (abi/uint256 token-amount)
      (abi/address
        (hex-int
          (get-in asset-meta-data [:token-contracts creditAsset])))
      (abi/uint256 (nonce-from-cid clientId)))))


(defn fact-to-condition [fact-registry-address fact-hex]
  (let [data (byte-array
               (concat
                 (Hex/decode (subs fact-registry-address 2))
                 (Hex/decode (subs fact-hex 2))))
        mask (biginteger (- (.pow (biginteger 2) 250) 1))]
    (.and (BigInteger. ^String (k256/keccak-256 data) 16) mask)))


(defn conditional-transfer
  "Build the Starkware conditional transfer that corresponds to a dYdX fast
  withdrawal request.

  Note that while creditAmount and toAddress are not present in the data
  structure, they are inputs to the ERC20 transfer fact, which is included."
  [{:keys [debitAsset debitAmount expiration clientId positionId
           lpPositionId lpStarkPublicKey] :as req}
   {:keys [>lots >asset-id contracts] :as asset-meta}]
  (let [fact-hex (transfer-erc20-fact req asset-meta)
        transfer-condition (fact-to-condition
                             (:fact-registry contracts)
                             fact-hex)]
    {:sender-position-id (biginteger positionId)
     :receiver-position-id (biginteger lpPositionId)
     :receiver-public-key (BigInteger. ^String lpStarkPublicKey 16)
     :condition transfer-condition
     :quantums-amount (to-quantums debitAmount (get >lots debitAsset))
     :nonce (nonce-from-cid clientId)
     :expiration-epoch-hours (exp-hours expiration 0)
     :asset-ids {:collateral (>asset-id debitAsset)
                 :fee (biginteger const/conditional-transfer-fee-asset-id)}}))


(defn conditional-transfer-merkle-tree
  [{:keys [receiver-public-key condition asset-ids
           sender-position-id receiver-position-id nonce
           quantums-amount expiration-epoch-hours]}]
  (let [asset-ids {:name :asset-ids
                   :value [(:collateral asset-ids) (:fee asset-ids)]}]
    [[{:name :part-1
       :value [{:name :asset-ids+receiver-key
                :value [asset-ids receiver-public-key]}
               condition]}
      {:name :part-2
       :value (-> sender-position-id
                  (shift-plus (const/ctbits :position-id) receiver-position-id)
                  (shift-plus (const/ctbits :position-id) sender-position-id)
                  (shift-plus (const/ctbits :nonce) nonce))}]
     {:name :part-3
      :value (-> (biginteger const/conditional-transfer-prefix)
                 (shift-plus (const/ctbits :quantums-amount) quantums-amount)
                 (shift-plus
                   (const/ctbits :quantums-amount)
                   (biginteger const/conditional-transfer-max-fee))
                 (shift-plus
                   (const/ctbits :expiration-epoch-hours)
                   (biginteger expiration-epoch-hours))
                 (shift-left const/conditional-transfer-padding-bits))}]))


(defn hash-conditional-transfer
  "Hash the Starkware conditional transfer, returning the signable data."
  [conditional-transfer]
  (-> conditional-transfer
      conditional-transfer-merkle-tree
      (hash-merkle-tree pedersen/pedersen-hash)))
