(ns io.sixtant.dydx-starkware.solidity-keccak
  "Clojure implementation of the web3.Web3.solidityKeccak[1][2] function.

  Takes a series of typed values, encodes them with the Ethereum ABI using
  non-standard packed mode[3], and then hashes them with Keccak-256.

  Output matches the output of the web3.py library, even where it differs from
  the spec. E.g. the spec says not to pad or sign extend fields smaller than 32
  bytes (is this a typo and they mean bits?), but addresses (20 bytes) are
  padded in the web3.py library implementation, so this library does the same.

  [1] https://web3py.readthedocs.io/en/stable/web3.main.html#web3.Web3.solidityKeccak
  [2] https://github.com/ethereum/web3.py/blob/8ce56bd124801dd5c46a4b6a1df9d6f65b3736e0/web3/main.py#L301
  [3] https://docs.soliditylang.org/en/develop/abi-spec.html#non-standard-packed-mode"
  (:refer-clojure :exclude [int bytes])
  (:require [clojure.string :as string]
            [taoensso.truss :as truss]
            [pandect.algo.keccak-256 :as k256])
  (:import (org.bouncycastle.util.encoders Hex)))


;;; ABI primitive types and their hex string encoding


(defmulti encode
  "Encode a single typed value with the ABI, return a hex string of the
  corresponding `bit-size`. If `bit-size` is nil, don't use padding.

  Each value is {:type _, :value _, :width _}, where :width is some number of
  bytes, and this method dispatches on :type."
  (fn [{:keys [type value width]}]
    type))


(defn uint
  ([i] (uint 256 i)) ; spec says 'uint' is equivalent to 'uint256'
  ([bits i]
   (truss/have (every-pred pos? integer?) i)
   (truss/have (every-pred #(< 0 % 257) #(zero? (mod % 8))) bits)
   {:type :uint :value i :width (/ bits 8)}))


(def uint8 (partial uint 8))
(def uint16 (partial uint 16))
(def uint32 (partial uint 32))
(def uint256 (partial uint 256))
(defn address [i] (uint 160 i))
(defn hex [nbytes value] (format (str "%0" (* 2 nbytes) "x") value))
(defmethod encode :uint [{:keys [value width]}] (hex width (biginteger value)))


(defn int
  ([i] (int 256 i)) ; spec says 'int' is equivalent to 'int256'
  ([bits i]
   (truss/have integer? i)
   (truss/have (every-pred #(< 0 % 257) #(zero? (mod % 8))) bits)
   {:type :int :width (/ bits 8) :value i}))


(def int8 (partial int 8))
(def int16 (partial int 16))
(def int32 (partial int 32))
(def int256 (partial int 256))


(defmethod encode :int
  [{:keys [value width]}]
  (let [bs (.toByteArray (biginteger value))
        padding-bytes (repeat (- width (count bs)) -1)]
    (Hex/toHexString (byte-array (concat padding-bytes bs)))))


(defn bool [x] (truss/have boolean? x) {:type :bool :value x :width 1})
(defmethod encode :bool [{:keys [value width]}] (hex width (if value 1 0)))


(defn bytes
  "Either dynamic in size if just byte array is provided or static if `nbytes`
  is also specified."
  ([byte-array']
   {:type :bytes :value byte-array' :width nil})
  ([nbytes byte-array']
   (truss/have (every-pred integer? #(< 0 % 33)) nbytes)
   {:type :bytes :value byte-array' :width nbytes}))


(def bytes32 (partial bytes 32))


(defmethod encode :bytes
  [{:keys [value width]}]
  (let [bs (.toByteArray (biginteger value))
        padding-bytes (when width ; only pad if fixed width version of the type
                        (repeat (- width (count bs)) 0))]
    (Hex/toHexString (byte-array (concat bs padding-bytes)))))


(defn string [s] {:type :string :value s :width nil})
(defmethod encode :string [x] (Hex/toHexString (.getBytes (:value x) "UTF-8")))


;;; Algorithm for packed encoding of ABI values, exactly as done by Solidity.
;;; https://docs.soliditylang.org/en/develop/abi-spec.html#non-standard-packed-mode


(defn encode-packed*
  ([value]
   (encode-packed* value nil))
  ([value ?force-width]
   (if (map? value)
     (encode
       (cond-> value ?force-width (assoc :width ?force-width)))
     (do
       (assert (apply = (map :type value)) "array values are the same type")
       (assert (apply = (map :width value)) "array values are the same type")
       (string/join (map #(encode-packed* % 32) value))))))


(defn encode-packed
  "Perform packed ABI encoding exactly as Solidity does, returning a hex string.

  Values are e.g. `(uint8 97)`, see the constructors in this namespace.

  See the relevant section of the spec for details [1].

  [1] https://docs.soliditylang.org/en/v0.5.3/abi-spec.html#non-standard-packed-mode"
  [values]
  (let [encoded (map encode-packed* values)]
    (string/join encoded)))


(defn solidity-keccak
  "Encodes, packs, and hashes values with keccak256 exactly as Solidity does.

  The values are built from constructors from this namespace corresponding to
  Solidity types (e.g. `(uint8 10)` or `(address 0x....)`). Solidity arrays like
  `unit8[]` are expressed as vectors, like `[(uint8 0) (uint8 1)]`."
  [& values]
  (let [abi-hex-encoded (encode-packed values)]
    (str "0x" (k256/keccak-256 (Hex/decode ^String abi-hex-encoded)))))
