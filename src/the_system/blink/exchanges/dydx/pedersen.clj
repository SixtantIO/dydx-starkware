(ns the-system.blink.exchanges.dydx.pedersen
  "A Starkware Pedersen hash, as implemented in dydxprotocol/dydx-v3-python[1].

  [1] https://github.com/dydxprotocol/dydx-v3-python/blob/35bc6800d44d9f2d096e0f036601269b795aebec/dydx3/starkex/starkex_resources/signature.py#L52"
  (:require [clojure.java.io :as io]
            [clojure.walk :as walk])
  (:import (org.bouncycastle.math.ec ECCurve$Fp)))


(set! *warn-on-reflection* true)


;; I also wrote a pure Clojure version :)
;; https://gist.github.com/matthewdowney/410ff9785c622f269f65e4b53e3984b5
(defn ec-add
  "Elliptic curve addition for two affine points on a curve over the finite
  field `p`."
  [pa pb p]
  (let [[ax ay] (mapv biginteger pa)
        [bx by] (mapv biginteger pb)
        curve (ECCurve$Fp. (biginteger p) ax ay)]
    (let [point (-> (.createPoint ^ECCurve$Fp curve ax ay)
                    (.add (.createPoint ^ECCurve$Fp curve bx by))
                    .normalize)]
      [(-> point .getAffineXCoord .toBigInteger)
       (-> point .getAffineYCoord .toBigInteger)])))


;;; Utilities for math with BigInteger values
(defn int-divide [^BigInteger n ^BigInteger d] (.divide n d))
(defn int-multiply [^BigInteger n ^BigInteger d] (.multiply n d))
(defn int-add [^BigInteger n ^BigInteger d] (.add n d))
(defn int-subtract [^BigInteger n ^BigInteger d] (.subtract n d))
(defn int-mod [^BigInteger n ^BigInteger m] (.mod n m))
(defn int-abs [^BigInteger n] (if (neg? n) (.negate n) n))


(defmacro biginteger-math
  "Replace operators (+ - / * mod) with the BigInteger equivalents and replace
  integer literals with BigIntegers."
  [& body]
  (->> `(do ~@body)
       (walk/postwalk
         (fn [x]
           (if (integer? x)
             (cond
               ;; Use the constants if we can
               (zero? x) `BigInteger/ZERO
               (= x 1) `BigInteger/ONE
               (= x 2) `BigInteger/TWO
               (= x 10) `BigInteger/TEN

               ;; Otherwise coerce via clojure.core/biginteger
               :else `(biginteger ~x))
             x)))
       (walk/postwalk-replace
         {'+   `int-add
          '-   `int-subtract
          '/   `int-divide
          '*   `int-multiply
          'mod `int-mod})))


;;; Pedersen hash algorithm


(defn- update-point [point x constant-points-subset field-prime]
  (let [[point x]
        (reduce
          (fn [[point ^BigInteger x] pt]
            (assert (not= (first pt) (first point)))
            (if-not (zero? (.and x BigInteger/ONE))
              [(ec-add point pt field-prime) (.shiftRight x 1)]
              [point (.shiftRight x 1)]))
          [point x]
          constant-points-subset)]
    (assert (zero? x))
    point))


(defn- constant-points-slice [constant-points idx bitlen]
  (let [lower (+ 2 (* idx bitlen))
        upper (+ 2 (* (+ idx 1) bitlen))]
    (if (> upper (count constant-points))
      (throw
        (ex-info
          "Too few constant points to construct a hash point."
          {:bitlength bitlen :idx idx}))
      (subvec constant-points lower upper))))


(defn pedersen-hash-pointf
  "Build a Pedersen hash function which takes two java.math.BigInteger values
  and returns an affine point on the elliptic curve over the finite field
  `field-prime`.

  I.e. f: int, int' -> [x, y]"
  [^BigInteger field-prime constant-points]
  (fn [a b]
    (let [shift-point (first constant-points)
          bitlen (.bitLength field-prime)]
      (reduce
        (fn [point [idx x]]
          (assert (<= 0 x field-prime))
          (let [slice (constant-points-slice constant-points idx bitlen)]
            (update-point point x slice field-prime)))
        shift-point
        [[0 (biginteger a)]
         [1 (biginteger b)]]))))


(defn pedersen-hashf
  "Build a Pedersen hash function shaped (fn [int int] => int) which operates
  on java.math.BigInteger values for an elliptic curve over the finite field
  `field-prime`.

  Uses a vector of constant points on the curve, shaped [[X, Y]], where
  coordinates are BigInteger values."
  [^BigInteger field-prime constant-points]
  (comp first (pedersen-hash-pointf field-prime constant-points)))


(defonce default-pedersen-params
  (let [raw (read-string (slurp (io/resource "pedersen_params.edn")))
        parse-points (fn [points]
                       (mapv
                         (fn [[x y]] [(biginteger x) (biginteger y)])
                         points))]
    (-> raw
        (update :FIELD_PRIME biginteger)
        (update :CONSTANT_POINTS parse-points))))


(def ^{:tag BigInteger :arglists '([a b])} pedersen-hash
  "Pedersen hash of integers `a` and `b`, using the field and constant points as
  used in dydx-v3-python (see ns doc)."
  (pedersen-hashf
    (:FIELD_PRIME default-pedersen-params)
    (:CONSTANT_POINTS default-pedersen-params)))
