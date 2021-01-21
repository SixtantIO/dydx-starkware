(ns the-system.blink.exchanges.dydx.pedersen
  "A Starkware Pedersen hash, as implemented in dydxprotocol/dydx-v3-python[1].

  [1] https://github.com/dydxprotocol/dydx-v3-python/blob/35bc6800d44d9f2d096e0f036601269b795aebec/dydx3/starkex/starkex_resources/signature.py#L52"
  (:require [clojure.java.io :as io]
            [taoensso.tufte :refer [p] :as tufte])
  (:import (org.bouncycastle.math.ec ECCurve$Fp ECPoint)))


(set! *warn-on-reflection* true)


;;; EC Point arithmetic


;; I'm using the ECPoint objects here instead of representing affine coordinates
;; in vectors of [x, y] for the considerable performance gain from Jacobain EC
;; addition.


(defn >point
  "Create an elliptic curve point on the finite field `p`."
  [p x y]
  (let [x (biginteger x)
        y (biginteger y)]
    (.createPoint (ECCurve$Fp. (biginteger p) x y) x y)))


(defn >affine
  "Convert a wrapped elliptic curve point to a vector of [x, y] BigInteger
  affine coordinates."
  [^ECPoint p]
  (let [p (tufte/p :normalize (.normalize p))]
    [(-> p .getAffineXCoord .toBigInteger)
     (-> p .getAffineYCoord .toBigInteger)]))


(defn ec-add
  "Elliptic curve addition."
  [^ECPoint pa ^ECPoint pb]
  (tufte/p :add (.add pa pb)))


;;; Pedersen hash algorithm


(defn- update-point [point ^BigInteger x constant-points-subset]
  (let [[point x]
        (reduce
          (fn [[point ^BigInteger x] pt]
            (if-not (zero? (.and x BigInteger/ONE))
              [(ec-add point pt) (.shiftRight x 1)]
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
      (>affine
        (reduce
          (fn [point [idx x]]
            (assert (<= 0 x field-prime))
            (let [slice (constant-points-slice constant-points idx bitlen)]
              (p :update-point (update-point point x slice))))
          shift-point
          [[0 (biginteger a)]
           [1 (biginteger b)]])))))


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
        p (-> raw :FIELD_PRIME biginteger)
        parse-points (fn [points] (mapv (fn [[x y]] (>point p x y)) points))]
    (-> raw
        (assoc :FIELD_PRIME p)
        (update :CONSTANT_POINTS parse-points))))


(def ^{:tag BigInteger :arglists '([a b])} pedersen-hash
  "Pedersen hash of integers `a` and `b`, using the field and constant points as
  used in dydx-v3-python (see ns doc)."
  (pedersen-hashf
    (:FIELD_PRIME default-pedersen-params)
    (:CONSTANT_POINTS default-pedersen-params)))


(comment
  ;;; Benchmark

  (assert ; does it still work
    (= (pedersen-hash
         0x3d937c035c878245caf64531a5756109c53068da139362728feb561405371cb
         0x208a0a10250e382e1e4bbe2880906c2791bf6275695e02fbbc6aeff9cd8b31a)
       0x30e480bed5fe53fa909cc0f8c4d99b8f9f2c016be4c41e13a4848797979c662))

  (let [[_ pstats]
        (tufte/profiled {}
          (dotimes [_ 10000]
            (tufte/p :hash
              (pedersen-hash
                0x3d937c035c878245caf64531a5756109c53068da139362728feb561405371cb
                0x208a0a10250e382e1e4bbe2880906c2791bf6275695e02fbbc6aeff9cd8b31a))))]
    (println (tufte/format-pstats pstats)))

  ; pId                   nCalls        Min      50% ≤      90% ≤      95% ≤      99% ≤        Max       Mean   MAD      Clock  Total
  ;
  ; :hash                 10,000     1.40ms     1.40ms     1.86ms     1.87ms     1.91ms   152.88ms     1.71ms  ±26%    17.13s    100%
  ; :update-point         20,000   687.84μs   698.25μs   926.42μs   930.57μs   939.48μs   151.86ms   847.94μs  ±26%    16.96s     99%
  ; :add               2,350,000     3.40μs     5.69μs     7.28μs     7.67μs     8.48μs   144.97ms     6.82μs  ±25%    16.02s     93%
  ; :tufte/compaction          2    74.24ms   151.04ms   151.04ms   151.04ms   151.04ms   151.04ms   112.64ms  ±34%   225.27ms     1%
  ; :normalize            10,000     7.96μs     9.75μs    12.23μs    13.40μs   281.92μs   326.80μs    14.55μs  ±62%   145.47ms     1%
  ;
  ; Accounted                                                                                                          50.48s    295%
  ; Clock
  )
