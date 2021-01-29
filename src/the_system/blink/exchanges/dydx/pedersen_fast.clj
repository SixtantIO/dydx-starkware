(ns the-system.blink.exchanges.dydx.pedersen-fast
  (:require [the-system.blink.exchanges.dydx.pedersen :as pedersen]
            [the-system.blink.exchanges.dydx.starkware-constants :as const])
  (:import (org.bouncycastle.math.ec ECPoint)))

(def ^:const low-part-bits 248)
(def ^:const low-part-mask (.subtract (.pow BigInteger/TWO 248) BigInteger/ONE))
(def shift-point (first (:CONSTANT_POINTS pedersen/default-pedersen-params)))

(def p0 (get (:CONSTANT_POINTS pedersen/default-pedersen-params) 2))
(def p1 (get (:CONSTANT_POINTS pedersen/default-pedersen-params) (+ 2 low-part-bits)))
(def p2 (get (:CONSTANT_POINTS pedersen/default-pedersen-params) (+ 2 const/n-element-bits-hash)))
(def p3 (get (:CONSTANT_POINTS pedersen/default-pedersen-params) (+ 2 low-part-bits const/n-element-bits-hash)))

(defn hash-single [^BigInteger x ^ECPoint p1 ^ECPoint p2]
  (let [high-nibble (.shiftRight x low-part-bits)
        low-part (.and x low-part-mask)

        left (.multiply p1 low-part)
        right (.multiply p2 high-nibble)]
    (println low-part)
    (println high-nibble)
    (cond
      (.isInfinity right) left
      (.isInfinity left) right
      :else (pedersen/ec-add left right))))

(defn pedersen [a b]
  (-> (pedersen/ec-add
        (pedersen/ec-add
          shift-point
          (hash-single (biginteger a) p0 p1))
        (hash-single (biginteger b) p2 p3))
      pedersen/>affine
      first))

(comment

  (require 'criterium.core)
  (criterium.core/quick-bench
    (pedersen
      0x3d937c035c878245caf64531a5756109c53068da139362728feb561405371cb
      0x208a0a10250e382e1e4bbe2880906c2791bf6275695e02fbbc6aeff9cd8b31a))
  )
