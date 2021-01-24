(ns the-system.blink.exchanges.dydx.starkware-ecdsa
  "Starkware's variation on classic ECDSA, transcribed from reference impl[1].

  They use a variant on RFC 6979 to generate a deterministic 'k' constant,
  which I implemented separately[2] since it might be of general interest/use.

  [1] https://github.com/dydxprotocol/dydx-v3-python/blob/35bc6800d44d9f2d096e0f036601269b795aebec/dydx3/starkex/starkex_resources/signature.py
  [2] https://github.com/matthewdowney/rfc6979"
  (:require [the-system.blink.exchanges.dydx.starkware-constants :as const]
            [io.sixtant.rfc6979 :as rfc6979])
  (:import (org.bouncycastle.math.ec ECCurve$Fp)))


(set! *warn-on-reflection* true)


;; Starkware pads the message hash before signing, for consistency with the
;; elliptic.js library
(defn- ^BigInteger pad-msg-hash [^BigInteger msg-hash]
  (let [bit-length (.bitLength msg-hash)]
    (if (and (<= 1 (rem bit-length 8) 4) (>= bit-length 248))
      (.multiply msg-hash (biginteger 16))
      msg-hash)))


(defn rfc6979-k-value
  "Generate a deterministic `k` value for ECDSA."
  [^BigInteger msg-hash ^BigInteger private-key extra-entropy]
  (first
    (rfc6979/generate-ks
      {:curve-order const/ec-order
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
  (let [curve (ECCurve$Fp. const/ec-prime const/ec-alpha const/ec-beta)
        generator-point (.createPoint
                          curve
                          const/ec-generator-point-x
                          const/ec-generator-point-y)]
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


;; See invalid-signature? and sign -- this is the maximum value for both parts
;; of the signature, as well as for the message hash to sign.
(def ^:const max-value
  (.subtract
    (.pow BigInteger/TWO const/n-element-bits-ecsda)
    BigInteger/ONE))


;; These constraints are custom to their curve, I believe. I copied these
;; failure conditions directly from the reference implementation.
(defn- invalid-signature?
  [^BigInteger r ^BigInteger s ^BigInteger msg-hash ^BigInteger private-key]
  (or
    (not (<= 1 r max-value))
    (not (<= 1 s max-value))
    (zero?
      (.mod
        (.add (.multiply r private-key) msg-hash)
        const/ec-order))))


(defn sign*
  "Sign `msg-hash` with Starkware's ECDSA, returning a [r, s] signature tuple."
  [^BigInteger msg-hash ^BigInteger private-key]
  (assert (<= 1 msg-hash max-value))

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
              const/ec-order)]
      (if (invalid-signature? r s msg-hash private-key)
        (recur (inc (or extra-entropy 0)))
        (let [s (modular-multiplicative-inverse
                  BigInteger/ONE
                  s
                  const/ec-order)]
          [r s])))))


;; Instead of DER encoding, they just concat the hex strings
(defn encode-sig "Hex encode [r,s] signature" [[r s]] (format "%064x%064x" r s))


;; Benchmarked at 1.281ms compared to 19.348ms in the
;; reference implementation :)
(defn sign
  "Sign `msg-hash` with Starkware's ECDSA, returning a hex string."
  [^BigInteger msg-hash ^BigInteger private-key]
  (encode-sig (sign* msg-hash private-key)))


(defn ^BigInteger private->public
  "Return the public key for some private key on the Stark curve."
  [^BigInteger private-key]
  (assert (< 0 private-key const/ec-order))
  (ec-multiply private-key))
