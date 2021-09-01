(ns frontend
  "Helper script to inject credentials into the front end.

  Uses SixtantIO/secrets to read credentials from a specified :path, also
  takes the wallet :address, and spits out some JavaScript to paste into the
  developer console to insert the credentials into the dYdX frontend. See the
  comment block at the end of the ns for the shape of the credentials.

  Invoke like this (note strings are double quoted for reading as EDN):

    clj -X:frontend frontend/main \\
      :address '\"0x89ded350b2be3dc2014c71f1e49cdfad17ccaf7c\"' \\
      :path '[\"/home/ubuntu/the-system/conf/keys.edn\" :dydx :mainnet]'
  "
  (:require [io.sixtant.dydx-starkware.starkware-ecdsa :as stark]
            [io.sixtant.secrets :as secrets]
            [clojure.string :as string]
            [clojure.data.json :as json]))


(set! *warn-on-reflection* true)


(defn read-hex-int [^String s]
  (BigInteger. (if (string/starts-with? s "0x") (subs s 2) s) 16))


(defn stark-key-pairs
  "Build the `STARK_KEY_PAIRS` object that the front end uses with the
  'remember me' feature."
  [{:keys [stark address]}]
  (let [private-key (read-hex-int stark)
        point (stark/ec-multiply* private-key)
        x (-> point .getAffineXCoord .toBigInteger)
        y (-> point .getAffineYCoord .toBigInteger)
        hex #(format "%064x" %)]
    {address
     {:walletAddress address
      :publicKey (hex x)
      :publicKeyYCoordinate (hex y)
      :privateKey (hex private-key)
      :legacySigning true
      :walletType "METAMASK"}}))


(defn api-key-pairs
  "Build the `API_KEY_PAIRS` object that the front end uses with the
  'remember me' feature."
  [{:keys [address key secret passphrase]}]
  {address
   {:walletAddress address
    :secret secret
    :key key
    :passphrase passphrase
    :legacySigning true
    :walletType "METAMASK"}})


(defn generate-js
  "Given dYdX api credentials, generate JS to paste into the developer console
  while on the dYdX frontend[1], which injects credential data into the
  browser's local storage.

  [1] https://trade.dydx.exchange/portfolio/overview"
  [dydx-api-credentials]
  (let [stark (stark-key-pairs dydx-api-credentials)
        api (api-key-pairs dydx-api-credentials)]
    (format
      (str "localStorage.setItem('STARK_KEY_PAIRS', JSON.stringify(%s));\n"
           "localStorage.setItem('API_KEY_PAIRS', JSON.stringify(%s));")
      (json/write-str stark)
      (json/write-str api))))


(defn main [{:keys [address path] :as not-secret-data}]
  (let [[filepath & keypath] path
        _ (println "Decrypting keys at" filepath)
        secret-data (secrets/with-path filepath
                      (secrets/with-secrets
                        (apply secrets/secrets keypath)))
        _ (assert (some? secret-data) "read dydx api secrets successfully")
        dydx-api-credentials (merge secret-data not-secret-data)]
    (println "Paste into the developer console:\n")
    (println (generate-js dydx-api-credentials))))


(comment
  ;; The API credentials are shaped like this:
  (def creds
    {; dYdX web API key, secret, and passphrase
     :key        "foo"
     :secret     "bar"
     :passphrase "baz"

     ; Starkware private key
     :stark      "qux"})

  ;; So you can also call from the REPL like this:
  (let [address "0x89ded350b2be3dc2014c71f1e49cdfad17ccaf7c"]
    (println (generate-js (assoc creds :address address))))
  )
