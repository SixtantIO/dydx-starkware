(ns io.sixtant.dydx-starkware.time
  (:import (java.text SimpleDateFormat DateFormat)
           (java.util TimeZone Date)))


(set! *warn-on-reflection* true)


(def ^:private ^ThreadLocal thread-local-iso-date-format
  (proxy [ThreadLocal] []
    (initialValue []
      (doto (SimpleDateFormat. "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'")
        (.setTimeZone (TimeZone/getTimeZone "GMT"))))))


(defn pr-inst-iso
  "The ISO 8601 UTC timestamp for some inst.

  E.g. 2021-01-23T16:25:15.932Z"
  [i]
  (let [^DateFormat utc-format (.get thread-local-iso-date-format)
        ^Date d (if (instance? Date i) i (Date. ^long (inst-ms i)))]
    (.format utc-format d)))


(defn inst-s [i] (-> i inst-ms (/ 1000.0)))
