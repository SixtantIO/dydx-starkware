(defproject dydx-starkware "0.2.0"
  :description "Creation, hashing, and signing of orders with Starkware's L2 as used by dYdX."
  :license {:name "EPL-2.0 OR GPL-2.0-or-later WITH Classpath-exception-2.0"
            :url "https://www.eclipse.org/legal/epl-2.0/"}
  :dependencies [[org.clojure/clojure "1.10.3"]
                 [org.clojure/data.json "0.2.6"] ; serialize requests

                 [org.bouncycastle/bcprov-jdk15on "1.68"] ; EC point math
                 [pandect "1.0.1"] ; hashing
                 [io.sixtant/rfc6979 "0.1.0"] ; deterministic EC signatures

                 [com.taoensso/encore "3.19.0"] ; supplements the std lib
                 [com.taoensso/tufte "2.2.0"] ; benchmarking
                 [com.taoensso/truss "1.6.0"]] ; assertions
  :repl-options {:init-ns io.sixtant.dydx-starkware})
