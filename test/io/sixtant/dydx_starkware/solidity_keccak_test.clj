(ns io.sixtant.dydx-starkware.solidity-keccak-test
  (:refer-clojure :exclude [int bytes])
  (:require [clojure.test :refer :all])
  (:require [io.sixtant.dydx-starkware.solidity-keccak :refer :all]))


;; See https://docs.soliditylang.org/en/develop/abi-spec.html#non-standard-packed-mode
(deftest encode-packed-test
  (testing "Example from https://docs.soliditylang.org/en/develop/abi-spec.html#non-standard-packed-mode"
    (let [data [(int16 -1)
                (bytes 1 (byte-array [0x42]))
                (uint16 0x03)
                (string "Hello, world!")]]
      (is (= (encode-packed data) "ffff42000348656c6c6f2c20776f726c6421"))))

  (testing "Examples tested against the python implementation"
    (testing "Address with leading zeros"
      (is (= (encode-packed [(address 0x0000006daea1723962647b7e189d311d757Fb793)])
             "0000006daea1723962647b7e189d311d757fb793")))))


(deftest solidity-keccak-test
  (testing "Examples from https://web3py.readthedocs.io/en/stable/web3.main.html#web3.Web3.solidityKeccak"
    (is (= (solidity-keccak (bool true))
           "0x5fe7f977e71dba2ea1a68e21057beebb9be2ac30c6410aa38d4f3fbe41dcffd2"))
    (is (= (apply solidity-keccak (map uint8 [97 98 99]))
           "0x4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"))
    (is (= (solidity-keccak (map uint8 [97 98 99]))
           "0x233002c671295529bcc50b76a2ef2b0de2dac2d93945fca745255de1a9e4017e"))
    (is (= (solidity-keccak (address 0x49EdDD3769c0712032808D86597B84ac5c2F5614))
           "0x2ff37b5607484cd4eecf6d13292e22bd6e5401eaffcc07e279583bc742c68882"))))
