(ns crypto-challenges.core-test
  (:require [clojure.test :refer :all]
            [crypto-challenges.core :refer :all]))

(deftest set-1-challenge-1
  (testing "Hex string converts to base64"
    (let [b64string "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
          result (encode-b64 (decode-hex "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"))]
      (is (= b64string result)))))

(deftest set-1-challenge-2
  (testing "Take two equal-length buffers and produce their XOR combination"
    (let [hexstring-a "1c0111001f010100061a024b53535009181c"
          hexstring-b "686974207468652062756c6c277320657965"
          result (fixed-xor hexstring-a hexstring-b)]
      (is (= result "746865206b696420646f6e277420706c6179")))))

(deftest set-1-challenge-5
  (testing "Implement repeating-key XOR"
    (let [lyrics "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
          result (repeating-key-xor lyrics "ICE")
          solution "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272\na282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"]
      (is (= result solution)))))

(deftest set-1-challenge-6
  (testing "Hamming distance"
    (let [s1 "this is a test"
          s2 "wokka wokka!!!"
          dis 37
          result (hamming-distance s1 s2)]
      (is (= result dis)))))

(deftest aes
  (testing "aes-ecb roundtrip -- random key -- 16-byte plaintext"
    (let [key (gen-aes-key)
          text "poopy bum sim su"
          encrypted (aes-ecb :encrypt key text)
          decrypted (aes-ecb :decrypt key encrypted)]
      (is (= text (clojure.string/join (map char decrypted))))))

  (testing "aes-ecb roundtrip -- random key -- 32-byte plaintext"
    (let [key (gen-aes-key)
          text "poopy bum sim super 88 8 uu ie e"
          encrypted (aes-ecb :encrypt key text)
          decrypted (aes-ecb :decrypt key encrypted)]
      (is (= text (clojure.string/join (map char decrypted))))))

  (testing "aes-cbc roundtrip -- random key -- random iv"
    (let [key (gen-aes-key)
          text "Do you have experience in project management or have worked as a project analyst within Information Technology (IT)? If so the Department of Innovation & Performance has the perfect position for you! Project Management Office Lead. Posted Now!"
          iv (gen-aes-key)
          encrypted (aes-cbc-encrypt key text iv)
          decrypted (aes-cbc-decrypt key encrypted)]
      (is (= text decrypted)))))
