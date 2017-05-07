(ns crypto-challenges.core
  (require [clojure.string :as st]
           [clojure.data.codec.base64 :as b64])
  (import (java.util.Base64)
          (javax.crypto Cipher KeyGenerator SecretKey)
          (javax.crypto.spec SecretKeySpec)
          (java.security SecureRandom)
          (org.apache.commons.codec.binary Base64)
          (javax.xml.bind.DatatypeConverter)))

(defn encode-hex
  "Accepts a collection of decimal byte values and encodes it to hexadecimal" 
  [bytes-map]
  (st/join (map (fn [b] (format "%x" b)) bytes-map)))

(defn decode-b64
  "Accepts base64 string and returns it decoded"
  [b64str]
  (b64/decode (.getBytes b64str)))

(defn b64-to-hex
  "Accepts base64 string and returns a hex string"
  [b64str]
  (let [decoded (.decode (java.util.Base64/getDecoder) b64str)]
    (encode-hex decoded)))

(defn decode-hex
  "Accepts hex string and returns a decoded string"
  [hexstr]
  (apply str (map
              (fn [[x y]] (char (Integer/parseInt (str x y) 16)))
              (partition 2 hexstr))))

(defn decode-hex-to-bytes
  "Accepts hex string and returns it decoded"
  [hexstr]
  (let [partitioned (partition 2 hexstr)]
    (map (fn [[x y]] (char (Integer/parseInt (str x y) 16))) partitioned)))

(defn get-bytes
  "Accepts a string of chars and returns a map of their respective byte values"
  [charstring]
  (map byte (.getBytes charstring)))

(defn encode-b64
  "Accepts a string and returns a base64 encoded string"
  [strarg]
  (.encodeToString (java.util.Base64/getEncoder) (.getBytes strarg)))

(defn fixed-xor
  "Accepts two hex strings and produces their XOR'd combination"
  [hex-a hex-b]
  (let [decoded-hex-a (decode-hex hex-a)
        decoded-hex-b (decode-hex hex-b)
        bytes-a (get-bytes decoded-hex-a)
        bytes-b (get-bytes decoded-hex-b)
        xord-map (map bit-xor bytes-a bytes-b)]
    (encode-hex xord-map)))

(defn single-char-xor
  "Accepts a hex string and returns lists of its ASCII-range single-byte XOR results"
  [hexstr]
  (let [asc (range 0 256)
        decoded-bytes (vec (map int (decode-hex hexstr)))
        length (.length decoded-bytes)
        asc-ext (for [byte asc] (repeat length byte))
        xord (for [a asc-ext]
               (map bit-xor decoded-bytes a))]
    (for [x xord] (st/join (map char x)))))

(defn sum-reduce
  "Reduce a collection by adding its items"
  [coll]
  (reduce (fn [p n] (+ p n)) 0 coll))

(defn score
  "Accepts hexstring and returns character frequency analysis scores for single-char-xor"
  [hexstr]
  (let [scorecard {"e" 100 "t" 96 "a" 92 "o" 88 "i" 84 "n" 80
                   "s" 76  "h" 72 "r" 68 "d" 64 "l" 60 "u" 56
                   "c" 52  "m" 48 "f" 44 "g" 40 "y" 36 "p" 32
                   "w" 28  "b" 24 "v" 20 "k" 16 "x" 12 "j" 8
                   "q" 4   "z" 2

                   "E" 98 "T" 94 "A" 90 "O" 86 "I" 82 "N" 78
                   "S" 74 "H" 70 "R" 66 "D" 62 "L" 58 "U" 54
                   "C" 50 "M" 46 "F" 42 "G" 38 "Y" 34 "P" 30
                   "W" 26 "B" 22 "V" 18 "K" 14 "X" 10 "J" 6
                   "Q" 2  "Z" 1 }

        strlist (single-char-xor hexstr)
        
        selections (map (fn [onestr]
                          (let [charkeys (keys scorecard)]
                            (for [k charkeys]
                              (re-seq (re-pattern k) onestr))))
                        strlist)
        
        nil-filtered (map (fn [l] (filter (fn [i] (not= nil i)) l)) selections)
        
        scores (map
                (fn [l] (for [i l] (for [z i] (scorecard z))))
                nil-filtered)

        scores-reduced (map (fn [l]
                              (for [thing l]
                                (sum-reduce thing)))
                            scores)
        reduced-again (for [thing scores-reduced]
                        (reduce (fn [p n] (+ p n)) 0 thing))]

    (sort-by last (map vector strlist reduced-again))))

(defn score-from-bytes
  "Accepts collection of decimal byte values and returns character frequency analysis scores."
  [byte-coll]
  (let [scorecard {"e" 0.12702 "t" 0.09056 "a" 0.08167 "o" 0.07507 "i" 0.06966 "n" 0.06749
                   "s" 0.06327  "h" 0.06094 "r" 0.05987 "d" 0.04253 "l" 0.04025 "u" 0.02758
                   "c" 0.02782  "m" 0.02406 "f" 0.02228 "g" 0.02015 "y" 0.01974 "p" 0.01929
                   "w" 0.02360  "b" 0.01492 "v" 0.00978 "k" 0.00772 "x" 0.00150 "j" 0.00153
                   "q" 0.00095   "z" 0.00074

                   "E" 0.12702 "T" 0.09056 "A" 0.08167 "O" 0.07507 "I" 0.06966 "N" 0.06749
                   "S" 0.06327 "H" 0.06094 "R" 0.05987 "D" 0.04253 "L" 0.04025 "U" 0.02758
                   "C" 0.02782 "M" 0.02406 "F" 0.02228 "G" 0.02015 "Y" 0.01974 "P" 0.01929
                   "W" 0.02360 "B" 0.01492 "V" 0.00978 "K" 0.00772 "X" 0.00150 "J" 0.00153
                   "Q" 0.00095  "Z" 0.00074 }

        bytes-turned-ascii (st/join (map char byte-coll))
        
        selections (let [charkeys (keys scorecard)]
                     (for [k charkeys]
                       (re-seq (re-pattern k) bytes-turned-ascii)))
        
        nil-filtered (filter #(not (nil? %)) selections)
        
        scores (for [seq nil-filtered]
                 (map #(scorecard %) seq))

        score (sum-reduce (for [seq scores] (sum-reduce seq)))]

    score))

(def set-1-challenge-4-data
  (clojure.java.io/file "resources/4.txt"))

(defn slurp-from-file-split
  [data]
  (st/split (slurp data) #"\n"))

(defn slurp-and-score
  "Accepts a text file of hex strings and returns/decrypts the one that has been XOR'd against a single character"
  [data]
  (let [slurped (slurp-from-file-split data)]
    (last (sort-by last (map score slurped)))))




;;;; BREAK REPEATING-KEY XOR ;;;;
(def set-1-challenge-6-data
  (clojure.java.io/file "resources/6.txt"))

(defn make-bin
  "Accepts a collection of decimal byte values (get-bytes provides this) and returns their equivalents in binary octets"
  [bytecoll]
  (->> bytecoll (map #(Integer/toBinaryString %))
                (map #(when (< (count %) 8)
                        (str (apply str (repeat (- 8 (count %)) "0")) %)))))
 
(defn hamming-distance
  "Accepts two collections of binary octet strings and gives the hamming distance between their respective bits"
  [c1 c2]
  (let [xord (map (fn [a b] (map (fn [c d] (bit-xor (int c) (int d))) a b)) c1 c2)
        total (let [r (map (fn [coll]
                             (let [filtered (filter (fn [i] (= 1 i)) coll)
                                   reduced (sum-reduce filtered)]
                               reduced))
                           xord)]
                (sum-reduce r))]
    total))

(defn b64-txt-to-bin
  [b64-data]
  "Accepts a txt file of base-64-encoded data and returns its translation into binary."
  (->> b64-data
       (slurp-from-file-split)
       (st/join)
       (decode-b64)
       (map byte)
       (make-bin)))

(defn b64-txt-to-bytes
  [b64-data]
  "Accepts a txt file of base-64-encoded data and returns its translation into binary."
  (->> b64-data
       (slurp-from-file-split)
       (st/join)
       (decode-b64)
       (map byte)))

(defn average-distances
  [partitioned-data num-blocks-to-compare]
  (let [distances (for [n (range num-blocks-to-compare)]
                    (let [b1 (nth partitioned-data n)
                          b2 (nth partitioned-data (+ 1 n))]
                      (hamming-distance b1 b2)))]
    (float (/ (sum-reduce distances) num-blocks-to-compare))))
  

(defn keysize-distances
  "Accepts binary data, and for range of keysizes, gets hamming distance between two keysize blocks in the data.  Returns a collection of maps sorted by :dist, least to greatest -- {:k keysize :dist hamming-distance}"
  [bin-data]
  (let [keysize (range 2 41)
        distances (for [k keysize]
                    (let [par (partition k bin-data)
                          avgdist (average-distances par 8)]
                      {:k k :dist (float (/ avgdist k))}))]
    (sort-by :dist distances)))

(defn single-char-xor-from-bytes
  [byte-block]
  
  "Accepts a block of bytes and returns lists of its ASCII-range single-byte XOR results"
  
  (let [asc (range 0 256)
        length (count byte-block)
        asc-ext (for [byte asc] (repeat length byte))]
    (for [a asc-ext]
      (let [xor-result (map bit-xor byte-block a)
            char (take 1 a)
            score (score-from-bytes xor-result)]
        {:xor-result xor-result
         :char char
         :score score}))))

(defn partition-transpose-score
  [kd-maps bytes]
  
  "Takes binary data and a collection of keysize-distance maps... breaks up the data into smallest-distance-keysize blocks... transposes first byte of each block, second byte, and so on for length of keysize... returns a map of block-index, block-bytes, block-bytes-xord.  Sometimes the SECOND item in kd-maps contains the correct keysize."
  
  (let [keysize (:k (second kd-maps))
        
        partitioned (vec (partition keysize bytes))

        transposed-scored (for [n (range keysize)]
                            (let [block-bytes (map (fn [block] (nth block n)) partitioned)
                                  xord-char-score (single-char-xor-from-bytes block-bytes)]
                              {:block-index n
                               :block-bytes block-bytes
                               :block-bytes-xord (vec xord-char-score)}))]

    transposed-scored))

(defn sort-and-keep-highest-scoring-block
  [transposed-scored-maps]
  (for [{:keys [block-bytes-xord] :as m} transposed-scored-maps]
    (let [highest-scoring-block (->> block-bytes-xord
                                     (sort-by :score)
                                     (last))]
      (assoc m :block-bytes-xord highest-scoring-block))))

(defn get-key
  [maps-with-highest-scoring-blocks]

  (let [k (for [{:keys [block-bytes-xord]} maps-with-highest-scoring-blocks]
            (:char block-bytes-xord))]
   (flatten k)))

(def keysize-distance-maps (->> set-1-challenge-6-data
                                (b64-txt-to-bin)
                                (keysize-distances)))

(def bytez (b64-txt-to-bytes set-1-challenge-6-data))

(defn xor-key-over-bytes
  [key byte-coll]
  (let [blen (count byte-coll)
        klen (count key)
        rem (mod blen klen)
        krem (take rem key)
        kext (repeat (/ blen klen) key)
        kext' (flatten (conj krem kext))
        xord (map bit-xor bytez kext')
        back-to-ascii (map char xord)]
    (st/join back-to-ascii)))

(def get-dat-key (->> bytez
                      (partition-transpose-score keysize-distance-maps)
                      (sort-and-keep-highest-scoring-block)
                      (get-key)))

(def break-it (xor-key-over-bytes get-dat-key bytez))


;;;; IMPLEMENT REPEATING-KEY XOR ;;;;
(defn repeating-key-xor
  "Accepts a string and a key, then XOR's the key over the string"
  [s k]
  (let [slength (.length s)
        klength (.length k)
        rem (mod slength klength)
        keyrem (subs k 0 rem)
        kext (str (apply str (repeat (/ slength klength) k)) keyrem)
        sbytes (get-bytes s)
        kbytes (get-bytes kext)]
    (encode-hex (map bit-xor sbytes kbytes))))


;;;; DECRYPT AES IN ECB MODE ;;;;
(def set-1-challenge-7-data
  (clojure.java.io/file "resources/7.txt"))

(defn decrypt [k ciph-text]
  "Takes key as string, cipher text as bytes, and decrypts"
  (let [c (Cipher/getInstance "AES/ECB/NoPadding")
        k-spec (SecretKeySpec. (.getBytes k "UTF-8") "AES")
        init (.init c Cipher/DECRYPT_MODE k-spec)]
    (String. (.doFinal c ciph-text))))

(defn debase64 [s]
  (Base64/decodeBase64 (.getBytes s "UTF-8")))

(def set-1-challenge-7-solution
  (->> set-1-challenge-7-data
       (slurp)
       (debase64)
       (decrypt "YELLOW SUBMARINE")))


;;;; DETECT AES IN ECB MODE ;;;;
(def set-1-challenge-8-data
  (clojure.java.io/file "resources/8.txt"))

(defn hex-str-to-bytes
    [hex-str]
    (javax.xml.bind.DatatypeConverter/parseHexBinary hex-str))

(defn partition-hex-by-16
  [hex-coll]
  (->> hex-coll (partition 2) (map #(apply str %)) (partition 16)))

(defn detect-aes-ecb ;; NEED TO DETECT PAIRS!!!
  [col-hex-strs]                                               ;; "aabbccdd" "eeff0011"
  (let [partitioned (map partition-hex-by-16 col-hex-strs)     ;; ["aa" "bb" "cc" "dd"...] ["ee" "ff" "00" "11"...]
        columns-by-pos (map #(apply map vector %) partitioned) ;; ["aa" "ee"...] ["bb" "ff"...] ["cc" "00"...] ["dd" "11"...]
        freqs (map #(map frequencies %) columns-by-pos)        ;; get frequency of byte by column
        count-per-pos (map (fn [column] (map #(map val %) column)) freqs)
        most-frequent #(reduce (fn [accum itm]
                                 (if (> itm accum) itm accum)) %)
        most-frequent-per-col (map #(map most-frequent %) count-per-pos)
        reduced (map
                 (fn [m]
                   (map #(reduce + (second %)) m)
                   (first m))
                 most-frequent-per-col)
        indexed (map-indexed hash-map reduced)
        sorted (sort-by #(second (first %)) indexed)]
    (first (reverse sorted)))) ;; where K is the line number, and where V is the highest number of repetitions
                               ;; found for any column, returns {K V}


;;;; IMPLEMENT PKCS#7 PADDING ;;;;
(defn pkcs7-pad
  [s block-len]
  (let [p (- block-len (count s))]
    (flatten (cons (map int s) (repeat p (byte p))))))
