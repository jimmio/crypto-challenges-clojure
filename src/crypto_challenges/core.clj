(ns crypto-challenges.core
  (require [clojure.string :as st]
           [clojure.data.codec.base64 :as b64]))

(:import java.util.Base64)

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

(defn keysize-distances
  "Accepts binary data, and for range of keysizes, gets hamming distance between two keysize blocks in the data.  Returns a collection of maps sorted by :dist, least to greatest -- {:k keysize :dist hamming-distance}"
  [bin-data]
  (let [keysize (range 2 41)
        distances (for [k keysize]
                    (let [par (partition k bin-data)
                          block1 (first par)
                          block2 (second par)
                          dist (hamming-distance block1 block2)]
                      {:k k :dist (float (/ dist k))}))]
    (sort-by :dist distances)))

(defn single-char-xor-from-bytes
  "Accepts a block of bytes and returns lists of its ASCII-range single-byte XOR results"
  [map']
  (let [asc (range 0 256)
        length (count (:block-bytes map'))
        asc-ext (for [byte asc] (repeat length byte))
        xord (for [a asc-ext]
               (let [{:keys [block-index block-bytes] :as m'} map']
                 (assoc map' :block-bytes-xord (map bit-xor block-bytes a)
                             :char-xord-against (take 1 a))))]
    xord
    #_(for [x xord] (st/join (map char x)))))

(defn partition-and-xor
  [bytes kd-maps]
  "Takes binary data and a collection of keysize-distance maps... breaks up the data into smallest-distance-keysize blocks... transposes first byte of each block, second byte, and so on for length of keysize... then computes each transposed block as if it were a single-char xor cipher."
  (let [keysize (:k (first kd-maps))
        partitioned (vec (partition keysize bytes))
        
        transposed (for [n (range keysize)]
                     {:block-index n
                      :block-bytes (map (fn [block] (nth block n)) partitioned)})
        xord (for [map' transposed] (single-char-xor-from-bytes map'))
        scored (for [{:keys [block-bytes-xord] :as mapp} xord]
                 (assoc mapp :score (score-from-bytes block-bytes-xord)))]
    (println (take 1 scored))))

#_(def bytes-from-file (b64-txt-to-bytes set-1-challenge-6-data))
#_(def octets-from-file (b64-txt-to-bin set-1-challenge-6-data))
#_(def together (partition-and-xor bytes-from-file (keysize-distances octets-from-file)))
