;   Copyright (c) Shantanu Kumar. All rights reserved.
;   The use and distribution terms for this software are covered by the
;   Eclipse Public License 1.0 (http://opensource.org/licenses/eclipse-1.0.php)
;   which can be found in the file LICENSE at the root of this distribution.
;   By using this software in any fashion, you are agreeing to be bound by
;   the terms of this license.
;   You must not remove this notice, or any other, from this software.


(ns plumcp.core.server.oauth-as.internal
  "The handful of primitives this module needs, kept local so the module has NO
  dependency on module/core and is therefore a leaf git dep.

  Why that matters: every other plumcp module declares
  `module/core {:local/root \"../module-core\"}`. Current tools.deps resolves
  such a relative local-root inside a git checkout, but older resolvers do not
  — notably `tools.deps.alpha` as used by lein-tools-deps, which fails with
  \"Manifest type not detected ... #:local{:root \\\"../module-core\\\"}\".
  Consumers building through Leiningen therefore cannot take any plumcp module
  as a git dep. Two git deps from the same repo fail differently but just as
  hard (\"no known ancestor relationship\" for module/core).

  An authorization server is exactly the sort of thing people bolt onto an
  existing build they do not control, so being consumable everywhere matters
  more here than sharing five functions. The duplication below is deliberate
  and small; when this module is released to Clojars the maven coordinate
  removes the problem and these can move back to module/core if desired.

  Every function here mirrors its module/core counterpart in behaviour:
    expected!          plumcp.core.util/expected!
    non-empty-string?  plumcp.core.util/non-empty-string?
    make-code-verifier plumcp.core.util.http-auth/make-code-verifier
    with-code-challenge* plumcp.core.util.http-auth/with-code-challenge*"
  (:require
   ;; Required unconditionally: a reader-conditional that yields nothing leaves
   ;; an empty (:require) clause, which is not a valid ns form in CLJ.
   [clojure.string :as str])
  #?(:clj (:import
           [java.nio.charset StandardCharsets]
           [java.security MessageDigest SecureRandom]
           [java.util Base64 Base64$Encoder])))


;; ---------------------------------------------------------------------------
;; Assertions
;; ---------------------------------------------------------------------------


(defn throw!
  "Throw an ex-info with the given message and data."
  ([message]           (throw (ex-info message {})))
  ([message data]      (throw (ex-info message data))))


(defn expected!
  "Throw an 'Expected <message>' exception carrying {:found <found>}, unless the
   predicate holds. Returns `found` on success so it can be used inline."
  ([found message]
   (throw! (str "Expected " message) {:found found}))
  ([found pred message]
   (if (pred found)
     found
     (expected! found message))))


(defn non-empty-string?
  "True when the argument is a string with at least one character."
  [s]
  (and (string? s)
       (boolean (seq s))))


;; ---------------------------------------------------------------------------
;; PKCE primitives — RFC 7636
;; ---------------------------------------------------------------------------


(defn make-code-verifier
  "256 bits from the platform CSPRNG, base64url-encoded without padding.

  Used for PKCE code verifiers and, in this module, for every unguessable
  identifier it mints: DCR client-ids, authorization codes, session tokens and
  refresh tokens."
  []
  #?(:cljs (let [array   (js/Uint32Array. 28)
                 dec2hex (fn [d] (-> (str "0" (.toString d 16)) (.substr -2)))]
             (js/crypto.getRandomValues array)
             (-> (js/Array.from array dec2hex) (.join "")))
     :clj  (let [^SecureRandom secure-random (SecureRandom.)
                 ^bytes buf (byte-array 32)]
             (.nextBytes secure-random buf)
             (-> ^Base64$Encoder (Base64/getUrlEncoder)
                 (.withoutPadding)
                 (.encodeToString buf)))))


(defn with-code-challenge*
  "Compute base64url(SHA-256(code-verifier)) and call `(f digest-string)`,
  returning whatever `f` returns.

  In CLJS the digest is asynchronous (SubtleCrypto), so `f` is invoked from a
  promise and the return value is that promise — callers in the CLJS branch
  must treat the result as async. In CLJ the call is synchronous."
  [^String code-verifier f]
  #?(:cljs (let [encoder (js/TextEncoder.)
                 data    (.encode encoder code-verifier)
                 b64url  (fn [buf]
                           (-> (->> (js/Uint8Array. buf)
                                    (map #(js/String.fromCharCode %))
                                    (str/join ""))
                               (js/btoa)
                               (str/replace "+" "-")
                               (str/replace "/" "_")
                               (str/replace #"=+$" "")))]
             (-> (.digest js/crypto.subtle "SHA-256" data)
                 (.then (fn [hashed] (f (b64url hashed))))))
     :clj  (let [cv-bytes (.getBytes code-verifier (.toString StandardCharsets/UTF_8))
                 ^MessageDigest md (MessageDigest/getInstance "SHA-256")]
             (.update md cv-bytes)
             (-> ^Base64$Encoder (Base64/getUrlEncoder)
                 (.withoutPadding)
                 (.encodeToString (.digest md))
                 (f)))))
