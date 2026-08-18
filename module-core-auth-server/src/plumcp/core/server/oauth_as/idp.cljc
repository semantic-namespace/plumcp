;   Copyright (c) Shantanu Kumar. All rights reserved.
;   The use and distribution terms for this software are covered by the
;   Eclipse Public License 1.0 (http://opensource.org/licenses/eclipse-1.0.php)
;   which can be found in the file LICENSE at the root of this distribution.
;   By using this software in any fashion, you are agreeing to be bound by
;   the terms of this license.
;   You must not remove this notice, or any other, from this software.


(ns plumcp.core.server.oauth-as.idp
  "The identity-provider abstraction. An IdP is a plain map with two callable
  entries:

    :idp/authorize-url-for   (fn [{:keys [state resource scope]}]) → String
    :idp/exchange-code!      (fn [code]) → {:email ..., ...} | nil

  `authorize-url-for` builds the URL the AS 302s the user to. `exchange-code!`
  runs the server-side code-for-token exchange and returns a normalized
  identity map (at minimum, `:email` — everything else is caller-visible on
  the session). Returning nil signals \"could not obtain a verified
  identity\" — the AS turns that into an OAuth `access_denied` response.

  Kept as a map rather than a protocol so a test IdP is a literal:
    {:idp/authorize-url-for (fn [_] \"http://example.com/authorize\")
     :idp/exchange-code!    (fn [code] (when (= code \"good\")
                                         {:email \"user@example.com\"}))}"
  (:require
   [clojure.string :as str])
  #?(:clj (:import [java.util Base64])))


;; ---------------------------------------------------------------------------
;; id_token claim helpers — shared by any OIDC-shaped provider
;; ---------------------------------------------------------------------------


(defn- b64url-decode-string
  "Decode a base64url segment (no padding) to a UTF-8 string. Reverses the
   encoding OIDC id_token headers/payloads use."
  ^String [^String s]
  #?(:clj  (let [pad (case (long (mod (count s) 4)) 2 "==" 3 "=" "")]
             (String. (.decode (Base64/getUrlDecoder) (str s pad)) "UTF-8"))
     :cljs (let [pad (case (long (mod (count s) 4)) 2 "==" 3 "=" "")
                 b64 (-> (str s pad)
                         (str/replace "-" "+")
                         (str/replace "_" "/"))]
             (js/atob b64))))


(defn parse-id-token-payload
  "Parse the payload segment of a JWT-shaped id_token without verifying the
  signature. Safe here because the id_token was just returned by the IdP's
  token endpoint over TLS (OIDC Core §3.1.3.7 permits skipping signature
  verification in that case) — the checks that carry weight are iss / aud /
  exp / email_verified, done by `verified-oidc-email`.

  `parse-json` is the caller-supplied JSON reader (plumcp's json-* modules
  provide one). Returning it as an arg keeps this ns free of a JSON dep."
  [parse-json ^String id-token]
  (let [[_header payload _sig] (str/split (or id-token "") #"\." 3)]
    (when payload
      (some-> payload b64url-decode-string parse-json))))


(defn verified-oidc-email
  "Common id_token verifier. Returns the lower-cased verified email or nil.
  Refuses unverified emails outright — anyone can add an unverified address
  to an OIDC account they control, and treating it as identity is an
  account-takeover primitive.

  `claims` is a parsed claims map. Callers pass:
    :expected-issuers  #{String}   iss must be in this set
    :expected-audience String       aud must equal this (the IdP client-id)
    :now-seconds       long         current time (injectable for tests)"
  [claims {:keys [expected-issuers expected-audience now-seconds]}]
  (let [issuer   (or (get claims "iss") (:iss claims))
        audience (or (get claims "aud") (:aud claims))
        exp      (or (get claims "exp") (:exp claims))
        verified (or (get claims "email_verified") (:email_verified claims))
        email    (or (get claims "email") (:email claims))]
    (when (and claims
               (contains? expected-issuers issuer)
               (= expected-audience audience)
               (number? exp)
               (> exp now-seconds)
               (true? verified)
               (string? email)
               (seq email))
      (str/lower-case email))))


;; ---------------------------------------------------------------------------
;; Callback dispatcher
;; ---------------------------------------------------------------------------


(defn identity-for
  "Wrap an IdP's :idp/exchange-code! call so callers see a consistent shape:
     {:email \"...\"}    - success
     nil                 - refused (bad code, unverified, expired, etc.)

  A thin function on purpose — the value is that everything upstream of the
  AS core (authorize-post, google-callback-get) stays generic."
  [idp code]
  (when (seq code)
    ((:idp/exchange-code! idp) code)))


(defn authorize-url
  "Delegates to the IdP-supplied builder. Present so callers depend on this
   ns for both the outbound URL and the inbound identity, keeping the shape
   symmetric."
  [idp ctx]
  ((:idp/authorize-url-for idp) ctx))
