;   Copyright (c) Shantanu Kumar. All rights reserved.
;   The use and distribution terms for this software are covered by the
;   Eclipse Public License 1.0 (http://opensource.org/licenses/eclipse-1.0.php)
;   which can be found in the file LICENSE at the root of this distribution.
;   By using this software in any fashion, you are agreeing to be bound by
;   the terms of this license.
;   You must not remove this notice, or any other, from this software.


(ns plumcp.core.server.oauth-as.dcr
  "RFC 7591 Dynamic Client Registration. Public clients only — we issue no
  client_secret, so there is no secret for an MCP client to leak. Registration
  is unauthenticated by design (that IS DCR), which is exactly why the
  redirect_uris are validated here and again by exact match at authorize
  time.

  Public per the MCP 2025-11-25 spec direction: DCR is retained for backward
  compatibility while CIMD (Client ID Metadata Documents) is the preferred
  mechanism going forward. This module implements DCR; CIMD is a separate
  namespace on the roadmap."
  (:require
   [clojure.string :as str]
   [plumcp.core.server.oauth-as.primitive :as prim]
   [plumcp.core.server.oauth-as.store :as store]))


(def ^:const default-client-ttl-seconds
  "One year. DCR clients don't have a natural expiry; this is a garbage-collection
   bound rather than a security control. Backends with their own retention story
   should override."
  (* 60 60 24 365))


(defn client-key
  "Store-key for a registered client. Namespaced so multiple sub-systems can
   share the same store without colliding."
  [client-id]
  ["oauth-as" "client" client-id])


(defn- loopback-uri?
  "http:// is only acceptable on the loopback interface, where there is no
   network attacker to intercept the redirect."
  [^String uri]
  (or (str/starts-with? uri "http://localhost")
      (str/starts-with? uri "http://localhost:")
      (str/starts-with? uri "http://127.0.0.1")
      (str/starts-with? uri "http://127.0.0.1:")
      (str/starts-with? uri "http://[::1]")))


(defn valid-redirect-uri?
  "https, or http on loopback. Fragments are refused: a fragment would make the
   exact-match check at authorize time meaningless."
  [uri]
  (and (string? uri)
       (seq uri)
       (not (str/includes? uri "#"))
       (or (str/starts-with? uri "https://")
           (loopback-uri? uri))))


(defn register
  "Registers a public client. `body` is the parsed RFC 7591 JSON payload —
  the caller is responsible for JSON decoding.

  Returns
    [:ok registration-map]      - store! it under (client-key client-id)
    [:error error-code message] - caller renders as 400 with an RFC 7591
                                  error body

  Delegated to the caller rather than done here: writing to the store, logging,
  HTTP response shape. The reasons are (a) the store type is a caller decision,
  (b) plumcp servers may want to log via different mechanisms, and (c) the
  Ring/other-transport response shape varies per host."
  [{:strs [client_name redirect_uris] :as _body}]
  (cond
    (or (not (coll? redirect_uris)) (empty? redirect_uris))
    [:error "invalid_redirect_uri"
     "redirect_uris is required and must be a non-empty array"]

    (not (every? valid-redirect-uri? redirect_uris))
    [:error "invalid_redirect_uri"
     "every redirect_uri must use https, or http on the loopback interface, and contain no fragment"]

    :else
    (let [client-id (prim/random-token)]
      [:ok {:client-id     client-id
            :client-name   (str (or client_name "Unnamed MCP client"))
            :redirect-uris (vec redirect_uris)}])))


(defn store-registration!
  "Convenience: run `register`, persist the successful record, and shape the
  response the way clients expect. Returns `{:status ..., :body ...}` — the
  caller wraps it in the Ring adapter's response type.

  A caller that needs to log the registration, apply admission control (e.g.
  block certain redirect_uri hosts), or persist to a different key namespace
  should compose `register` + `store/put!` themselves rather than use this."
  [store body & {:keys [ttl-seconds] :or {ttl-seconds default-client-ttl-seconds}}]
  (let [[outcome a b] (register body)]
    (case outcome
      :error {:status 400
              :body   {"error"             a
                       "error_description" b}}
      :ok    (let [record a]
               (store/put! store (client-key (:client-id record)) record ttl-seconds)
               {:status 201
                :body   {"client_id"                  (:client-id record)
                         "client_name"                (:client-name record)
                         "redirect_uris"              (:redirect-uris record)
                         "grant_types"                ["authorization_code" "refresh_token"]
                         "response_types"             ["code"]
                         "token_endpoint_auth_method" "none"}}))))


(defn lookup
  "Return a stored client record by id, or nil."
  [store client-id]
  (when (string? client-id)
    (store/get* store (client-key client-id))))


(defn client-may-use-redirect-uri?
  "The exact-match rule. This is the open-redirect boundary — a prefix or
   contains check here would let a client bounce through a hostile suffix."
  [client-record redirect-uri]
  (boolean (and client-record redirect-uri
                (some #(= redirect-uri %) (:redirect-uris client-record)))))
