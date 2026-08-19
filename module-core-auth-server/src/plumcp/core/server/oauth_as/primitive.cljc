;   Copyright (c) Shantanu Kumar. All rights reserved.
;   The use and distribution terms for this software are covered by the
;   Eclipse Public License 1.0 (http://opensource.org/licenses/eclipse-1.0.php)
;   which can be found in the file LICENSE at the root of this distribution.
;   By using this software in any fashion, you are agreeing to be bound by
;   the terms of this license.
;   You must not remove this notice, or any other, from this software.


(ns plumcp.core.server.oauth-as.primitive
  "Cross-platform primitives with no ambiguity: cryptographically-strong random
  tokens, PKCE S256 verification, and RFC 8414 / RFC 9728 discovery-document
  builders. Deliberately kept small — nothing here depends on the store, the
  IdP, or the caller's identity model, so this file changes rarely and can be
  reviewed as-is."
  (:require
   [plumcp.core.server.oauth-as.internal :as internal])
  #?(:clj (:import
           [java.security MessageDigest]
           [java.util Base64])))


;; ---------------------------------------------------------------------------
;; Random tokens
;; ---------------------------------------------------------------------------


(defn random-token
  "URL-safe, unpadded, ~256 bits of cryptographically-strong entropy. Used
  interchangeably for DCR client-ids, authorization codes, session tokens and
  refresh tokens — every one of them needs to be unguessable, and none of
  them carry structured meaning at the client."
  []
  (internal/make-code-verifier))


;; ---------------------------------------------------------------------------
;; PKCE — RFC 7636 (S256 only)
;; ---------------------------------------------------------------------------


(defn- constant-time-eq?
  "Timing-safe string comparison — the equality check must not leak whether an
   early or late character differed. Both operands base64url so ASCII-only."
  [^String a ^String b]
  (and (some? a) (some? b)
       #?(:clj  (MessageDigest/isEqual (.getBytes a "US-ASCII")
                                       (.getBytes b "US-ASCII"))
          :cljs (and (= (count a) (count b))
                     (loop [i 0 acc 0]
                       (if (>= i (count a))
                         (zero? acc)
                         (recur (inc i)
                                (bit-or acc (bit-xor (.charCodeAt a i)
                                                     (.charCodeAt b i))))))))))


(defn code-challenge-for
  "Compute the S256 code-challenge for a verifier. The AS itself never needs
  this — clients generate the pair — but it is the natural inverse to expose
  for tests, for a plumcp-based MCP client, and for anyone building tooling
  against the endpoint."
  [code-verifier]
  (internal/with-code-challenge* code-verifier identity))


(defn pkce-verify?
  "True when base64url(SHA-256(code-verifier)) equals code-challenge. Runs the
  comparison in constant time. In CLJS the check is async (SubtleCrypto), so
  `f` receives the boolean; in CLJ the return value is the boolean directly.

  S256 is the only method OAuth 2.1 requires — `plain` is refused upstream.

  Guards nil/blank operands BEFORE delegating to the digest helper: a token
  request that omits `code_verifier` is an ordinary protocol error that must
  surface as `invalid_grant`, not a 500 from a NullPointerException inside
  the hash. (`plumcp.core.util.http-auth/with-code-challenge*` calls
  `.getBytes` on its argument unguarded.)"
  ([code-verifier code-challenge]
   (if (or (not (string? code-verifier)) (empty? code-verifier)
           (not (string? code-challenge)) (empty? code-challenge))
     false
     (internal/with-code-challenge* code-verifier
       (fn [computed] (constant-time-eq? computed code-challenge)))))
  ([code-verifier code-challenge f]
   ;; CLJS-friendly explicit-callback shape
   (if (or (not (string? code-verifier)) (empty? code-verifier)
           (not (string? code-challenge)) (empty? code-challenge))
     (f false)
     ;; `with-code-challenge*` already takes a callback, so the result is
     ;; threaded straight into `f` — no async-bridge needed. In CLJS this is
     ;; the promise's then-handler; in CLJ it is a direct call.
     (internal/with-code-challenge* code-verifier
       (fn [computed] (f (constant-time-eq? computed code-challenge)))))))


;; ---------------------------------------------------------------------------
;; Discovery metadata (RFC 8414 + RFC 9728)
;; ---------------------------------------------------------------------------
;;
;; Both documents are static-ish JSON derived from a small set of inputs (base
;; URL, resource path). Kept as pure functions returning maps so the caller
;; assembles JSON via whichever plumcp json-* module is on the classpath.


(defn authorization-server-metadata
  "RFC 8414 payload. `base-url` is the MCP server origin; the endpoint paths
  are conventional and match what this module's handlers serve.

  `dcr?` toggles the `registration_endpoint` — advertise it only when the
  caller has actually wired the DCR handler. Silent omission is safer than
  advertising a 404."
  [{:keys [base-url dcr? scopes-supported]
    :or   {scopes-supported ["mcp"]
           dcr? true}}]
  (cond-> {"issuer"                                     base-url
           "authorization_endpoint"                     (str base-url "/oauth/authorize")
           "token_endpoint"                             (str base-url "/oauth/token")
           "response_types_supported"                   ["code"]
           "grant_types_supported"                      ["authorization_code" "refresh_token"]
           "code_challenge_methods_supported"           ["S256"]
           "token_endpoint_auth_methods_supported"      ["none"]
           "scopes_supported"                           scopes-supported
           "authorization_response_iss_parameter_supported" true}
    dcr? (assoc "registration_endpoint"                 (str base-url "/oauth/register"))))


(defn protected-resource-metadata
  "RFC 9728 payload. Advertises the base URL as `resource` (not the specific
  path) so a token issued once validates at every partitioned sibling
  (`/mcp`, `/mcp/atlas`, `/mcp/self`) — the audience-binding check accepts
  base or any `base/mcp/*`."
  [{:keys [base-url authorization-servers scopes-supported]
    :or   {scopes-supported []}}]
  {"resource"                  base-url
   "authorization_servers"     (or authorization-servers [base-url])
   "bearer_methods_supported"  ["header"]
   "scopes_supported"          scopes-supported
   "resource_documentation"    (str base-url "/mcp")})


(defn www-authenticate-header
  "RFC 9728 §5.1 challenge that triggers a compliant MCP client to begin
  discovery rather than simply erroring out. `scope` is optional but useful:
  the client uses it as the initial scope for the authorization request."
  [{:keys [base-url scope]}]
  (str "Bearer resource_metadata=\""
       base-url "/.well-known/oauth-protected-resource\""
       (when scope (str ", scope=\"" scope "\""))))
