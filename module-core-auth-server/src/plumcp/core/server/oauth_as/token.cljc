;   Copyright (c) Shantanu Kumar. All rights reserved.
;   The use and distribution terms for this software are covered by the
;   Eclipse Public License 1.0 (http://opensource.org/licenses/eclipse-1.0.php)
;   which can be found in the file LICENSE at the root of this distribution.
;   By using this software in any fashion, you are agreeing to be bound by
;   the terms of this license.
;   You must not remove this notice, or any other, from this software.


(ns plumcp.core.server.oauth-as.token
  "/oauth/token — the two grant types this AS supports (authorization_code and
  refresh_token) — and the session-token validation the MCP resource server
  calls on every request.

  Deliberately excludes: `client_credentials` (no automation flow yet),
  `password` (the ROPC grant should never be reintroduced — reason it was
  removed is worth remembering: it forces the AS to see user credentials,
  which defeats delegating identity to an IdP)."
  (:require
   [clojure.string :as str]
   [plumcp.core.server.oauth-as.primitive :as prim]
   [plumcp.core.server.oauth-as.store :as store]))


(def ^:const default-access-ttl-seconds  3600)
(def ^:const default-refresh-ttl-seconds (* 60 60 24 30))
(def ^:const default-auth-code-ttl-seconds 90)


(defn code-key    [code]  ["oauth-as" "code"    code])
(defn access-key  [tok]   ["oauth-as" "access"  tok])
(defn refresh-key [tok]   ["oauth-as" "refresh" tok])


;; ---------------------------------------------------------------------------
;; Response shape
;; ---------------------------------------------------------------------------


(defn- json-response
  [status body]
  {:status  status
   :headers {"Content-Type"  "application/json"
             "Cache-Control" "no-store"}
   :body    body})


(defn- error
  ([status err]              (error status err nil))
  ([status err description]
   (json-response status (cond-> {"error" err}
                           description (assoc "error_description" description)))))


;; ---------------------------------------------------------------------------
;; Mint tokens
;; ---------------------------------------------------------------------------


(defn issue-tokens!
  "Mint an access + refresh pair for a `session` map. `session` MUST carry
  `:client-id` (for refresh-token owner enforcement) and `:resource` (for
  audience binding at validation time); other keys are stored verbatim and
  returned by `session-for`.

  The returned map is the RFC 6749 token-endpoint success body."
  [store session
   & {:keys [access-ttl refresh-ttl scope]
      :or   {access-ttl  default-access-ttl-seconds
             refresh-ttl default-refresh-ttl-seconds
             scope       "mcp"}}]
  (let [access  (prim/random-token)
        refresh (prim/random-token)]
    (store/put! store (access-key access)  session access-ttl)
    (store/put! store (refresh-key refresh) session refresh-ttl)
    {"access_token"  access
     "token_type"    "Bearer"
     "expires_in"    access-ttl
     "refresh_token" refresh
     "scope"         scope}))


;; ---------------------------------------------------------------------------
;; Grant: authorization_code
;; ---------------------------------------------------------------------------


(defn- authorization-code-grant
  "PKCE-verifies, client-checks, redirect_uri-checks, then mints. Returns a
  Ring response map; the caller composes it into their transport's response
  type."
  [store {:strs [code code_verifier redirect_uri client_id]}]
  (let [stored (when (seq code) (store/consume! store (code-key code)))]
    (cond
      (nil? stored)
      (error 400 "invalid_grant" "authorization code is unknown, expired or already used")

      (not= client_id (:client-id stored))
      (error 400 "invalid_grant" "client_id does not match the authorization code")

      (not= redirect_uri (:redirect-uri stored))
      (error 400 "invalid_grant" "redirect_uri mismatch")

      (not (prim/pkce-verify? code_verifier (:code-challenge stored)))
      (error 400 "invalid_grant" "PKCE verification failed")

      :else
      ;; Carry the whole stored record minus the single-use protocol fields.
      ;; A fixed whitelist here silently dropped every caller-defined identity
      ;; key: a `resolve-identity` returning {:org "acme"} had its :org thrown
      ;; away between the callback and the session, so downstream authorization
      ;; that keyed on it never applied and the call went through unscoped. The
      ;; module cannot know which keys a consumer's identity model uses, so it
      ;; must not enumerate them — it removes what IT owns and keeps the rest.
      (json-response 200
                     (issue-tokens! store
                                    (dissoc stored :code-challenge :redirect-uri))))))


;; ---------------------------------------------------------------------------
;; Grant: refresh_token (with rotation)
;; ---------------------------------------------------------------------------


(defn- refresh-grant
  "Consume the presented refresh token and mint a new access/refresh pair.
  OAuth 2.1 requires rotation for public clients — a stolen refresh token is
  dead once the legitimate client has used it. `store/consume!` gives us that
  by construction: read-then-delete."
  [store {:strs [refresh_token client_id]}]
  (let [stored (when (seq refresh_token) (store/consume! store (refresh-key refresh_token)))]
    (cond
      (nil? stored)
      (error 400 "invalid_grant" "refresh token is unknown, expired or already used")

      (not= client_id (:client-id stored))
      (error 400 "invalid_grant" "client_id does not match the refresh token")

      :else
      (json-response 200 (issue-tokens! store stored)))))


;; ---------------------------------------------------------------------------
;; /oauth/token dispatcher
;; ---------------------------------------------------------------------------


(defn token-post
  "Ring handler entry point. Dispatches on `grant_type`. Anything not in
  #{authorization_code refresh_token} — including the historical ROPC
  password grant — is refused as `unsupported_grant_type`."
  [{:keys [store] :as _deps} {:strs [grant_type] :as params}]
  (case grant_type
    "authorization_code" (authorization-code-grant store params)
    "refresh_token"      (refresh-grant store params)
    (error 400 "unsupported_grant_type"
           "only authorization_code and refresh_token are supported")))


;; ---------------------------------------------------------------------------
;; Session validation (called from the resource-server middleware)
;; ---------------------------------------------------------------------------


(defn bearer-token
  "Extract the bearer value from an Authorization header. Case-insensitive on
  the scheme keyword — RFC 6750 §2.1 says the scheme is case-insensitive, and
  some clients ship 'bearer' lowercase."
  [authorization-header]
  (some-> authorization-header
          (str/replace-first #"^(?i)bearer\s+" "")
          str/trim
          not-empty))


(defn audience-ok?
  "RFC 8707 audience binding, loosened to accept partitioned siblings under
  the same base URL. `resource-in-token` is what the client asked for at
  authorize-time (or nil, for tokens minted before we tracked it); `base-url`
  is this resource server's canonical URL.

  Accepted:
    - nil                      (backward-compat with un-audience-bound tokens)
    - base-url                 (the client used the coarse resource id)
    - base-url + \"/mcp\"      (the client used the specific canonical URI)
    - base-url + \"/mcp/...\"  (a partitioned sibling — same resource server)

  NOT accepted:
    - base-url + \"/mcp-anything\" — the trailing slash on the /mcp/
      loosening stops look-alike-path smuggling."
  [resource-in-token base-url]
  (or (nil? resource-in-token)
      (= resource-in-token base-url)
      (= resource-in-token (str base-url "/mcp"))
      (str/starts-with? resource-in-token (str base-url "/mcp/"))))


(defn session-for
  "Look up the session behind a bearer token. Returns the session map (with
  the caller-chosen keys — typically `:user-id`, `:email`, `:client-id`) or
  nil.

  Callers use this in whatever middleware they mount at the protected
  endpoint. A nil return means either: no bearer, unknown token, or the
  token was minted for a resource other than this server."
  [{:keys [store base-url] :as _deps} authorization-header]
  (when-let [tok (bearer-token authorization-header)]
    (when-let [session (store/get* store (access-key tok))]
      (when (audience-ok? (:resource session) base-url)
        session))))
