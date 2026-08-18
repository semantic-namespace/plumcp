;   Copyright (c) Shantanu Kumar. All rights reserved.
;   The use and distribution terms for this software are covered by the
;   Eclipse Public License 1.0 (http://opensource.org/licenses/eclipse-1.0.php)
;   which can be found in the file LICENSE at the root of this distribution.
;   By using this software in any fashion, you are agreeing to be bound by
;   the terms of this license.
;   You must not remove this notice, or any other, from this software.


(ns plumcp.core.server.oauth-as
  "Embedded OAuth 2.1 Authorization Server for plumcp MCP servers.

  plumcp already lets an MCP server act as a *resource server* — see
  `plumcp.core.server.http-ring-auth`, which validates JWTs minted by an
  external AS (Auth0, Keycloak, Cognito, …). This namespace covers the other
  half: being your own AS, so the MCP server is self-contained and needs no
  external IdP admin surface.

  Why you'd want that: enabling Dynamic Client Registration at the tenant
  level on a hosted IdP is often undesirable (it lets anonymous parties create
  applications in your tenant). With an embedded AS, DCR lives in your own
  process, the upstream IdP client-id stays fixed and server-side, and the
  IdP never learns that MCP clients exist.

  Shape of the flow:

      MCP client                  this AS                     upstream IdP
          │  POST /mcp (no token)     │                             │
          │────────────────────────►  │                             │
          │  401 + WWW-Authenticate   │                             │
          │◄────────────────────────  │                             │
          │  GET  /.well-known/*      │                             │
          │  POST /oauth/register     │  mint client_id (store)     │
          │  GET  /oauth/authorize    │  validate client +          │
          │                           │  EXACT redirect_uri match   │
          │  consent page             │  (confused-deputy guard)    │
          │◄────────────────────────  │                             │
          │  POST /oauth/authorize ─► │  302 ──────────────────────►│
          │                           │  GET /oauth/*/callback ◄────│
          │                           │  exchange code, verify      │
          │                           │  email → your user-id       │
          │  302 ?code=…&iss=…        │  mint one-time auth code    │
          │◄────────────────────────  │                             │
          │  POST /oauth/token ─────► │  PKCE verify, mint session  │
          │  POST /mcp + Bearer ────► │  session → your identity    │

  Minimal wiring:

      (require '[plumcp.core.server.oauth-as :as as]
               '[plumcp.core.server.oauth-as.store :as store]
               '[plumcp.core.server.oauth-as.google-java :as google])

      (def as-options
        (as/make-ring-as-options
          {:store        (store/atom-store)     ; use Redis etc. in prod
           :base-url     \"https://mcp.example.com\"
           :parse-json   u/json-parse
           :write-json   u/json-write
           :idp          (google/google-provider
                           {:client-id     google-client-id
                            :client-secret (fn [] (secret!))
                            :callback-url  \"https://mcp.example.com/oauth/google/callback\"
                            :parse-json    u/json-parse})
           :domain-policy    #(if (str/ends-with? % \"@example.com\") :allow :deny)
           :resolve-identity (fn [email]
                               (if-let [u (find-user-by-email email)]
                                 {:user-id (:id u)}
                                 :none))}))

      ;; then, in your Ring stack
      (-> mcp-handler
          (hrt/wrap-oauth (:wrap-oauth-options as-options))
          (hrt/wrap-route-match uris {:get-uri-routes (:routes as-options)}))

  See the sibling namespaces for the pieces: `.store`, `.primitive`, `.dcr`,
  `.authorize`, `.token`, `.idp`, `.callback`."
  (:require
   [plumcp.core.server.oauth-as.authorize :as as.authorize]
   [plumcp.core.server.oauth-as.callback :as as.callback]
   [plumcp.core.server.oauth-as.idp :as as.idp]
   [plumcp.core.server.oauth-as.dcr :as as.dcr]
   [plumcp.core.server.oauth-as.primitive :as as.prim]
   [plumcp.core.server.oauth-as.token :as as.token]
   [plumcp.core.util :as u]))


;; ---------------------------------------------------------------------------
;; Route URIs
;; ---------------------------------------------------------------------------


(def uri-oauth-register  "/oauth/register")
(def uri-oauth-authorize "/oauth/authorize")
(def uri-oauth-token     "/oauth/token")


(defn default-callback-uri
  "Conventional callback path for a named provider — `/oauth/google/callback`
   for `:google`. Callers registering the URI with their IdP must use the same
   value; pass `:callback-uri` to override."
  [provider-kw]
  (str "/oauth/" (name provider-kw) "/callback"))


;; ---------------------------------------------------------------------------
;; Body / param helpers
;; ---------------------------------------------------------------------------


(defn- json-body
  "Serialise a map body to a JSON string, leaving strings untouched so
   handlers can return either."
  [write-json response]
  (cond-> response
    (map? (:body response)) (update :body write-json)))


(defn- request-params
  "Merge query-params and form-params into one string-keyed map. Ring's
  wrap-params populates both; OAuth uses query on GET and form on POST, and
  handlers here don't care which."
  [request]
  (merge (:query-params request)
         (:form-params request)
         ;; some adapters only populate :params
         (when-let [p (:params request)]
           (into {} (map (fn [[k v]] [(name k) v])) p))))


;; ---------------------------------------------------------------------------
;; Handlers
;; ---------------------------------------------------------------------------


(defn handler-for:register
  "POST /oauth/register — RFC 7591 Dynamic Client Registration.

  `parse-json` reads the request body; `write-json` serialises the response."
  [{:keys [store parse-json write-json client-ttl-seconds]}]
  (fn register-handler [request]
    (let [body (try
                 (let [b (:body request)]
                   (cond
                     (map? b)    b
                     (string? b) (parse-json b)
                     (nil? b)    {}
                     :else       (parse-json (slurp b))))
                 (catch #?(:clj Exception :cljs :default) _ {}))]
      (->> (if client-ttl-seconds
             (as.dcr/store-registration! store body :ttl-seconds client-ttl-seconds)
             (as.dcr/store-registration! store body))
           (json-body write-json)))))


(defn handler-for:authorize
  "GET and POST /oauth/authorize on a single URI.

  plumcp's `wrap-route-match` dispatches `:get-uri-routes` on URI alone
  (method is not part of the lookup), so this handler self-dispatches on
  `:request-method` — GET renders consent, POST forwards to the IdP."
  [{:keys [store base-url idp auth-req-ttl provider-label] :as deps}]
  (fn authorize-handler [request]
    (let [params (request-params request)]
      (case (:request-method request)
        :post (as.authorize/authorize-post
               {:store store}
               (fn [ctx] (as.idp/authorize-url idp ctx))
               params)
        ;; default to the GET behaviour — a HEAD or an adapter that doesn't
        ;; set :request-method still gets the safe, non-mutating branch
        (as.authorize/authorize-get
         (cond-> {:store store :base-url base-url}
           auth-req-ttl   (assoc :auth-req-ttl auth-req-ttl)
           provider-label (assoc :provider-label provider-label))
         params)))))


(defn handler-for:token
  "POST /oauth/token — authorization_code and refresh_token grants."
  [{:keys [store write-json]}]
  (fn token-handler [request]
    (->> (as.token/token-post {:store store} (request-params request))
         (json-body write-json))))


(defn handler-for:callback
  "GET /oauth/{provider}/callback — the IdP redirect target."
  [{:keys [store base-url idp domain-policy resolve-identity]}]
  (fn callback-handler [request]
    (as.callback/google-callback-get
     (cond-> {:store store :base-url base-url :idp idp
              :resolve-identity resolve-identity}
       domain-policy (assoc :domain-policy domain-policy))
     (request-params request))))


(defn handler-for:authorization-server-metadata
  "GET /.well-known/oauth-authorization-server — RFC 8414."
  [{:keys [base-url write-json scopes-supported]}]
  (let [body (write-json (as.prim/authorization-server-metadata
                          (cond-> {:base-url base-url :dcr? true}
                            scopes-supported (assoc :scopes-supported scopes-supported))))]
    (fn as-metadata-handler [_]
      {:status  200
       :headers {"Content-Type" "application/json"}
       :body    body})))


(defn handler-for:protected-resource-metadata
  "GET /.well-known/oauth-protected-resource — RFC 9728. Advertises the base
  URL as the resource identifier so one token validates at every partitioned
  sibling path under it."
  [{:keys [base-url write-json scopes-supported]}]
  (let [body (write-json (as.prim/protected-resource-metadata
                          (cond-> {:base-url base-url}
                            scopes-supported (assoc :scopes-supported scopes-supported))))]
    (fn prm-handler [_]
      {:status  200
       :headers {"Content-Type" "application/json"}
       :body    body})))


;; ---------------------------------------------------------------------------
;; Assembly
;; ---------------------------------------------------------------------------


(defn make-ring-as-options
  "Build the route table and `wrap-oauth` options for an embedded AS.

  Required:
    :store             a `plumcp.core.server.oauth-as.store/Store`
    :base-url          canonical origin, e.g. \"https://mcp.example.com\"
    :idp               identity provider map (see `.idp`; `.google-java`
                         provides a Google factory)
    :resolve-identity  (fn [email]) → {:user-id …} | :none | :ambiguous
    :parse-json        (fn [String]) → Map
    :write-json        (fn [Map]) → String

  Optional:
    :domain-policy      (fn [email]) → :allow | :deny  (default: allow all —
                          most deployments want at least a domain allow-list)
    :provider           keyword naming the IdP for the callback path,
                          default :google
    :callback-uri       explicit callback path, overrides :provider
    :scopes-supported   vector of scope strings advertised in discovery
    :auth-req-ttl       seconds a pending authorization request lives
    :client-ttl-seconds seconds a DCR registration lives
    :provider-label     consent-button text, e.g. \"Continue with Google\"

  Returns:
    {:routes             {uri → ring-handler}   feed to wrap-route-match's
                                                :get-uri-routes
     :wrap-oauth-options {…}                    feed to wrap-oauth
     :token->session     (fn [bearer-token]) → session-map | nil}

  `:token->session` is also exposed directly because an MCP server usually
  wants the resolved identity (`:user-id`) bound into the request, not just a
  yes/no auth decision — `wrap-oauth`'s `:token->claims` contract returns the
  claims map, and here that map IS the session."
  [{:keys [store base-url idp resolve-identity parse-json write-json
           domain-policy provider callback-uri scopes-supported
           auth-req-ttl client-ttl-seconds provider-label]
    :or   {provider :google}
    :as   options}]
  (u/expected! store some? "store to be a Store implementation")
  (u/expected! base-url u/non-empty-string? "base-url to be a non-empty URL string")
  (u/expected! idp map? "idp to be an identity-provider map")
  (u/expected! resolve-identity fn? "resolve-identity to be a (fn [email])")
  (u/expected! parse-json fn? "parse-json to be a (fn [json-string])")
  (u/expected! write-json fn? "write-json to be a (fn [data])")
  (let [deps     (assoc options :provider provider)
        cb-uri   (or callback-uri (default-callback-uri provider))
        prm-uri  "/.well-known/oauth-protected-resource"
        as-uri   "/.well-known/oauth-authorization-server"]
    {:routes
     {uri-oauth-register  (handler-for:register deps)
      uri-oauth-authorize (handler-for:authorize deps)
      uri-oauth-token     (handler-for:token deps)
      cb-uri              (handler-for:callback deps)
      prm-uri             (handler-for:protected-resource-metadata deps)
      as-uri              (handler-for:authorization-server-metadata deps)}

     :wrap-oauth-options
     {:auth-enabled?     true
      :resource-metadata (str base-url prm-uri)
      ;; wrap-oauth calls this the "claims" map; for an embedded AS the
      ;; session map plays that role — it already holds the resolved identity.
      :token->claims     (fn [token]
                           (as.token/session-for
                            {:store store :base-url base-url}
                            (str "Bearer " token)))}

     :token->session
     (fn [token]
       (as.token/session-for {:store store :base-url base-url}
                             (str "Bearer " token)))}))
