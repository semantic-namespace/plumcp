;   Copyright (c) Shantanu Kumar. All rights reserved.
;   The use and distribution terms for this software are covered by the
;   Eclipse Public License 1.0 (http://opensource.org/licenses/eclipse-1.0.php)
;   which can be found in the file LICENSE at the root of this distribution.
;   By using this software in any fashion, you are agreeing to be bound by
;   the terms of this license.
;   You must not remove this notice, or any other, from this software.


(ns plumcp.core.server.oauth-as.authorize
  "GET and POST /oauth/authorize — the boundary that stops this module from
  becoming an open redirector.

  Two rules make it work, and neither can be softened without losing the
  guarantee:

    1. Client + redirect_uri validation runs BEFORE anything can 302.
       An unknown client_id or an unregistered redirect_uri renders an error
       page rendered on OUR domain, never a Location header pointing at the
       attacker.

    2. Once the redirect_uri has been proven safe (exact match against the
       registered set), subsequent protocol errors DO redirect back to the
       client with an OAuth error param. This is where the consent screen
       lives too — see `authorize-consent-page` for why it exists at all
       (confused-deputy protection when proxying a static upstream IdP client
       on behalf of dynamically-registered MCP clients)."
  (:require
   [clojure.string :as str]
   [plumcp.core.server.oauth-as.dcr :as dcr]
   [plumcp.core.server.oauth-as.primitive :as prim]
   [plumcp.core.server.oauth-as.store :as store])
  #?(:clj (:import [java.net URLEncoder])))


(def ^:const default-auth-request-ttl-seconds
  "10 minutes — long enough for the user to complete the consent + upstream IdP
   dance, short enough that abandoned flows don't accumulate."
  600)


(defn auth-request-key
  [request-id]
  ["oauth-as" "authreq" request-id])


;; ---------------------------------------------------------------------------
;; URL / HTML helpers — cross-platform, deliberately tiny
;; ---------------------------------------------------------------------------


(defn- url-encode
  [^String s]
  #?(:clj  (URLEncoder/encode s "UTF-8")
     :cljs (js/encodeURIComponent s)))


(defn- html-escape
  "Sufficient escaping for embedding attacker-supplied strings (client_name
   from an unauthenticated DCR registration) into HTML attribute values and
   text nodes. Not a full XSS suite — the templates are minimal and don't
   embed script contexts."
  [s]
  (-> (str s)
      (str/replace "&"  "&amp;")
      (str/replace "<"  "&lt;")
      (str/replace ">"  "&gt;")
      (str/replace "\"" "&quot;")
      (str/replace "'"  "&#39;")))


(defn- querystring
  "URL-encode a params map, dropping nil values so callers can express
   optional params with nil. Never emits key= for a missing value."
  [params]
  (->> params
       (remove (fn [[_ v]] (nil? v)))
       (map (fn [[k v]] (str (name k) "=" (url-encode (str v)))))
       (str/join "&")))


(defn redirect-back
  "302 with the resolved client redirect_uri. Only ever called AFTER exact-
  match against the registered client's redirect_uris — otherwise it would be
  the very open redirector the callers assume this module doesn't build."
  [redirect-uri params]
  (let [sep (if (str/includes? redirect-uri "?") "&" "?")]
    {:status  302
     :headers {"Location"      (str redirect-uri sep (querystring params))
               "Cache-Control" "no-store"}
     :body    ""}))


;; ---------------------------------------------------------------------------
;; Error and consent pages
;; ---------------------------------------------------------------------------


(defn- page
  [title body-html]
  {:status  200
   :headers {"Content-Type"  "text/html; charset=utf-8"
             "Cache-Control" "no-store"}
   :body
   (str "<!DOCTYPE html><html><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
        "<title>" (html-escape title) "</title>"
        "<style>"
        "body{font-family:system-ui,sans-serif;display:flex;align-items:center;"
        "justify-content:center;min-height:100vh;margin:0;background:#f3f4f6;color:#111}"
        ".card{background:#fff;padding:32px;border-radius:12px;max-width:380px;"
        "box-shadow:0 2px 16px rgba(0,0,0,.10)}"
        "h2{margin:0 0 12px;font-size:1.25rem}"
        "p{margin:0 0 16px;font-size:.95rem;line-height:1.5;color:#374151}"
        ".client{font-weight:600;color:#111}"
        ".scopes{background:#f9fafb;border:1px solid #e5e7eb;border-radius:8px;"
        "padding:12px;margin:0 0 16px;font-size:.875rem;color:#374151}"
        "button{width:100%;padding:11px;background:#2563eb;color:#fff;border:none;"
        "border-radius:6px;cursor:pointer;font-size:1rem;font-weight:500}"
        "button:hover{background:#1d4ed8}"
        ".err{color:#b91c1c}"
        "</style></head><body><div class=\"card\">"
        body-html
        "</div></body></html>")})


(defn error-page
  "Rendered on OUR domain (not the client's redirect_uri) when we cannot
  safely redirect back — unknown client, unregistered redirect_uri, expired
  authorization request. Everything else uses `redirect-back` with an OAuth
  error param."
  [title message]
  (assoc (page title
               (str "<h2 class=\"err\">" (html-escape title) "</h2>"
                    "<p>" (html-escape message) "</p>"))
         :status 400))


(defn consent-page
  "The confused-deputy protection. Because we proxy a static upstream IdP
  client on behalf of dynamically-registered MCP clients, we MUST show the
  user which MCP client is asking BEFORE forwarding them to the IdP.
  Otherwise a client that registers with an attacker-controlled redirect_uri
  could harvest an authorization code off the user's existing IdP session
  with no visible prompt."
  [{:keys [client-name request-id continue-action provider-label]
    :or   {continue-action "/oauth/authorize"
           provider-label  "Continue"}}]
  (page "Authorize access"
        (str
         "<h2>Authorize access</h2>"
         "<p><span class=\"client\">" (html-escape client-name) "</span>"
         " is asking to access your account.</p>"
         "<div class=\"scopes\">You will now sign in with your identity provider. "
         "Choose the account whose data you want to expose to this application.</div>"
         "<form method=\"POST\" action=\"" (html-escape continue-action) "\">"
         "<input type=\"hidden\" name=\"request_id\" value=\"" (html-escape request-id) "\">"
         "<button type=\"submit\">" (html-escape provider-label) "</button>"
         "</form>")))


;; ---------------------------------------------------------------------------
;; GET /oauth/authorize
;; ---------------------------------------------------------------------------


(defn authorize-get
  "First half of the OAuth authorization flow.

  `deps` carries the runtime pieces the handler needs:
    :store            plumcp.core.server.oauth-as.store/Store
    :base-url         canonical server URL (for iss echo in error redirects)
    :auth-req-ttl     seconds, defaults to `default-auth-request-ttl-seconds`
    :provider-label   optional consent-button label (\"Continue with Google\")

  `params` is the request's query-param map with string keys/values (Ring
  form-decoded shape). Returns a Ring response map."
  [{:keys [store base-url auth-req-ttl provider-label]
    :or   {auth-req-ttl default-auth-request-ttl-seconds}
    :as   _deps}
   {:strs [client_id redirect_uri state code_challenge code_challenge_method
           resource scope]}]
  (let [client (dcr/lookup store client_id)]
    (cond
      (nil? client)
      (error-page "Unknown client"
                  "This application is not registered. Register via the OAuth registration endpoint first.")

      (not (dcr/client-may-use-redirect-uri? client redirect_uri))
      (error-page "Invalid redirect URI"
                  "The redirect_uri does not exactly match one registered by this application.")

      ;; From here the redirect_uri is trusted; subsequent protocol errors go
      ;; back to the client rather than rendering pages.
      (not= "S256" (or code_challenge_method "S256"))
      (redirect-back redirect_uri
                     {:error             "invalid_request"
                      :error_description "only S256 code_challenge_method is supported"
                      :state             state
                      :iss               base-url})

      (not (seq code_challenge))
      (redirect-back redirect_uri
                     {:error             "invalid_request"
                      :error_description "code_challenge is required (PKCE)"
                      :state             state
                      :iss               base-url})

      :else
      (let [request-id (prim/random-token)]
        (store/put! store (auth-request-key request-id)
                    {:client-id      client_id
                     :client-name    (:client-name client)
                     :redirect-uri   redirect_uri
                     :state          state
                     :code-challenge code_challenge
                     :resource       resource
                     :scope          scope}
                    auth-req-ttl)
        (consent-page {:client-name    (:client-name client)
                       :request-id     request-id
                       :provider-label provider-label})))))


;; ---------------------------------------------------------------------------
;; POST /oauth/authorize  — consent granted, forward to IdP
;; ---------------------------------------------------------------------------


(defn authorize-post
  "Consent granted → redirect to the upstream IdP. `provider->authorize-url`
  is a fn `(fn [{:keys [request-id resource scope]}]) → String` supplied by
  the caller — it is the only IdP-specific piece the AS core needs here.
  Everything security-relevant (the pending request record) stays server-side
  under request_id, so nothing round-trips through the browser."
  [{:keys [store] :as _deps} provider->authorize-url {:strs [request_id]}]
  (if-let [pending (when (seq request_id)
                     (store/get* store (auth-request-key request_id)))]
    {:status  302
     :headers {"Location"      (provider->authorize-url
                                {:request-id request_id
                                 :resource   (:resource pending)
                                 :scope      (:scope pending)})
               "Cache-Control" "no-store"}
     :body    ""}
    (error-page "Request expired"
                "This authorization request has expired. Please start again from your client.")))
