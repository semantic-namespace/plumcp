;   Copyright (c) Shantanu Kumar. All rights reserved.
;   The use and distribution terms for this software are covered by the
;   Eclipse Public License 1.0 (http://opensource.org/licenses/eclipse-1.0.php)
;   which can be found in the file LICENSE at the root of this distribution.
;   By using this software in any fashion, you are agreeing to be bound by
;   the terms of this license.
;   You must not remove this notice, or any other, from this software.


(ns plumcp.core.server.oauth-as.google-java
  "JVM Google identity-provider factory. Uses the JDK 11+ built-in
  java.net.http.HttpClient — no clj-http dep — so this module stays as low-
  dependency as the rest of plumcp.

  The CLJS counterpart is intentionally not implemented yet: browser-side
  code exchange belongs to the client, not an AS running in the browser."
  (:require
   [clojure.string :as str]
   [plumcp.core.server.oauth-as.idp :as idp])
  (:import
   [java.net URI URLEncoder]
   [java.net.http HttpClient HttpRequest HttpRequest$BodyPublishers
                  HttpResponse$BodyHandlers]
   [java.time Duration]))


(def ^:private ^:const authorize-url "https://accounts.google.com/o/oauth2/v2/auth")
(def ^:private ^:const token-url "https://oauth2.googleapis.com/token")

(def ^:private google-issuers
  "Google id_tokens ship with either the bare host or the scheme+host form
   depending on where the token was minted. Both are legitimate."
  #{"accounts.google.com" "https://accounts.google.com"})


(defn- form-encode
  [params]
  (->> params
       (map (fn [[k v]] (str (name k) "=" (URLEncoder/encode (str v) "UTF-8"))))
       (str/join "&")))


(defn- http-client
  ^HttpClient []
  (-> (HttpClient/newBuilder)
      (.connectTimeout (Duration/ofSeconds 5))
      .build))


(defn- post-form
  "One-shot form POST returning the response body string, or nil on error.
  Errors are swallowed to nil rather than propagated because the caller
  (google-callback-get) needs to turn 'IdP said no' into an OAuth
  access_denied redirect anyway."
  [^String url form-params]
  (try
    (let [req (-> (HttpRequest/newBuilder)
                  (.uri (URI/create url))
                  (.timeout (Duration/ofSeconds 10))
                  (.header "Content-Type" "application/x-www-form-urlencoded")
                  (.POST (HttpRequest$BodyPublishers/ofString (form-encode form-params)))
                  .build)
          resp (.send (http-client) req (HttpResponse$BodyHandlers/ofString))]
      (when (<= 200 (.statusCode resp) 299)
        (.body resp)))
    (catch Exception _ nil)))


(defn google-provider
  "Return an IdP map ready to hand to authorize-post + google-callback-get.

  Options:
    :client-id       String                 Google OAuth client-id
    :client-secret   String | (fn [] String) - the secret, or a no-arg fn to
                                              fetch it lazily (rotatable /
                                              vaulted)
    :callback-url    String                 our /oauth/google/callback URL
    :parse-json      (fn [String]) → Map    JSON reader (plumcp json-* module)
    :extra-auth-params  Map                 optional query-params appended to
                                              the authorize URL (default:
                                              `{\"prompt\" \"select_account\"}`
                                              which matters — the resulting
                                              user-id depends on which
                                              account the user chooses)"
  [{:keys [client-id client-secret callback-url parse-json extra-auth-params]
    :or   {extra-auth-params {"prompt" "select_account"}}}]
  (let [secret-fn (if (fn? client-secret) client-secret (constantly client-secret))]
    {:idp/authorize-url-for
     (fn [{:keys [request-id]}]
       (let [base-params {"client_id"     client-id
                          "redirect_uri"  callback-url
                          "response_type" "code"
                          "scope"         "openid email"
                          "access_type"   "online"
                          "state"         request-id}
             all-params (merge base-params extra-auth-params)]
         (str authorize-url "?" (form-encode all-params))))

     :idp/exchange-code!
     (fn [code]
       (when-let [body (post-form
                        token-url
                        {"code"          code
                         "client_id"     client-id
                         "client_secret" (secret-fn)
                         "redirect_uri"  callback-url
                         "grant_type"    "authorization_code"})]
         (let [parsed   (parse-json body)
               id-token (or (get parsed "id_token") (:id_token parsed))
               claims   (idp/parse-id-token-payload parse-json id-token)
               email    (idp/verified-oidc-email
                         claims
                         {:expected-issuers  google-issuers
                          :expected-audience client-id
                          :now-seconds       (quot (System/currentTimeMillis) 1000)})]
           (when email
             {:email email}))))}))
