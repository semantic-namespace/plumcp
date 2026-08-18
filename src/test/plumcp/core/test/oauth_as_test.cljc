;   Copyright (c) Shantanu Kumar. All rights reserved.
;   The use and distribution terms for this software are covered by the
;   Eclipse Public License 1.0 (http://opensource.org/licenses/eclipse-1.0.php)
;   which can be found in the file LICENSE at the root of this distribution.
;   By using this software in any fashion, you are agreeing to be bound by
;   the terms of this license.
;   You must not remove this notice, or any other, from this software.


(ns plumcp.core.test.oauth-as-test
  "Tests for the embedded Authorization Server.

  Registration is unauthenticated by design (that IS Dynamic Client
  Registration), so every guarantee the AS offers rests on what happens
  *after*: exact redirect_uri matching before anything can redirect, PKCE
  actually binding the exchange, one-time codes, refresh rotation, audience
  binding. Each is asserted with the NEGATIVE case first — a happy-path-only
  suite would pass against an open redirector."
  (:require
   [clojure.string :as str]
   #?(:clj  [clojure.test :refer [deftest is testing]]
      :cljs [cljs.test :refer-macros [deftest is testing]])
   [plumcp.core.server.oauth-as.authorize :as as.authorize]
   [plumcp.core.server.oauth-as.callback :as as.callback]
   [plumcp.core.server.oauth-as.dcr :as as.dcr]
   [plumcp.core.server.oauth-as.idp :as as.idp]
   [plumcp.core.server.oauth-as.primitive :as as.prim]
   [plumcp.core.server.oauth-as.store :as as.store]
   [plumcp.core.server.oauth-as.token :as as.token]))


(def base-url "https://mcp.example.com")


(defn- fresh-store [] (as.store/atom-store))


(defn- register!
  "Register a client, return its record."
  [store redirect-uris]
  (let [[outcome record] (as.dcr/register {"client_name"   "Test MCP Client"
                                           "redirect_uris" redirect-uris})]
    (assert (= :ok outcome) "fixture registration must succeed")
    (as.store/put! store (as.dcr/client-key (:client-id record)) record 3600)
    record))


(defn- location [response] (get-in response [:headers "Location"]))


(defn- query-param
  [url k]
  (some->> (str/split (or url "") #"[?&]")
           (map #(str/split % #"=" 2))
           (filter #(= k (first %)))
           first
           second))


;; ---------------------------------------------------------------------------
;; Store
;; ---------------------------------------------------------------------------


(deftest store-round-trips-and-deletes
  (let [s (fresh-store)]
    (testing "put! then get* returns the value"
      (as.store/put! s ["k"] {:a 1} 60)
      (is (= {:a 1} (as.store/get* s ["k"]))))
    (testing "delete! removes it"
      (as.store/delete! s ["k"])
      (is (nil? (as.store/get* s ["k"]))))
    (testing "consume! reads once then the entry is gone — this is what makes
              authorization codes and refresh tokens single-use"
      (as.store/put! s ["c"] {:v 2} 60)
      (is (= {:v 2} (as.store/consume! s ["c"])))
      (is (nil? (as.store/consume! s ["c"]))))
    (testing "an expired entry reads as absent even without eviction"
      (as.store/put! s ["e"] {:v 3} 0)
      (is (nil? (as.store/get* s ["e"]))))))


;; ---------------------------------------------------------------------------
;; PKCE
;; ---------------------------------------------------------------------------


#?(:clj
   (deftest pkce-verifies-only-the-matching-verifier
     (let [verifier  "a-known-code-verifier-value"
           challenge (as.prim/code-challenge-for verifier)]
       (testing "the matching verifier passes"
         (is (true? (as.prim/pkce-verify? verifier challenge))))
       (testing "a different verifier fails"
         (is (false? (as.prim/pkce-verify? "some-other-verifier" challenge))))
       (testing "the challenge is base64url with no padding — it goes in a URL"
         (is (re-matches #"[A-Za-z0-9_-]+" challenge)))
       (testing "nil or blank operands return false rather than throwing — a
                 token request omitting code_verifier must surface as
                 invalid_grant, not a 500"
         (is (false? (as.prim/pkce-verify? nil challenge)))
         (is (false? (as.prim/pkce-verify? verifier nil)))
         (is (false? (as.prim/pkce-verify? "" challenge)))
         (is (false? (as.prim/pkce-verify? verifier "")))))))


;; ---------------------------------------------------------------------------
;; Dynamic Client Registration
;; ---------------------------------------------------------------------------


(deftest dcr-refuses-unusable-redirect-uris
  (testing "plaintext http off-loopback is refused — no TLS to protect the code"
    (let [[outcome err] (as.dcr/register {"redirect_uris" ["http://evil.example.com/cb"]})]
      (is (= :error outcome))
      (is (= "invalid_redirect_uri" err))))

  (testing "a fragment is refused — it would make exact matching meaningless"
    (is (= :error (first (as.dcr/register {"redirect_uris" ["https://ok.example.com/cb#x"]})))))

  (testing "redirect_uris is mandatory and must be non-empty"
    (is (= :error (first (as.dcr/register {"client_name" "no uris"}))))
    (is (= :error (first (as.dcr/register {"redirect_uris" []})))))

  (testing "https and loopback http are both accepted"
    (is (= :ok (first (as.dcr/register
                       {"redirect_uris" ["https://claude.ai/api/mcp/auth_callback"
                                         "http://localhost:33418/callback"
                                         "http://127.0.0.1:8080/cb"]}))))))


(deftest dcr-issues-public-clients-only
  (let [store (fresh-store)
        resp  (as.dcr/store-registration! store {"client_name"   "X"
                                                 "redirect_uris" ["https://x.example.com/cb"]})]
    (is (= 201 (:status resp)))
    (testing "no client_secret is ever issued — nothing for a public client to leak"
      (is (nil? (get (:body resp) "client_secret")))
      (is (= "none" (get (:body resp) "token_endpoint_auth_method"))))
    (testing "client ids are unguessable, not sequential"
      (let [a (get-in (as.dcr/store-registration! store {"redirect_uris" ["https://a.example.com/cb"]}) [:body "client_id"])
            b (get-in (as.dcr/store-registration! store {"redirect_uris" ["https://b.example.com/cb"]}) [:body "client_id"])]
        (is (not= a b))
        (is (<= 40 (count a)))))))


(deftest dcr-redirect-uri-match-is-exact
  (let [store  (fresh-store)
        record (register! store ["https://good.example.com/cb"])]
    (testing "the registered value matches"
      (is (as.dcr/client-may-use-redirect-uri? record "https://good.example.com/cb")))
    (testing "a different host does not"
      (is (not (as.dcr/client-may-use-redirect-uri? record "https://attacker.example.com/steal"))))
    (testing "a path-extended variant does not — prefix matching would be a hole"
      (is (not (as.dcr/client-may-use-redirect-uri? record "https://good.example.com/cb/extra"))))
    (testing "an appended query does not"
      (is (not (as.dcr/client-may-use-redirect-uri?
                record "https://good.example.com/cb?next=https://evil.example.com"))))))


;; ---------------------------------------------------------------------------
;; /oauth/authorize — the open-redirect boundary
;; ---------------------------------------------------------------------------


(deftest authorize-never-redirects-for-an-unknown-client
  (let [store (fresh-store)
        resp  (as.authorize/authorize-get
               {:store store :base-url base-url}
               {"client_id"      "never-registered"
                "redirect_uri"   "https://attacker.example.com/steal"
                "code_challenge" "abc"})]
    (is (= 400 (:status resp)))
    (is (nil? (location resp)))
    (testing "the attacker URI does not even appear in the rendered page"
      (is (not (str/includes? (:body resp) "attacker.example.com"))))))


(deftest authorize-never-redirects-to-an-unregistered-uri
  (let [store  (fresh-store)
        record (register! store ["https://good.example.com/cb"])
        resp   (as.authorize/authorize-get
                {:store store :base-url base-url}
                {"client_id"      (:client-id record)
                 "redirect_uri"   "https://attacker.example.com/steal"
                 "code_challenge" "abc"})]
    (is (= 400 (:status resp)))
    (is (nil? (location resp)))))


(deftest authorize-requires-pkce-s256
  (let [store  (fresh-store)
        record (register! store ["https://good.example.com/cb"])
        call   (fn [params]
                 (as.authorize/authorize-get
                  {:store store :base-url base-url}
                  (merge {"client_id"    (:client-id record)
                          "redirect_uri" "https://good.example.com/cb"
                          "state"        "st"}
                         params)))]
    (testing "a missing code_challenge is rejected — redirected, since the
              redirect_uri is trusted by this point"
      (let [resp (call {})]
        (is (= 302 (:status resp)))
        (is (= "invalid_request" (query-param (location resp) "error")))
        (is (nil? (query-param (location resp) "code")))))

    (testing "downgrading to `plain` is refused"
      (let [resp (call {"code_challenge"        "abc"
                        "code_challenge_method" "plain"})]
        (is (= 302 (:status resp)))
        (is (= "invalid_request" (query-param (location resp) "error")))))

    (testing "S256 with a challenge renders the consent page"
      (let [resp (call {"code_challenge"        "abc"
                        "code_challenge_method" "S256"})]
        (is (= 200 (:status resp)))
        (is (nil? (location resp)) "must not bounce to the IdP before consent")
        (is (str/includes? (:body resp) "Test MCP Client"))))))


(deftest authorize-escapes-the-attacker-supplied-client-name
  (testing "client_name comes from unauthenticated DCR and is rendered into HTML"
    (let [store (fresh-store)
          [_ record] (as.dcr/register {"client_name"   "<script>alert(1)</script>"
                                       "redirect_uris" ["https://good.example.com/cb"]})
          _     (as.store/put! store (as.dcr/client-key (:client-id record)) record 3600)
          resp  (as.authorize/authorize-get
                 {:store store :base-url base-url}
                 {"client_id"             (:client-id record)
                  "redirect_uri"          "https://good.example.com/cb"
                  "code_challenge"        "abc"
                  "code_challenge_method" "S256"})]
      (is (not (str/includes? (:body resp) "<script>alert(1)</script>")))
      (is (str/includes? (:body resp) "&lt;script&gt;")))))


(deftest authorize-post-requires-a-live-pending-request
  (let [store (fresh-store)]
    (testing "an unknown request_id cannot forward to the IdP"
      (let [resp (as.authorize/authorize-post
                  {:store store}
                  (fn [_] "https://idp.example.com/authorize")
                  {"request_id" "never-issued"})]
        (is (= 400 (:status resp)))
        (is (nil? (location resp)))))))


;; ---------------------------------------------------------------------------
;; Token endpoint
;; ---------------------------------------------------------------------------


(defn- seed-code!
  [store {:keys [code client-id redirect-uri challenge user-id resource]}]
  (as.store/put! store (as.token/code-key code)
                 {:client-id      client-id
                  :redirect-uri   redirect-uri
                  :code-challenge challenge
                  :resource       resource
                  :user-id        user-id
                  :email          "user@example.com"}
                 90)
  store)


(def ^:private code-fixture
  {:code "the-code" :client-id "cid" :redirect-uri "https://good.example.com/cb"
   :challenge "not-a-real-digest" :user-id "user-1"})


(deftest token-refuses-the-ropc-password-grant
  (testing "the password grant must never be reachable — an AS that sees user
            credentials defeats the point of delegating to an IdP"
    (let [resp (as.token/token-post {:store (fresh-store)}
                                    {"grant_type" "password"
                                     "username"   "u"
                                     "password"   "p"})]
      (is (= 400 (:status resp)))
      (is (= "unsupported_grant_type" (get (:body resp) "error"))))))


(deftest token-binds-the-code-to-client-and-redirect-uri
  (testing "another client cannot redeem a code that is not theirs"
    (let [store (seed-code! (fresh-store) code-fixture)
          resp  (as.token/token-post
                 {:store store}
                 {"grant_type"    "authorization_code"
                  "code"          "the-code"
                  "client_id"     "a-different-client"
                  "redirect_uri"  "https://good.example.com/cb"
                  "code_verifier" "whatever"})]
      (is (= 400 (:status resp)))
      (is (= "invalid_grant" (get (:body resp) "error")))))

  (testing "a mismatched redirect_uri at exchange fails"
    (let [store (seed-code! (fresh-store) code-fixture)
          resp  (as.token/token-post
                 {:store store}
                 {"grant_type"    "authorization_code"
                  "code"          "the-code"
                  "client_id"     "cid"
                  "redirect_uri"  "https://elsewhere.example.com/cb"
                  "code_verifier" "whatever"})]
      (is (= 400 (:status resp))))))


(deftest authorization-code-is-single-use
  (testing "a replayed code fails, so an intercepted code is worthless once
            the legitimate client has redeemed it"
    (let [store    (fresh-store)
          verifier "the-real-verifier"
          _        (seed-code! store (assoc code-fixture
                                            :challenge (as.prim/code-challenge-for verifier)))
          params   {"grant_type"    "authorization_code"
                    "code"          "the-code"
                    "client_id"     "cid"
                    "redirect_uri"  "https://good.example.com/cb"
                    "code_verifier" verifier}
          first*   (as.token/token-post {:store store} params)
          second*  (as.token/token-post {:store store} params)]
      (testing "the first exchange succeeds and returns a usable token pair"
        (is (= 200 (:status first*)))
        (is (seq (get (:body first*) "access_token")))
        (is (seq (get (:body first*) "refresh_token"))))
      (testing "the replay is refused"
        (is (= 400 (:status second*)))
        (is (= "invalid_grant" (get (:body second*) "error"))))
      (testing "the resolved identity reaches the session, and is NOT handed
                to the client in the token response"
        (let [session (as.token/session-for
                       {:store store :base-url base-url}
                       (str "Bearer " (get (:body first*) "access_token")))]
          (is (= "user-1" (:user-id session)))
          (is (nil? (get (:body first*) "user_id")))
          (is (not (str/includes? (str (:body first*)) "user-1"))))))))


(deftest token-exchange-enforces-pkce
  (testing "a wrong verifier fails even with an otherwise-valid code"
    (let [store (fresh-store)
          _     (seed-code! store (assoc code-fixture
                                         :challenge (as.prim/code-challenge-for "right")))
          resp  (as.token/token-post
                 {:store store}
                 {"grant_type"    "authorization_code"
                  "code"          "the-code"
                  "client_id"     "cid"
                  "redirect_uri"  "https://good.example.com/cb"
                  "code_verifier" "wrong"})]
      (is (= 400 (:status resp)))
      (is (= "invalid_grant" (get (:body resp) "error")))))

  (testing "an omitted code_verifier is a clean invalid_grant, not a crash"
    (let [store (fresh-store)
          _     (seed-code! store (assoc code-fixture
                                         :challenge (as.prim/code-challenge-for "right")))
          resp  (as.token/token-post
                 {:store store}
                 {"grant_type"   "authorization_code"
                  "code"         "the-code"
                  "client_id"    "cid"
                  "redirect_uri" "https://good.example.com/cb"})]
      (is (= 400 (:status resp)))
      (is (= "invalid_grant" (get (:body resp) "error"))))))


(deftest refresh-tokens-rotate-and-cannot-be-replayed
  (let [store   (fresh-store)
        session {:client-id "cid" :resource base-url :user-id "user-1"}
        issued  (as.token/issue-tokens! store session)
        refresh (get issued "refresh_token")
        second* (as.token/token-post {:store store}
                                     {"grant_type"    "refresh_token"
                                      "refresh_token" refresh
                                      "client_id"     "cid"})]
    (is (= 200 (:status second*)))
    (testing "OAuth 2.1 requires rotation for public clients"
      (is (seq (get (:body second*) "refresh_token")))
      (is (not= refresh (get (:body second*) "refresh_token"))))
    (testing "the presented token is dead — a stolen copy cannot be reused"
      (is (= 400 (:status (as.token/token-post
                           {:store store}
                           {"grant_type"    "refresh_token"
                            "refresh_token" refresh
                            "client_id"     "cid"})))))
    (testing "a refresh token cannot be redeemed by a different client"
      (is (= 400 (:status (as.token/token-post
                           {:store store}
                           {"grant_type"    "refresh_token"
                            "refresh_token" (get (:body second*) "refresh_token")
                            "client_id"     "someone-else"})))))))


;; ---------------------------------------------------------------------------
;; Session validation / audience binding
;; ---------------------------------------------------------------------------


(deftest bearer-parsing-is-scheme-case-insensitive
  (is (= "abc" (as.token/bearer-token "Bearer abc")))
  (is (= "abc" (as.token/bearer-token "bearer abc")))
  (is (nil? (as.token/bearer-token "Bearer ")))
  (is (nil? (as.token/bearer-token nil))))


(deftest audience-binding-accepts-siblings-but-not-lookalikes
  (testing "nil audience passes — backward compat with un-bound tokens"
    (is (as.token/audience-ok? nil base-url)))
  (testing "the base URL and the canonical /mcp path both pass"
    (is (as.token/audience-ok? base-url base-url))
    (is (as.token/audience-ok? (str base-url "/mcp") base-url)))
  (testing "a partitioned sibling passes — same resource server"
    (is (as.token/audience-ok? (str base-url "/mcp/atlas") base-url))
    (is (as.token/audience-ok? (str base-url "/mcp/self") base-url)))
  (testing "a look-alike path does NOT pass — the trailing slash in the
            /mcp/ check stops prefix smuggling"
    (is (not (as.token/audience-ok? (str base-url "/mcp-evil") base-url))))
  (testing "another origin does not pass"
    (is (not (as.token/audience-ok? "https://other.example.com/mcp" base-url)))))


(deftest session-for-enforces-the-audience
  (let [store (fresh-store)]
    (testing "a token minted for another resource is refused here"
      (let [issued (as.token/issue-tokens!
                    store {:client-id "cid" :resource "https://other.example.com/mcp"})]
        (is (nil? (as.token/session-for
                   {:store store :base-url base-url}
                   (str "Bearer " (get issued "access_token")))))))

    (testing "a token minted for this server resolves to the session identity"
      (let [issued (as.token/issue-tokens!
                    store {:client-id "cid" :resource base-url :user-id "user-1"})
            session (as.token/session-for
                     {:store store :base-url base-url}
                     (str "Bearer " (get issued "access_token")))]
        (is (= "user-1" (:user-id session)))))

    (testing "a refresh token must not work as an access token"
      (let [issued (as.token/issue-tokens!
                    store {:client-id "cid" :resource base-url})]
        (is (nil? (as.token/session-for
                   {:store store :base-url base-url}
                   (str "Bearer " (get issued "refresh_token")))))))

    (testing "an unknown token resolves to nil, not an exception"
      (is (nil? (as.token/session-for {:store store :base-url base-url}
                                      "Bearer not-a-real-token"))))))


;; ---------------------------------------------------------------------------
;; IdP claim verification
;; ---------------------------------------------------------------------------


(def ^:private good-claims
  {"iss" "https://accounts.example.com"
   "aud" "our-client-id"
   "exp" 9999999999
   "email" "User@Example.com"
   "email_verified" true})


(def ^:private verify-opts
  {:expected-issuers  #{"https://accounts.example.com"}
   :expected-audience "our-client-id"
   :now-seconds       1000})


(deftest oidc-email-verification-rejects-every-bad-case
  (testing "the happy path lower-cases the address"
    (is (= "user@example.com" (as.idp/verified-oidc-email good-claims verify-opts))))
  (testing "an unverified email is refused — anyone can claim an unverified
            address on an account they control"
    (is (nil? (as.idp/verified-oidc-email
               (assoc good-claims "email_verified" false) verify-opts))))
  (testing "a token for another audience is refused"
    (is (nil? (as.idp/verified-oidc-email
               (assoc good-claims "aud" "someone-elses-client") verify-opts))))
  (testing "an unexpected issuer is refused"
    (is (nil? (as.idp/verified-oidc-email
               (assoc good-claims "iss" "https://evil.example.com") verify-opts))))
  (testing "an expired token is refused"
    (is (nil? (as.idp/verified-oidc-email
               (assoc good-claims "exp" 999) verify-opts))))
  (testing "a missing email is refused"
    (is (nil? (as.idp/verified-oidc-email (dissoc good-claims "email") verify-opts))))
  (testing "nil claims are refused"
    (is (nil? (as.idp/verified-oidc-email nil verify-opts)))))


;; ---------------------------------------------------------------------------
;; Callback — domain gate + identity resolution
;; ---------------------------------------------------------------------------


(defn- stub-idp
  [email]
  {:idp/authorize-url-for (fn [_] "https://idp.example.com/authorize")
   :idp/exchange-code!    (fn [_code] (when email {:email email}))})


(defn- pending!
  [store request-id]
  (as.store/put! store (as.authorize/auth-request-key request-id)
                 {:client-id      "cid"
                  :redirect-uri   "https://good.example.com/cb"
                  :state          "st"
                  :code-challenge "abc"
                  :resource       base-url}
                 600)
  store)


(deftest callback-refuses-an-expired-request-without-redirecting
  (let [resp (as.callback/google-callback-get
              {:store (fresh-store) :base-url base-url
               :idp (stub-idp "user@example.com")
               :resolve-identity (constantly {:user-id "u"})}
              {"code" "x" "state" "never-issued"})]
    (is (= 400 (:status resp)))
    (is (nil? (location resp)))))


(deftest callback-applies-the-domain-gate-before-the-identity-resolver
  (testing "an out-of-policy identity is refused, and the resolver is never
            called — otherwise the AS would be an account-enumeration oracle"
    (let [resolver-called? (atom false)
          store (pending! (fresh-store) "req-1")
          resp  (as.callback/google-callback-get
                 {:store store :base-url base-url
                  :idp (stub-idp "outsider@elsewhere.example")
                  :domain-policy (fn [email]
                                   (if (str/ends-with? email "@example.com") :allow :deny))
                  :resolve-identity (fn [_] (reset! resolver-called? true) {:user-id "u"})}
                 {"code" "x" "state" "req-1"})]
      (is (= 302 (:status resp)))
      (is (= "access_denied" (query-param (location resp) "error")))
      (is (nil? (query-param (location resp) "code")))
      (is (false? @resolver-called?) "the identity resolver must not run"))))


(deftest callback-refuses-unknown-and-ambiguous-identities
  (testing "an unknown identity is a refusal, never an implicit signup"
    (let [store (pending! (fresh-store) "req-2")
          resp  (as.callback/google-callback-get
                 {:store store :base-url base-url
                  :idp (stub-idp "stranger@example.com")
                  :resolve-identity (constantly :none)}
                 {"code" "x" "state" "req-2"})]
      (is (= 400 (:status resp)))
      (is (nil? (location resp)))))

  (testing "two accounts sharing an address must not silently pick one"
    (let [store (pending! (fresh-store) "req-3")
          resp  (as.callback/google-callback-get
                 {:store store :base-url base-url
                  :idp (stub-idp "dup@example.com")
                  :resolve-identity (constantly :ambiguous)}
                 {"code" "x" "state" "req-3"})]
      (is (= 400 (:status resp)))
      (is (nil? (location resp))))))


(deftest callback-mints-a-code-carrying-the-resolved-identity
  (let [store (pending! (fresh-store) "req-4")
        resp  (as.callback/google-callback-get
               {:store store :base-url base-url
                :idp (stub-idp "user@example.com")
                :resolve-identity (constantly {:user-id "user-42" :org "acme"})}
               {"code" "x" "state" "req-4"})
        loc   (location resp)
        code  (query-param loc "code")]
    (is (= 302 (:status resp)))
    (is (str/starts-with? loc "https://good.example.com/cb"))
    (is (= "st" (query-param loc "state")))
    (testing "RFC 9207: iss is echoed so the client can detect an AS mix-up"
      (is (seq (query-param loc "iss"))))
    (testing "the stored code carries every key the resolver returned"
      (let [stored (as.store/get* store (as.token/code-key code))]
        (is (= "user-42" (:user-id stored)))
        (is (= "acme" (:org stored)))
        (is (= "user@example.com" (:email stored)))))
    (testing "the pending request is consumed — the same state cannot be reused"
      (is (= 400 (:status (as.callback/google-callback-get
                           {:store store :base-url base-url
                            :idp (stub-idp "user@example.com")
                            :resolve-identity (constantly {:user-id "user-42"})}
                           {"code" "x" "state" "req-4"})))))))


;; ---------------------------------------------------------------------------
;; Discovery metadata
;; ---------------------------------------------------------------------------


(deftest discovery-advertises-what-clients-need
  (testing "without registration_endpoint a web MCP client cannot self-register"
    (let [md (as.prim/authorization-server-metadata {:base-url base-url})]
      (is (= (str base-url "/oauth/register") (get md "registration_endpoint")))
      (is (= base-url (get md "issuer")))
      (is (= ["S256"] (get md "code_challenge_methods_supported")))
      (is (contains? (set (get md "grant_types_supported")) "refresh_token"))
      (is (true? (get md "authorization_response_iss_parameter_supported")))))

  (testing "registration_endpoint is omitted when DCR is not wired — silent
            omission beats advertising a 404"
    (is (nil? (get (as.prim/authorization-server-metadata
                    {:base-url base-url :dcr? false})
                   "registration_endpoint"))))

  (testing "the protected resource names the base URL so one token spans
            every partitioned sibling path"
    (let [md (as.prim/protected-resource-metadata {:base-url base-url})]
      (is (= base-url (get md "resource")))
      (is (= [base-url] (get md "authorization_servers")))))

  (testing "the challenge header points at the metadata document"
    (let [h (as.prim/www-authenticate-header {:base-url base-url :scope "mcp"})]
      (is (str/includes? h "resource_metadata="))
      (is (str/includes? h "/.well-known/oauth-protected-resource"))
      (is (str/includes? h "scope=\"mcp\"")))))
