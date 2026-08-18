;   Copyright (c) Shantanu Kumar. All rights reserved.
;   The use and distribution terms for this software are covered by the
;   Eclipse Public License 1.0 (http://opensource.org/licenses/eclipse-1.0.php)
;   which can be found in the file LICENSE at the root of this distribution.
;   By using this software in any fashion, you are agreeing to be bound by
;   the terms of this license.
;   You must not remove this notice, or any other, from this software.


(ns plumcp.core.server.oauth-as.callback
  "GET /oauth/{idp}/callback — the round-trip endpoint the IdP redirects the
  user back to. Runs the code exchange, applies the caller-supplied domain
  and identity resolvers, and either mints our authorization code (redirect
  back to the client with `?code=...`) or refuses (redirect back with
  `?error=access_denied`).

  Two design choices worth naming:

    1. Refusals redirect to the client's redirect_uri with an OAuth error,
       not an HTML page — the MCP client can then surface a real error to
       the user rather than a broken flow. The exception is 'request
       expired' (state not found), which cannot redirect anywhere safely
       and so renders an error page on our domain.

    2. Unknown identities are refused, not silently signed up. This module
       runs in front of an existing service — the user already has an
       account or they don't. Treating an unrecognised email as a signup
       primitive would be surprising to callers who wanted an AS, not a
       registration surface."
  (:require
   [plumcp.core.server.oauth-as.authorize :as authorize]
   [plumcp.core.server.oauth-as.idp :as idp]
   [plumcp.core.server.oauth-as.primitive :as prim]
   [plumcp.core.server.oauth-as.store :as store]
   [plumcp.core.server.oauth-as.token :as token]))


;; ---------------------------------------------------------------------------
;; Caller-supplied policies (typed for docs; runtime is duck-typed)
;; ---------------------------------------------------------------------------
;;
;; :domain-policy    (fn [email]) → :allow | :deny
;;    Optional. Default: :allow every non-blank email. Providers usually want
;;    at least a domain allow-list — `#(if (str/ends-with? % "@example.com")
;;                                       :allow :deny)`.
;;
;; :resolve-identity (fn [email]) → {:user-id ..., ...} | :none | :ambiguous
;;    Required. Maps the verified IdP email to the caller's internal user
;;    identity. Returning :none makes the AS refuse the whole flow (unknown
;;    account); returning :ambiguous is treated as a hard error rather than a
;;    guess (two users share the address; the AS will not pick one).


(defn google-callback-get
  "Handles the IdP-side redirect.

  `deps` carries:
    :store        Store
    :base-url     canonical AS URL — echoed as `iss` on error redirects
    :idp          identity-provider map (see plumcp.core.server.oauth-as.idp)
    :domain-policy    (fn [email]) → :allow | :deny         optional
    :resolve-identity (fn [email]) → {:user-id ...} | :none | :ambiguous

  `params` is the query-param map from the IdP's redirect (`code`, `state`,
  optional `error`)."
  [{:keys [store base-url idp domain-policy resolve-identity]
    :or   {domain-policy (constantly :allow)}
    :as   _deps}
   {:strs [code state error]}]
  (let [pending (when (seq state)
                  (store/consume! store (authorize/auth-request-key state)))]
    (cond
      (nil? pending)
      (authorize/error-page "Request expired"
                            "This sign-in request has expired. Please start again from your client.")

      (seq error)
      (authorize/redirect-back (:redirect-uri pending)
                               {:error             "access_denied"
                                :error_description "sign-in was cancelled"
                                :state             (:state pending)
                                :iss               base-url})

      (not (seq code))
      (authorize/redirect-back (:redirect-uri pending)
                               {:error             "invalid_request"
                                :error_description "missing code from identity provider"
                                :state             (:state pending)
                                :iss               base-url})

      :else
      (let [identity     (idp/identity-for idp code)
            email        (:email identity)
            domain-ok?   (and email (= :allow (domain-policy email)))
            resolution   (when domain-ok? (resolve-identity email))]
        (cond
          (nil? email)
          (authorize/redirect-back (:redirect-uri pending)
                                   {:error             "access_denied"
                                    :error_description "could not obtain a verified identity"
                                    :state             (:state pending)
                                    :iss               base-url})

          (not domain-ok?)
          ;; Gate BEFORE the identity resolver: unauthorized identities
          ;; cannot learn whether their email is in the account database
          ;; (would be a stealth enumeration primitive).
          (authorize/redirect-back (:redirect-uri pending)
                                   {:error             "access_denied"
                                    :error_description "sign in with an allowed identity"
                                    :state             (:state pending)
                                    :iss               base-url})

          (= :none resolution)
          (authorize/error-page
           "No account"
           "That identity is not associated with an account here.")

          (= :ambiguous resolution)
          (authorize/error-page
           "Account could not be identified"
           "More than one account shares that email address. Please contact support.")

          :else
          (let [auth-code (prim/random-token)]
            (store/put! store (token/code-key auth-code)
                        (-> (select-keys pending [:client-id :redirect-uri :code-challenge :resource])
                            (merge resolution)
                            (assoc :email email))
                        token/default-auth-code-ttl-seconds)
            (authorize/redirect-back (:redirect-uri pending)
                                     {:code  auth-code
                                      :state (:state pending)
                                      :iss   base-url})))))))
