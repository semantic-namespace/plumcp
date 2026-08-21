;   Copyright (c) Shantanu Kumar. All rights reserved.
;   The use and distribution terms for this software are covered by the
;   Eclipse Public License 1.0 (http://opensource.org/licenses/eclipse-1.0.php)
;   which can be found in the file LICENSE at the root of this distribution.
;   By using this software in any fashion, you are agreeing to be bound by
;   the terms of this license.
;   You must not remove this notice, or any other, from this software.


(ns plumcp.core.server.oauth-as.store
  "Storage protocol for OAuth AS ephemeral state — DCR client registrations,
  pending authorization requests, one-time auth codes, session tokens, refresh
  tokens. All entries carry a TTL because every OAuth object either expires or
  is single-use; nothing is meant to live forever.

  Kept intentionally small so callers can back it with Redis, an in-memory
  atom for tests, a durable KV, or a Ring session store adapter.")


(defprotocol Store
  (get* [_this k]
    "Return the stored value or nil. Expired entries return nil.")

  (put! [_this k v ttl-seconds]
    "Store value with a TTL. Returns nil.")

  (delete! [_this k]
    "Remove the entry. No-op if the key is absent. Returns nil.

    OAuth AS depends on delete!: authorization codes and refresh tokens are
    single-use, and the way we enforce that is read-then-delete. A racing
    double-redeem by the SAME party can still read the value twice (this
    operation is not atomic on purpose — atomicity is expected to come from
    the backend), but the code is additionally bound to client-id +
    redirect-uri + PKCE challenge, so a replay by any *other* party fails
    the binding checks."))


(defonce ^:private warned? (volatile! false))


(defn- warn-not-durable!
  "Say once, on the first write, that nothing here survives the process.

  A docstring saying \"not meant for production\" is not enough, because the
  failure does not look like storage. Every OAuth object lives here — DCR client
  registrations, authorization codes, access and refresh tokens — so a restart
  silently invalidates all of them at once. What an operator then sees is a
  client that completes the whole sign-in flow, receives a token, and is
  rejected the moment it reconnects: the exact shape of an authorization bug,
  with no authorization bug present. Discovery documents, audience binding and
  the 401 challenge all still verify correct, so the search goes everywhere
  except the store.

  Fires on the first `put!` rather than at construction: that is the moment
  something exists to lose, and it is still early enough to land in startup
  logs. Once per process, so it cannot become noise."
  []
  (when-not @warned?
    (vreset! warned? true)
    (let [msg (str "plumcp oauth-as: using the in-memory atom-store. "
                   "Every client registration, authorization code, session and "
                   "refresh token is lost when this process restarts — clients "
                   "that signed in successfully will be rejected on reconnect. "
                   "Supply a durable Store implementation for anything but tests "
                   "and single-process dev.")]
      #?(:clj  (binding [*out* *err*] (println "WARNING:" msg))
         :cljs (js/console.warn (str "WARNING: " msg))))))


(defn atom-store
  "Trivial in-memory Store useful for tests and single-process dev. TTLs are
  recorded and enforced against System/currentTimeMillis, so an entry that
  passes its expiry returns nil from get* even without eviction. Not meant
  for production — no cleanup thread, unbounded growth, and nothing survives a
  restart (see `warn-not-durable!`).

  `:warn?` false suppresses the first-write warning — for test suites that
  build many stores and have no interest in being told."
  ([] (atom-store (atom {}) {}))
  ([backing-atom] (atom-store backing-atom {}))
  ([backing-atom {:keys [warn?] :or {warn? true}}]
   (reify Store
     (get* [_ k]
       (let [{:keys [value expires-at]} (get @backing-atom k)]
         (when (and (some? value)
                    (< #?(:clj  (System/currentTimeMillis)
                          :cljs (.getTime (js/Date.)))
                       expires-at))
           value)))
     (put! [_ k v ttl-seconds]
       (when warn? (warn-not-durable!))
       (swap! backing-atom assoc k
              {:value      v
               :expires-at (+ #?(:clj  (System/currentTimeMillis)
                                 :cljs (.getTime (js/Date.)))
                              (* 1000 ttl-seconds))})
       nil)
     (delete! [_ k]
       (swap! backing-atom dissoc k)
       nil))))


(defn consume!
  "Read-then-delete, in that order. Returns the value or nil. Used for
  single-use entries — authorization codes, refresh tokens (rotation). See
  Store's delete! docstring for the atomicity trade-off."
  [store k]
  (when-let [v (get* store k)]
    (delete! store k)
    v))
