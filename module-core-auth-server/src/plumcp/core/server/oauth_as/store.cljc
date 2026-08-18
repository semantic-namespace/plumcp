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


(defn atom-store
  "Trivial in-memory Store useful for tests and single-process dev. TTLs are
  recorded and enforced against System/currentTimeMillis, so an entry that
  passes its expiry returns nil from get* even without eviction. Not meant
  for production — no cleanup thread, unbounded growth."
  ([] (atom-store (atom {})))
  ([backing-atom]
   (reify Store
     (get* [_ k]
       (let [{:keys [value expires-at]} (get @backing-atom k)]
         (when (and (some? value)
                    (< #?(:clj  (System/currentTimeMillis)
                          :cljs (.getTime (js/Date.)))
                       expires-at))
           value)))
     (put! [_ k v ttl-seconds]
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
