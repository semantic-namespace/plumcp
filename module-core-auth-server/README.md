# plumcp module-core-auth-server

**Embedded OAuth 2.1 Authorization Server for plumcp MCP servers.**

## Why this module exists

plumcp already lets an MCP server act as an OAuth *resource server* —
`plumcp.core.server.http-ring-auth` validates JWTs minted by an external
authorization server (Auth0, Keycloak, Cognito, Cloudflare Access, …), and
`plumcp.core.client.http-client-transport-auth` is a full OAuth 2.1 client.

This module covers the remaining role: **being your own authorization server**,
so an MCP server is self-contained and needs no external IdP admin surface.

The motivating constraint is concrete. The MCP spec expects clients to obtain a
`client_id` without human intervention — historically via Dynamic Client
Registration (RFC 7591). Hosted IdPs gate DCR behind a tenant-wide setting that
lets *anonymous third parties create applications in your tenant*, which many
operators reasonably decline to enable. With an embedded AS, DCR lives in your
own process: your upstream IdP client-id stays fixed and server-side, and the
IdP never learns MCP clients exist.

## Flow

```
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
```

## Namespaces

| Namespace | Role |
|---|---|
| `plumcp.core.server.oauth-as` | Assembly — route table + `wrap-oauth` options |
| `…oauth-as.store` | `Store` protocol (+ `atom-store` for tests) |
| `…oauth-as.primitive` | Random tokens, PKCE S256, discovery documents |
| `…oauth-as.dcr` | RFC 7591 Dynamic Client Registration |
| `…oauth-as.authorize` | `/oauth/authorize` — consent + the open-redirect boundary |
| `…oauth-as.token` | `/oauth/token`, session validation, audience binding |
| `…oauth-as.idp` | Identity-provider abstraction + OIDC claim verification |
| `…oauth-as.google-java` | Google IdP factory (JVM; JDK `HttpClient`, no extra deps) |
| `…oauth-as.callback` | IdP redirect target — domain gate + identity resolution |

## Usage

```clojure
(require '[plumcp.core.server.oauth-as :as as]
         '[plumcp.core.server.oauth-as.store :as store]
         '[plumcp.core.server.oauth-as.google-java :as google]
         '[plumcp.core.server.http-ring-transport :as hrt]
         '[plumcp.core.util :as u])

(def as-options
  (as/make-ring-as-options
    {:store            (store/atom-store)   ; back with Redis in production
     :base-url         "https://mcp.example.com"
     :parse-json       u/json-parse
     :write-json       u/json-write
     :idp              (google/google-provider
                         {:client-id     "…apps.googleusercontent.com"
                          :client-secret (fn [] (secret!))
                          :callback-url  "https://mcp.example.com/oauth/google/callback"
                          :parse-json    u/json-parse})
     :domain-policy    #(if (str/ends-with? % "@example.com") :allow :deny)
     :resolve-identity (fn [email]
                         (if-let [u (find-user-by-email email)]
                           {:user-id (:id u)}
                           :none))
     :provider-label   "Continue with Google"}))

(-> mcp-handler
    (hrt/wrap-oauth (:wrap-oauth-options as-options))
    (hrt/wrap-route-match uris {:get-uri-routes (:routes as-options)}))
```

Register **one** redirect URI with your IdP —
`https<your-base-url>/oauth/google/callback` — regardless of how many MCP
clients register with the AS.

## Security properties

Every one of these has a test asserting the **negative** case:

**Exact redirect_uri matching.** `/oauth/authorize` resolves `client_id` and
requires `redirect_uri` to be an exact member of that client's registered list
*before anything can 302*. Unknown client or unmatched URI renders an error page
on your domain. Since DCR is unauthenticated, this check is the entire basis for
trusting a redirect target — a prefix or `contains` check would be a hole.

**Per-client consent (confused deputy).** The AS proxies a *static* upstream IdP
client on behalf of *dynamically registered* MCP clients, so it obtains user
consent naming the registering client before forwarding. Without it, a client
registering an attacker-controlled `redirect_uri` could harvest an authorization
code off the user's existing IdP session with no visible prompt. The client name
is attacker-supplied and HTML-escaped.

**PKCE (RFC 7636, S256 only).** Required on every authorization request; `plain`
is refused rather than accepted as a downgrade. Constant-time comparison.
Nil/blank operands return `false` rather than throwing, so a request omitting
`code_verifier` surfaces as `invalid_grant` instead of a 500.

**One-time authorization codes.** 90-second TTL, read-then-delete, and
additionally bound to `client-id` + `redirect-uri` + PKCE challenge, so a replay
by any other party fails the binding checks even if the delete races.

**Refresh token rotation.** OAuth 2.1 requires it for public clients. The
presented token is consumed and a new one issued, so a stolen copy is dead once
the legitimate client has used it.

**Audience binding (RFC 8707).** `resource` is recorded at authorize time and
checked at validation. Accepts the base URL, `base/mcp`, or any `base/mcp/*`
sibling (so one token spans partitioned endpoints), but *not* `base/mcp-anything`
— the trailing slash stops look-alike-path smuggling.

**Public clients only.** No `client_secret` is ever issued, so there is no
client secret for an MCP client to leak.

**Opaque session tokens.** 256 bits from the platform CSPRNG, stored server-side.
No signing key to manage or rotate, revocation is a delete, and claims cannot be
forged because the token carries none.

**Domain gate before identity resolution.** The optional `:domain-policy` runs
*before* `:resolve-identity`, so an out-of-policy identity cannot learn whether
an address exists in your account database.

**No implicit signup.** An unrecognised identity is refused (`:none`), and an
address matching more than one account is refused rather than guessed
(`:ambiguous`).

**No ROPC.** The `password` grant is not implemented and should not be added — it
forces the AS to handle user credentials, defeating the point of delegating
identity to an IdP.

## Status and roadmap

Working end-to-end in production against Google, exercised by Claude.ai custom
connectors, Claude Code HTTP MCP entries, and raw `curl`.

Not yet implemented:

- **Client ID Metadata Documents (CIMD).** MCP spec 2025-11-25 deprecates DCR in
  favour of CIMD, where the client's `client_id` is an HTTPS URL the AS fetches
  metadata from. Supporting it means an outbound fetch of a client-controlled URL,
  so it needs SSRF protection and HTTP cache-header handling — deliberately
  deferred rather than rushed. DCR works with current clients.
- **CLJS `google-provider`.** The AS core is `.cljc`; only the Google HTTP
  exchange is JVM-only. A browser-resident AS is an unusual deployment, so this
  has not been a priority.
- **Fine-grained scopes / incremental consent.** A single `mcp` scope today.
- **Per-tool audit and rate limiting.** Out of scope for the AS itself.
