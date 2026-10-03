# %wicket

`%wicket` is a ship-local OAuth 2.1 authorization server for Earth MCP clients. `%keeper` is the management MCP for that server. Other desks register their own URLs as resource servers and scry `%wicket` to check Bearer tokens.

The desk starts `%wicket` and `%keeper`. It does not bind `/.well-known`, `/oauth`, or `/mcp`, so it can run beside [gwbtc/urbit-mcp](https://github.com/gwbtc/urbit-mcp) (`%mcp-server` on those three paths) and beside ACME (`/.well-known/acme-challenge`).

Granting a scope, or adding one to a grant, happens only when the ship owner approves the consent page. `%keeper`, the dojo, and the action mark can list and revoke clients and tokens, and can remove scopes that were already granted. They cannot grant.

## Install

Kelvin `[%zuse 408]`. `desk/` is the source desk. `zig build` writes `zig-out/` from that directory plus pinned files from [urbit/urbit](https://github.com/urbit/urbit) `0f94550` (`pkg/base-dev` and `pkg/landscape`: the agent libraries, thread libraries, and marks this desk imports). The builder is the same script as %pier-mcp and compiles with Zig 0.15. Git needs 2.25 or newer. `desk-dev/` is the kit a resource server copies into its own desk; the build does not include it.

`mar/hoon.hoon` stays in this repo. The pinned `%hoon` mark is the old CodeMirror page, and this desk ships a local source viewer instead.

```
|new-desk %wicket
|mount %wicket
```

From this repo, `-Ddesk` clears the mounted desk and replaces it with `zig-out/`:

```
zig build -Ddesk=~/path/to/pier/wicket
```

```
|commit %wicket
|install our %wicket
|eyre/cors/approve 'http://127.0.0.1:8080'
:wicket &wicket-action [%set-origin 'http://127.0.0.1:8080']
```

`origin` is the public URL with no trailing slash. `|install` starts both agents before it is set. The issuer is `{origin}/wicket`. `%keeper` registers `{origin}/wicket/mcp` when this poke lands.

## Discovery

MCP clients build the authorization-server URL by inserting `/.well-known/oauth-authorization-server` in front of the issuer path (RFC 8414). For this issuer that is:

```
GET /.well-known/oauth-authorization-server/wicket
```

The same document is also at `{origin}/wicket/.well-known/openid-configuration`, which is the third probe in the MCP discovery list. `{issuer}/.well-known/oauth-authorization-server` is not a probe, so it is not served.

`%keeper` answers a missing bearer with:

```
HTTP/1.1 401
WWW-Authenticate: Bearer realm="wicket",
  resource_metadata="{origin}/wicket/oauth/protected-resource/wicket/mcp"
```

That document lists `authorization_servers: ["{origin}/wicket"]` and the keeper scopes. Clients then fetch the RFC 8414 URL above. The metadata `authorization_endpoint` and `token_endpoint` are under `{origin}/wicket/oauth/`. `registration_endpoint` is included only while dynamic client registration is open.

Protocol: authorization code, PKCE S256 only, public clients (`token_endpoint_auth_method=none`), refresh tokens. The `resource` parameter is required. `%wicket` does not accept a client secret.

## Keeper

`POST {origin}/wicket/mcp` is a stateless MCP endpoint. Tools, and the scope each one requires:

| Tool | Scope |
| --- | --- |
| `list-clients` | `wicket.clients.read` |
| `revoke-client` | `wicket.clients.revoke` |
| `list-access-tokens`, `list-refresh-tokens` | `wicket.tokens.read` |
| `revoke-access-token`, `revoke-refresh-token` | `wicket.tokens.revoke` |
| `list-grants` | `wicket.grants.read` |
| `drop-scopes` | `wicket.grants.drop` |

`tools/list` hides tools whose scope was not granted. `tools/call` of a hidden tool is HTTP 403 with `WWW-Authenticate` and the missing scope. Token listings return `id_prefix` only. `revoke-*-token` accepts that prefix when it matches one token. `drop-scopes` rejects a scope that is not already on the grant.

Grok Build, in the user `~/.grok/config.toml` (leave the dev `%mcp-server` entry in place):

```toml
[mcp_servers.wicket]
url = "http://127.0.0.1:8080/wicket/mcp"
enabled = true
```

`/mcps`, refresh, then authenticate `wicket`. The browser opens `{origin}/wicket/oauth/authorize`. Log in with the ship `+code`. Uncheck any scope you do not want. Approve. The catalog keys are `wicket__list-clients` and the other seven tools.

## Management page

The Landscape tile **Wicket** opens `{origin}/wicket/manage`. The same page is the owner's view of the lists above. Log in with the ship `+code`. A client can use the ship only where a scope is listed. Each client is a fixed-height tile: name, id, created time, and one line of resource names. Scopes, tokens, and revoking the client open on that tile.

Removing a scope leaves the client registered. Removing its last scope on a resource revokes that grant and the tokens for it. Revoking an access or refresh token leaves the grant; revoking a refresh token ends that Earth session. Revoking the client deletes the client, its grants, and every token. The page cannot grant a scope. That stays on the consent screen.

The page lists only access and refresh tokens that have not expired. It shows token prefixes, not the full token. A registered resource server is listed at the bottom and cannot be added or removed here. Each server is a card. Closed, it shows its name and URL. Open, it shows the agent, the audience when that differs from the URL, and each scope with its description and, for a ship-control scope, that flag, plus any copy for scopes that are not registered.

`{origin}/wicket/manage/log` records client registration, consent approval and denial, revocation of one scope or a whole client, and issuance and explicit revocation of access and refresh tokens. Each row keeps every value from that moment, including the token prefix and the expiry written on the issuance row. Refreshing tokens is an issuance row, and that row names the prefix of the refresh token it replaced. Tokens removed because a scope or a client was revoked are listed on that row. The bearer itself is not stored. Filters are All, Registration, Authorization, Revocation, and Tokens. The channel on a row is the owner page, a local action (Keeper, Dojo, or any local poke), the revocation endpoint, or the removal of a client that was not approved within 24 hours.

The same page opens and closes dynamic client registration. It starts closed. Clients already stored keep working, and new ones cannot register until the owner opens it. While it is open, one address may register 5 clients an hour, at most 32 clients may be waiting for a first approval, and a client that has never been approved is deleted 24 hours after it was created. Approving consent once keeps the client past that deadline, including if its scopes are later removed. The page can also block or unblock an address. Nothing is blocked automatically.

Rate limits and the block list use the address Eyre puts on the request. That is the TCP peer, unless the peer is `127.0.0.1` and the request carries an RFC 7239 `Forwarded` header, in which case Eyre uses the first `for=` value. A reverse proxy should connect from localhost and set that header itself, replacing any value the client sent:

```
reverse_proxy 127.0.0.1:8080 {
  header_up Forwarded "for={remote_host}"
}
```

If the proxy only sends `X-Forwarded-For`, every client shares `127.0.0.1` and the per-address limit is a ship-wide limit of 5 registrations an hour. The switch, the cap of 32, and the 24-hour removal still apply.

```
:wicket &wicket-action [%set-registration %.y]
:wicket &wicket-action [%set-registration %.n]
```

## Dojo

Same listings as the MCP. Token lines print the prefix. A revoke thread takes that prefix, or the bearer itself.

On this dojo, `+desk!generator` runs a generator on a desk. These files live at `gen/wicket/`, so the command is `+wicket!wicket/clients` and the rest the same way:

```
+wicket!wicket/clients
+wicket!wicket/access
+wicket!wicket/refresh
+wicket!wicket/grants
+wicket!wicket/resources
```

```
-wicket!revoke-client 'client-id'
-wicket!revoke-access 'prefix'
-wicket!revoke-refresh 'prefix'
-wicket!drop-scopes ['client-id' 'http://127.0.0.1:8080/wicket/mcp' 'wicket.clients.read']
```

`-test %/tests/lib/wicket` runs the library tests.

## Resource servers

Copy `desk-dev/` into the resource desk (`sur/wicket.hoon`, `mar/wicket/action.hoon`, `lib/wicket-check.hoon`). Poke `%wicket` at runtime. The URL must be on the configured origin.

```
:wicket &wicket-action [%register-resource ['http://127.0.0.1:8080/larder' %larder (silt ~['larder.read']) 'http://127.0.0.1:8080/larder']]
```

Consent shows the scope cord unless the resource server also pokes `%set-scope-copy` with a title and a label per scope. `%ship` (and a bare `&`) is listed first, marked "Controls the ship", and its checkbox starts unchecked. `%ask` also starts unchecked and is not marked as ship control. `%off` (and a bare `|`) stays checked. Keeper does not send copy, so its labels stay the ones in this desk.

```
:wicket &wicket-action [%set-scope-copy 'http://127.0.0.1:8080/larder' ['Larder' (malt ~[['larder.read' ['Read recipes.' %off]]])]]
```

On a missing or unknown bearer, send:

```
401 Unauthorized
WWW-Authenticate: Bearer realm="wicket",
  resource_metadata="{origin}/wicket/oauth/protected-resource/larder"
```

`/lib/wicket-check.hoon` builds that metadata URL with `+metadata` and checks a token with:

```
.^(? %gx /=wicket=/ok/(scot %t audience)/(scot %t scope)/(scot %t token)/noun)
```

A request Eyre has authenticated as `our` is allowed without a bearer. `%wicket`'s own authorize, token, and register routes do not use that shortcut.

Other scries: `/x/origin`, `/x/issuer`, `/x/resources`, `/x/resource/[scot %t url]`, `/x/clients`, `/x/access`, `/x/refresh`, `/x/grants`, `/x/grant/[scot %t token]`.
