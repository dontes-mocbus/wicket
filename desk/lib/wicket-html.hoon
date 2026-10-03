::  /lib/wicket-html: Sail pages for consent, client management, and the log
::
::    CSS lives in a cord so Sail does not treat braces as interpolation.
::
/-  *wicket
/+  wicket
|%
++  sheet
  ^-  tape
  %-  trip
  '''
  :root {
    --paper: #f4f1ea;
    --ink: #1c1915;
    --muted: #5e584e;
    --line: #d8d2c6;
    --card: #fffcf7;
  }
  * { box-sizing: border-box; }
  html, body {
    margin: 0;
    background: var(--paper);
    color: var(--ink);
    font: 16px/1.5 ui-sans-serif, system-ui, sans-serif;
  }
  body {
    min-height: 100vh;
    padding: 1.5rem 1.25rem 3rem;
  }
  .wordmark {
    margin: 0 0 1.15rem;
    font-size: 0.72rem;
    letter-spacing: 0.18em;
    text-transform: uppercase;
    color: var(--muted);
  }
  main.card {
    max-width: 28rem;
    margin: 0 auto;
    background: var(--card);
    border: 1px solid var(--line);
    border-radius: 10px;
    padding: 1.45rem 1.4rem 1.6rem;
  }
  h1 {
    font-size: 1.5rem;
    font-weight: 600;
    letter-spacing: -0.02em;
    line-height: 1.25;
    margin: 0 0 0.45rem;
  }
  p { margin: 0 0 0.75rem; }
  .muted, .lede, .hint { color: var(--muted); }
  .lede { margin-bottom: 1.1rem; }
  .hint { font-size: 0.85rem; margin: 0.4rem 0 0.9rem; }
  label { display: block; font-size: 0.85rem; font-weight: 500; margin-bottom: 0.35rem; }
  input[type=password], input[type=text] {
    width: 100%;
    padding: 0.65rem 0.75rem;
    border: 1px solid var(--line);
    border-radius: 6px;
    background: #fff;
    color: var(--ink);
    font: inherit;
  }
  button:focus, input:focus, a:focus { outline: 2px solid var(--ink); outline-offset: 2px; }
  .actions { display: flex; flex-wrap: wrap; gap: 0.5rem; margin-top: 0.4rem; }
  button {
    display: inline-block;
    padding: 0.55rem 0.95rem;
    border-radius: 6px;
    border: 1px solid var(--ink);
    background: var(--ink);
    color: #fff;
    font: inherit;
    font-size: 0.95rem;
    cursor: pointer;
  }
  button.secondary { background: transparent; color: var(--ink); }
  .alt { margin: 1.15rem 0 0; font-size: 0.9rem; }
  .alt a { color: var(--ink); }
  .alt a + a { margin-left: 1rem; }
  p.filters { display: flex; flex-wrap: wrap; gap: 0.35rem 0.9rem; }
  p.filters a { color: var(--ink); }
  ul.scopes { list-style: none; padding: 0; margin: 0 0 1rem; }
  li.scope {
    padding: 0.55rem 0.75rem;
    border: 1px solid var(--line);
    border-radius: 6px;
    background: #fff;
    margin-bottom: 0.4rem;
  }
  li.scope.warn {
    border-color: #8a3b12;
    background: #fff4ec;
  }
  p.flag {
    margin: 0 0 0.35rem;
    font-size: 0.78rem;
    font-weight: 600;
    letter-spacing: 0.04em;
    text-transform: uppercase;
    color: #8a3b12;
  }
  label.check {
    display: flex;
    align-items: flex-start;
    gap: 0.6rem;
    margin: 0;
    font-weight: 500;
  }
  label.check input { margin-top: 0.25rem; }
  .resource { margin-bottom: 1rem; }
  .resource strong { display: block; }
  code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 0.85em; }
  main.board { max-width: 42rem; margin: 0 auto; }
  details.client, details.resource, details.event, section.registration {
    background: var(--card);
    border: 1px solid var(--line);
    border-radius: 10px;
    margin: 0 0 1rem;
  }
  section.registration { padding: 1.2rem 1.25rem 1.3rem; }
  section.registration h2 { margin: 0 0 0.6rem; }
  form.block { margin-top: 0.9rem; }
  form.block input[type=text] { margin: 0.35rem 0 0.6rem; }
  details.client > summary, details.resource > summary, details.event > summary {
    list-style: none;
    cursor: pointer;
    position: relative;
    overflow: hidden;
    padding: 0.85rem 2.15rem 0.85rem 1.25rem;
  }
  details.client > summary { height: 6.1rem; }
  details.resource > summary, details.event > summary { overflow: visible; }
  details.client > summary::-webkit-details-marker,
  details.resource > summary::-webkit-details-marker,
  details.event > summary::-webkit-details-marker { display: none; }
  details.client > summary::marker,
  details.resource > summary::marker,
  details.event > summary::marker { content: ""; }
  details.client > summary:focus,
  details.client > summary:focus-visible,
  details.resource > summary:focus,
  details.resource > summary:focus-visible,
  details.event > summary:focus,
  details.event > summary:focus-visible { outline: none; }
  details.client > summary::after, details.resource > summary::after, details.event > summary::after {
    content: "";
    position: absolute;
    right: 1.2rem;
    top: 1.2rem;
    width: 0.45rem;
    height: 0.45rem;
    border-right: 2px solid var(--ink);
    border-bottom: 2px solid var(--ink);
    transform: rotate(45deg);
  }
  details.client[open] > summary::after,
  details.resource[open] > summary::after,
  details.event[open] > summary::after {
    transform: rotate(-135deg);
    top: 1.4rem;
  }
  details.client > summary .name, details.resource > summary .name {
    display: block;
    font-size: 1.05rem;
    font-weight: 600;
    line-height: 1.45rem;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  details.resource > summary .url {
    margin: 0;
    line-height: 1.4rem;
    color: var(--muted);
    font-size: 0.85rem;
    word-break: break-all;
  }
  details.client > summary .meta {
    display: flex;
    gap: 0.75rem;
    align-items: baseline;
    min-width: 0;
    margin: 0;
    line-height: 1.4rem;
    word-break: normal;
  }
  details.client > summary .meta code {
    flex: 0 1 auto;
    min-width: 0;
    margin-right: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    word-break: normal;
  }
  details.client > summary .when {
    flex: none;
    font-size: 0.85rem;
    color: var(--muted);
    white-space: nowrap;
  }
  details.client > summary .resources {
    margin: 0;
    line-height: 1.4rem;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    color: var(--muted);
    font-size: 0.85rem;
  }
  details.client .body, details.resource .body, details.event .body {
    padding: 0.85rem 1.25rem 1.2rem;
    border-top: 1px solid var(--line);
  }
  h2 { font-size: 1.05rem; font-weight: 600; margin: 1.4rem 0 0.6rem; }
  h3 { font-size: 1.05rem; font-weight: 600; margin: 0 0 0.35rem; }
  h4 {
    font-size: 0.85rem;
    font-weight: 600;
    letter-spacing: 0.04em;
    text-transform: uppercase;
    color: var(--muted);
    margin: 0.9rem 0 0.2rem;
  }
  .row {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    justify-content: space-between;
    gap: 0.5rem 1rem;
    padding: 0.55rem 0;
    border-top: 1px solid var(--line);
  }
  section.registration .row { border-top: none; padding-top: 0; }
  section.registration .row + .row {
    border-top: 1px solid var(--line);
    margin-top: 0.55rem;
    padding-top: 0.55rem;
  }
  .row form { margin: 0; }
  .stack { min-width: 12rem; flex: 1 1 16rem; }
  .pair {
    display: flex;
    flex: 1 1 12rem;
    flex-wrap: wrap;
    justify-content: space-between;
    align-items: baseline;
    gap: 0.2rem 1.25rem;
    min-width: 0;
  }
  .pair code { margin-left: auto; color: var(--muted); }
  button.icon {
    padding: 0.1rem 0.45rem;
    min-width: 1.75rem;
    line-height: 1.2;
    font-size: 1.1rem;
    background: transparent;
    color: var(--ink);
  }
  a.button {
    display: inline-block;
    padding: 0.45rem 0.75rem;
    border-radius: 6px;
    border: 1px solid var(--ink);
    background: transparent;
    color: var(--ink);
    font: inherit;
    font-size: 0.9rem;
    text-decoration: none;
  }
  .notice {
    background: var(--card);
    border: 1px solid var(--line);
    border-radius: 6px;
    padding: 0.6rem 0.75rem;
    margin: 0 0 1rem;
  }
  .meta { font-size: 0.85rem; color: var(--muted); word-break: break-all; }
  p.meta code, .stack code { margin-right: 0.6rem; }
  ul.plain { margin: 0 0 1rem; padding-left: 1.15rem; }
  ul.plain li { margin: 0.25rem 0; }
  ul.redirects { margin: 0.2rem 0 0.6rem; padding-left: 1.1rem; }
  ul.redirects li { margin: 0.15rem 0; }
  .grant { margin-top: 0.8rem; }
  details.event > summary .what {
    display: block;
    font-weight: 600;
    line-height: 1.45;
    word-break: break-word;
  }
  details.event code, details.event .row span.v {
    word-break: break-all;
  }
  details.event .row span.k { flex: 0 0 auto; }
  details.event .row code, details.event .row span.v {
    flex: 1 1 12rem;
    min-width: 0;
  }
  details.event .token + .token {
    margin-top: 0.8rem;
    padding-top: 0.15rem;
    border-top: 1px solid var(--line);
  }
  details.resource ul.reg, details.event ul.reg {
    list-style: none;
    padding: 0;
    margin: 0.7rem 0 0;
  }
  details.resource li.reg, details.event li.reg {
    padding: 0.55rem 0 0.15rem;
    border-top: 1px solid var(--line);
  }
  details.resource li.reg:first-child, details.event li.reg:first-child {
    border-top: none;
    padding-top: 0;
  }
  details.resource li.reg.warn {
    margin-top: 0.45rem;
    padding: 0.45rem 0.65rem 0.15rem;
    border: 1px solid #8a3b12;
    border-radius: 6px;
    background: #fff4ec;
  }
  details.resource li.reg.warn + li.reg { border-top: none; }
  details.resource .scope-head {
    display: flex;
    flex-wrap: wrap;
    justify-content: space-between;
    align-items: baseline;
    gap: 0.15rem 0.75rem;
  }
  details.resource .scope-head code { word-break: break-all; }
  details.resource p.desc { margin: 0.12rem 0 0.4rem; }
  details.resource span.flag {
    font-size: 0.78rem;
    font-weight: 600;
    letter-spacing: 0.04em;
    text-transform: uppercase;
    color: #8a3b12;
  }
  '''
::
++  page
  |=  [title=tape body=marl]
  ^-  manx
  ;html
    ;head
      ;meta(charset "utf-8");
      ;meta(name "viewport", content "width=device-width, initial-scale=1");
      ;title: {title}
      ;style: {sheet}
    ==
    ;body
      ;*  body
    ==
  ==
::
++  error-page
  |=  [code=@ud msg=tape]
  ^-  manx
  %-  page
  :-  "Wicket error"
  :~  ;main.card
        ;p.wordmark: Wicket
        ;h1: {msg}
        ;p.muted: HTTP {(scow %ud code)}
      ==
  ==
::
++  consent-page
  |=  [our=@p who=client az=authz copies=(map resource scope-copy)]
  ^-  manx
  =/  nam  (client-name who)
  =/  ship  (scow %p our)
  =/  lab  (title-of resource.az copies)
  =/  url  (resource-url resource.az)
  =/  hid  (scow %uv id.az)
  =/  heading  :(weld "Authorize " nam "?")
  =/  ordered
    %+  sort  scopes.az
    |=  [a=scope b=scope]
    ^-  ?
    =/  wa  (care-of a resource.az copies)
    =/  wb  (care-of b resource.az copies)
    ?:  =((care-rank wa) (care-rank wb))
      (aor (crip (label-of a resource.az copies)) (crip (label-of b resource.az copies)))
    (lth (care-rank wa) (care-rank wb))
  %-  page
  :-  "Wicket — authorize"
  :~  ;main.card
        ;p.wordmark: Wicket
        ;h1: {heading}
        ;p.lede: {nam} wants access to {ship}.
        ;p.resource
          ;strong: {lab}
          ;span.muted: {url}
        ==
        ;form(method "post", action "/wicket/oauth/authorize")
          ;input(type "hidden", name "id", value "{hid}");
          ;ul.scopes
            ;*  (turn ordered |=(s=scope (scope-choice s resource.az copies)))
          ==
          ;p.hint: Uncheck a scope to withhold it. This page cannot add a scope the client did not request.
          ;div.actions
            ;button.primary(type "submit", name "decision", value "approve"): Approve
            ;button.secondary(type "submit", name "decision", value "deny"): Deny
          ==
        ==
      ==
  ==
::
++  scope-choice
  |=  [s=scope res=(unit resource) copies=(map resource scope-copy)]
  ^-  manx
  =/  lab  (label-of s res copies)
  =/  val  (trip s)
  =/  c  (care-of s res copies)
  ?:  (hold-care c)
    ;li.scope.warn
      ;*  (choice-flag c)
      ;label.check
        ;input(type "checkbox", name "scope", value "{val}");
        ;span: {lab}
      ==
    ==
  ;li.scope
    ;label.check
      ;input(type "checkbox", name "scope", value "{val}", checked "checked");
      ;span: {lab}
    ==
  ==
::
++  client-name
  |=  c=client
  ^-  tape
  (trip ?:(=('' name.c) id.c name.c))
::
++  scope-label
  |=  s=scope
  ^-  tape
  ?+  s  (trip s)
    %'wicket.clients.read'    "List OAuth clients"
    %'wicket.clients.revoke'  "Revoke OAuth clients"
    %'wicket.tokens.read'     "List access and refresh tokens"
    %'wicket.tokens.revoke'   "Revoke access and refresh tokens"
    %'wicket.grants.read'     "List grants"
    %'wicket.grants.drop'     "Remove granted scopes"
  ==
::
++  scope-warn
  |=  s=scope
  ^-  ?
  %.n
::
++  copy-of
  |=  [res=(unit resource) copies=(map resource scope-copy)]
  ^-  scope-copy
  ?~  res  *scope-copy
  (fall (~(get by copies) u.res) *scope-copy)
::
++  label-of
  |=  [s=scope res=(unit resource) copies=(map resource scope-copy)]
  ^-  tape
  =/  n  (~(get by notes:(copy-of res copies)) s)
  ?~  n  (scope-label s)
  ?:  =('' label.u.n)  (scope-label s)
  (trip label.u.n)
::
++  care-of
  |=  [s=scope res=(unit resource) copies=(map resource scope-copy)]
  ^-  care
  =/  n  (~(get by notes:(copy-of res copies)) s)
  ?~  n  %.n
  care.u.n
::
++  ship-care
  |=  c=care
  ^-  ?
  ?|(=(c %.y) =(c %ship))
::
++  hold-care
  |=  c=care
  ^-  ?
  ?|(=(c %ask) (ship-care c))
::
::  +care-rank: ship, then other unchecked scopes, then the rest.
::
++  care-rank
  |=  c=care
  ^-  @ud
  ?:  (ship-care c)  0
  ?:  =(c %ask)  1
  2
::
++  choice-flag
  |=  c=care
  ^-  marl
  ?.  (ship-care c)  ~
  :~  ;p.flag: Controls the ship
  ==
::
++  title-of
  |=  [res=(unit resource) copies=(map resource scope-copy)]
  ^-  tape
  =/  c  (copy-of res copies)
  ?:  =('' title.c)  (resource-label res)
  (trip title.c)
::
++  resource-label
  |=  url=(unit @t)
  ^-  tape
  ?~  url  "this ship"
  =/  t  (trip u.url)
  ?:  ?=(^ (find "/wicket/mcp" t))  "Keeper"
  t
::
++  resource-url
  |=  url=(unit @t)
  ^-  tape
  (trip (fall url 'this ship'))
::
++  pad2
  |=  n=@ud
  ^-  tape
  =/  t  (scow %ud n)
  ?:  (lth n 10)  (weld "0" t)
  t
::
++  undot
  |=  t=tape
  ^-  tape
  (skip t |=(c=@tD =('.' c)))
::
++  fmt-da
  |=  d=@da
  ^-  tape
  =/  =date  (yore d)
  ;:  weld
    (undot (scow %ud y.date))
    "-"
    (pad2 m.date)
    "-"
    (pad2 d.t.date)
    " "
    (pad2 h.t.date)
    ":"
    (pad2 m.t.date)
  ==
::
++  join-labels
  |=  [s=(list scope) res=(unit resource) copies=(map resource scope-copy)]
  ^-  tape
  ?~  s  ""
  =/  lab  (label-of i.s res copies)
  ?~  t.s  lab
  (weld lab (weld " · " $(s t.s)))
::
+$  manage-view
  $:  our=@p
      now=@da
      clients=(list client)
      grants=(list authorization)
      access=(list token-info)
      refresh=(list token-info)
      resources=(list registered-resource)
      notice=(unit tape)
      open=(unit client-id)
      registration=?
      approved=(set client-id)
      denied=(list @t)
      copies=(map resource scope-copy)
  ==
::
++  manage-page
  |=  v=manage-view
  ^-  manx
  %-  page
  :-  "Wicket — clients"
  :~  (manage-body v)
  ==
::
++  manage-body
  |=  v=manage-view
  ^-  manx
  =/  ship  (scow %p our.v)
  =/  heading  (weld "Clients on " ship)
  ;main.board
    ;p.wordmark: Wicket
    ;h1: {heading}
    ;p.lede: A client can use this ship only where a scope is listed.
    ;ul.plain
      ;li: Removing a scope leaves the client registered. Removing its last scope on a resource also revokes that grant and its tokens.
      ;li: Revoking a token leaves the grant. Revoking a refresh token ends that session.
      ;li: Revoking the client deletes the client, its grants, and every token.
    ==
    ;*  (notice-marl notice.v)
    ;*  (registration-marl v)
    ;*  (client-sections v)
    ;*  (resource-section resources.v copies.v)
    ;p.alt
      ;a(href "/wicket/manage/log"): Log
      ;a(href "/apps/landscape/"): Landscape
    ==
  ==
::
++  notice-marl
  |=  n=(unit tape)
  ^-  marl
  ?~  n  ~
  [(notice-node u.n)]~
::
++  notice-node
  |=  text=tape
  ^-  manx
  ;p.notice: {text}
::
++  heading-node
  |=  title=tape
  ^-  manx
  ;h2: {title}
::
++  muted-node
  |=  text=tape
  ^-  manx
  ;p.muted: {text}
::
++  client-before
  |=  [a=client b=client]
  ^-  ?
  =/  na  (crip (client-name a))
  =/  nb  (crip (client-name b))
  ?:  =(na nb)  (aor id.a id.b)
  (aor na nb)
::
++  grants-of
  |=  [cid=client-id rows=(list authorization)]
  ^-  (list authorization)
  (skim rows |=(a=authorization =(client.a cid)))
::
++  client-sections
  |=  v=manage-view
  ^-  marl
  =/  ordered  (sort clients.v client-before)
  =/  with
    %+  skim  ordered
    |=(c=client ?=(^ (grants-of id.c grants.v)))
  =/  without
    %+  skip  ordered
    |=(c=client ?=(^ (grants-of id.c grants.v)))
  ?:  =(~ ordered)
    :~  ;p.muted: No clients have been registered.
    ==
  ;:  welp
    (headed "Clients" with |=(c=client (access-card c v)) "No clients have access.")
    (headed "Registered, no access" without |=(c=client (idle-card c v)) "")
  ==
::
++  headed
  |=  [title=tape cs=(list client) make=$-(client manx) empty=tape]
  ^-  marl
  ?:  =(~ cs)
    ?:  =("" empty)
      ~
    ~[(heading-node title) (muted-node empty)]
  (weld ~[(heading-node title)] (turn cs make))
::
++  access-card
  |=  [c=client v=manage-view]
  ^-  manx
  =/  gs  (sort (grants-of id.c grants.v) grant-before)
  =/  body=marl
    (weld (turn gs |=(a=authorization (grant-block a v))) (other-tokens c gs v))
  (client-shell c v body)
::
++  idle-card
  |=  [c=client v=manage-view]
  ^-  manx
  =/  line=tape
    ?:  (~(has in approved.v) id.c)
      "No access granted."
    (removal-line created.c)
  =/  body=marl
    :~  ;p.muted: {line}
    ==
  (client-shell c v body)
::
++  removal-line
  |=  created=@da
  ^-  tape
  :(weld "Removed " (fmt-da (add created idle-ttl:wicket)) " if not approved.")
::
++  waiting-count
  |=  v=manage-view
  ^-  @ud
  %-  lent
  %+  skip  clients.v
  |=  c=client
  (~(has in approved.v) id.c)
::
++  registration-marl
  |=  v=manage-view
  ^-  marl
  [(registration-section v)]~
::
++  registration-section
  |=  v=manage-view
  ^-  manx
  =/  open  registration.v
  =/  status=tape  ?:(open "Open" "Closed")
  =/  label=tape  ?:(open "Close registration" "Open registration")
  =/  flag=tape  ?:(open "no" "yes")
  =/  hours  (div idle-ttl:wicket ~h1)
  =/  explain=tape
    ?:  open
      :(weld "An address may register " (scow %ud rate-max:wicket) " clients an hour. Clients you have not approved are removed after " (scow %ud hours) " hours. " (scow %ud (waiting-count v)) " waiting.")
    "New clients cannot register. Clients that already registered keep working."
  ;section.registration
    ;h2: Registration
    ;p
      ;strong: {status}
    ==
    ;p.muted: {explain}
    ;form(method "post", action "/wicket/manage")
      ;input(type "hidden", name "action", value "set-registration");
      ;input(type "hidden", name "open", value "{flag}");
      ;button(type "submit"): {label}
    ==
    ;*  (denied-marl denied.v)
    ;form.block(method "post", action "/wicket/manage")
      ;input(type "hidden", name "action", value "deny-address");
      ;label(for "block-address"): Block an address
      ;input#block-address(type "text", name "address", required "true", autocomplete "off", spellcheck "false");
      ;button(type "submit"): Block address
    ==
    ;p.hint: Blocking uses the address Eyre recorded. A proxy on localhost must send a Forwarded header for that to be the client.
  ==
::
++  denied-marl
  |=  rows=(list @t)
  ^-  marl
  ?:  =(~ rows)  ~
  (turn rows denied-row)
::
++  denied-row
  |=  addr=@t
  ^-  manx
  =/  shown  (trip addr)
  ;div.row
    ;code: {shown}
    ;form(method "post", action "/wicket/manage")
      ;input(type "hidden", name "action", value "allow-address");
      ;input(type "hidden", name "address", value "{shown}");
      ;button.secondary(type "submit"): Remove
    ==
  ==
::
++  client-shell
  |=  [c=client v=manage-view body=marl]
  ^-  manx
  =/  opened  (tile-open id.c open.v)
  =/  kids=marl
    ~[(client-summary c v) (client-panel c body)]
  ?:  opened
    ;details.client(open "open")
      ;*  kids
    ==
  ;details.client
    ;*  kids
  ==
::
++  tile-open
  |=  [cid=client-id want=(unit client-id)]
  ^-  ?
  ?~  want  %.n
  =(cid u.want)
::
++  client-summary
  |=  [c=client v=manage-view]
  ^-  manx
  =/  nam  (client-name c)
  =/  cid  (trip id.c)
  =/  when  (fmt-da created.c)
  =/  line  (resource-line c grants.v copies.v)
  ;summary
    ;span.name: {nam}
    ;p.meta
      ;code: {cid}
      ;span.when: {when}
    ==
    ;p.resources: {line}
  ==
::
++  client-panel
  |=  [c=client body=marl]
  ^-  manx
  =/  href  (revoke-href id.c)
  ;div.body
    ;*  (redirect-marl redirect-uris.c)
    ;*  body
    ;p.alt
      ;a.button(href "{href}"): Revoke client
    ==
  ==
::
++  resource-line
  |=  [c=client grants=(list authorization) copies=(map resource scope-copy)]
  ^-  tape
  =/  gs  (sort (grants-of id.c grants) grant-before)
  ?~  gs  "No access"
  (join-mid " · " (turn gs |=(a=authorization (title-of resource.a copies))))
::
++  join-mid
  |=  [mid=tape parts=(list tape)]
  ^-  tape
  ?~  parts  ""
  ?~  t.parts  i.parts
  (weld i.parts (weld mid $(parts t.parts)))
::
++  manage-href
  |=  [done=(unit @t) who=(unit client-id)]
  ^-  tape
  =/  done-part=(list tape)
    ?~  done  ~
    ~[(weld "done=" (trip u.done))]
  =/  open-part=(list tape)
    ?~  who  ~
    ~[(weld "open=" (en-urlt:html (trip u.who)))]
  =/  parts  (weld done-part open-part)
  ?~  parts  "/wicket/manage"
  (weld "/wicket/manage?" (join-mid "&" parts))
::
++  revoke-href
  |=  cid=client-id
  ^-  tape
  (weld "/wicket/manage/revoke?client=" (en-urlt:html (trip cid)))
::
++  redirect-marl
  |=  uris=(set @t)
  ^-  marl
  =/  rows  (sort ~(tap in uris) aor)
  ?~  rows  ~
  :~  ;ul.redirects
        ;*  (turn rows redirect-item)
      ==
  ==
::
++  redirect-item
  |=  u=@t
  ^-  manx
  =/  t  (trip u)
  ;li
    ;code: {t}
  ==
::
++  grant-before
  |=  [a=authorization b=authorization]
  ^-  ?
  =/  la  (crip (resource-label resource.a))
  =/  lb  (crip (resource-label resource.b))
  ?:  =(la lb)
    (aor (fall resource.a '') (fall resource.b ''))
  (aor la lb)
::
++  grant-block
  |=  [a=authorization v=manage-view]
  ^-  manx
  =/  lab  (title-of resource.a copies.v)
  =/  url  (resource-url resource.a)
  =/  when  ?:(=(updated.a *@da) "(unset)" (fmt-da updated.a))
  =/  granted  (weld "Granted " when)
  =/  acc  (live-tokens now.v (tokens-matching client.a resource.a access.v))
  =/  ref  (live-tokens now.v (tokens-matching client.a resource.a refresh.v))
  ;div.grant
    ;p.resource
      ;strong: {lab}
      ;span.muted: {url}
    ==
    ;p.meta: {granted}
    ;*  (scope-rows a copies.v)
    ;*  (last-scope-hint scopes.a)
    ;*  (token-group "Access" %access acc copies.v)
    ;*  (token-group "Refresh" %refresh ref copies.v)
    ;*  (token-hint acc ref)
  ==
::
++  scope-before
  |=  [a=scope b=scope]
  ^-  ?
  (aor (crip (scope-label a)) (crip (scope-label b)))
::
++  scope-rows
  |=  [a=authorization copies=(map resource scope-copy)]
  ^-  marl
  =/  rows
    %+  sort  scopes.a
    |=  [p=scope q=scope]
    ^-  ?
    (aor (crip (label-of p resource.a copies)) (crip (label-of q resource.a copies)))
  (turn rows |=(s=scope (scope-row a s copies)))
::
++  scope-row
  |=  [a=authorization s=scope copies=(map resource scope-copy)]
  ^-  manx
  =/  lab  (label-of s resource.a copies)
  =/  raw  (trip s)
  =/  cid  (trip client.a)
  =/  hint  (weld "Remove " lab)
  ;div.row
    ;div.pair
      ;span: {lab}
      ;*  (raw-code !=(lab raw) raw)
    ==
    ;form(method "post", action "/wicket/manage")
      ;input(type "hidden", name "action", value "drop-scope");
      ;input(type "hidden", name "client", value "{cid}");
      ;*  (resource-input resource.a)
      ;input(type "hidden", name "scope", value "{raw}");
      ;button.icon(type "submit", aria-label "{hint}", title "{hint}"): ×
    ==
  ==
::
++  raw-code
  |=  [show=? raw=tape]
  ^-  marl
  ?.  show  ~
  [(raw-code-node raw)]~
::
++  raw-code-node
  |=  raw=tape
  ^-  manx
  ;code.meta: {raw}
::
++  resource-input
  |=  res=(unit resource)
  ^-  marl
  ?~  res  ~
  [(resource-input-node (trip u.res))]~
::
++  resource-input-node
  |=  url=tape
  ^-  manx
  ;input(type "hidden", name "resource", value "{url}");
::
++  last-scope-hint
  |=  scopes=(list scope)
  ^-  marl
  ?.  ?=([* ~] scopes)  ~
  :~  ;p.hint: Removing this scope ends the grant and revokes its tokens for this resource.
  ==
::
++  tokens-matching
  |=  [cid=client-id res=(unit resource) rows=(list token-info)]
  ^-  (list token-info)
  %+  skim  rows
  |=  t=token-info
  ?&  =(client.t cid)
      =(resource.t res)
  ==
::
++  live-tokens
  |=  [now=@da rows=(list token-info)]
  ^-  (list token-info)
  %+  skim  rows
  |=  t=token-info
  (gth expires.t now)
::
++  token-before
  |=  [a=token-info b=token-info]
  ^-  ?
  ?:  =(expires.a expires.b)  (aor id-prefix.a id-prefix.b)
  (aor expires.a expires.b)
::
++  token-group
  |=  [title=tape kind=?(%access %refresh) rows=(list token-info) copies=(map resource scope-copy)]
  ^-  marl
  =/  head  [(token-head title)]~
  ?:  =(~ rows)
    =/  empty=marl
      :~  ;p.meta: No tokens.
      ==
    (weld head empty)
  (weld head (turn (sort rows token-before) |=(t=token-info (token-row kind t copies))))
::
++  token-head
  |=  title=tape
  ^-  manx
  ;h4: {title}
::
++  token-row
  |=  [kind=?(%access %refresh) t=token-info copies=(map resource scope-copy)]
  ^-  manx
  =/  pre  (trip id-prefix.t)
  =/  when  (fmt-da expires.t)
  =/  action=tape
    ?:  ?=(%access kind)  "revoke-access"
    "revoke-refresh"
  =/  hint
    ?:  ?=(%access kind)
      (weld "Revoke access token " pre)
    (weld "Revoke refresh token " pre)
  =/  scopes  (join-labels scopes.t resource.t copies)
  ;div.row
    ;div.stack
      ;code: {pre}
      ;span.meta: {when}
      ;p.meta: {scopes}
    ==
    ;form(method "post", action "/wicket/manage")
      ;input(type "hidden", name "action", value "{action}");
      ;input(type "hidden", name "token", value "{pre}");
      ;button.icon(type "submit", aria-label "{hint}", title "{hint}"): ×
    ==
  ==
::
++  token-hint
  |=  [acc=(list token-info) ref=(list token-info)]
  ^-  marl
  ?:  &(?=(~ acc) ?=(~ ref))  ~
  :~  ;p.hint: Revoking an access token leaves the grant. Revoking a refresh token ends that session and leaves the grant.
  ==
::
++  other-tokens
  |=  [c=client gs=(list authorization) v=manage-view]
  ^-  marl
  =/  known  (silt (turn gs |=(a=authorization resource.a)))
  =/  stray
    |=  rows=(list token-info)
    ^-  (list token-info)
    %+  skip  rows
    |=  t=token-info
    ?|  !=(client.t id.c)
        (~(has in known) resource.t)
    ==
  =/  acc  (live-tokens now.v (stray access.v))
  =/  ref  (live-tokens now.v (stray refresh.v))
  ?:  &(?=(~ acc) ?=(~ ref))  ~
  ;:  welp
    :~  ;h4: Other tokens
    ==
    (filled-tokens "Access" %access acc copies.v)
    (filled-tokens "Refresh" %refresh ref copies.v)
  ==
::
++  filled-tokens
  |=  [title=tape kind=?(%access %refresh) rows=(list token-info) copies=(map resource scope-copy)]
  ^-  marl
  ?~  rows  ~
  (token-group title kind rows copies)
::
++  resource-before
  |=  [a=registered-resource b=registered-resource]
  ^-  ?
  (aor url.a url.b)
::
++  resource-section
  |=  [rs=(list registered-resource) copies=(map resource scope-copy)]
  ^-  marl
  =/  rows  (sort rs resource-before)
  =/  body=marl
    ?:  =(~ rows)
      :~  ;p.muted: No resource servers are registered.
      ==
    (turn rows |=(r=registered-resource (resource-row r copies)))
  (weld [(heading-node "Resource servers")]~ body)
::
++  resource-row
  |=  [r=registered-resource copies=(map resource scope-copy)]
  ^-  manx
  =/  url  (trip url.r)
  =/  who  (trip agent.r)
  =/  nam  (reg-name r copies)
  ;details.resource
    ;summary
      ;span.name: {nam}
      ;p.url: {url}
    ==
    ;div.body
      ;p.meta: Agent {who}
      ;*  (reg-audience r)
      ;*  (resource-scopes r copies)
    ==
  ==
::
++  reg-name
  |=  [r=registered-resource copies=(map resource scope-copy)]
  ^-  tape
  =/  c  (copy-of `url.r copies)
  ?:  !=('' title.c)  (trip title.c)
  =/  lab  (resource-label `url.r)
  ?:  =(lab (trip url.r))  (trip agent.r)
  lab
::
++  reg-audience
  |=  r=registered-resource
  ^-  marl
  ?:  =(audience.r url.r)  ~
  =/  aud  (trip audience.r)
  :~  ;p.meta: Audience {aud}
  ==
::
++  resource-scopes
  |=  [r=registered-resource copies=(map resource scope-copy)]
  ^-  marl
  =/  res  `url.r
  =/  rows  (order-scopes ~(tap in scopes.r) res copies)
  =/  extra  (order-scopes (extra-scopes url.r scopes.r copies) res copies)
  ?:  &(?=(~ rows) ?=(~ extra))
    :~  ;p.meta: No scopes.
    ==
  (weld (scope-list rows res copies) (unregistered-scopes extra res copies))
::
++  order-scopes
  |=  [rows=(list scope) res=(unit resource) copies=(map resource scope-copy)]
  ^-  (list scope)
  %+  sort  rows
  |=  [a=scope b=scope]
  ^-  ?
  =/  wa  (care-of a res copies)
  =/  wb  (care-of b res copies)
  ?:  =((care-rank wa) (care-rank wb))
    (aor a b)
  (lth (care-rank wa) (care-rank wb))
::
++  extra-scopes
  |=  [url=resource have=(set scope) copies=(map resource scope-copy)]
  ^-  (list scope)
  =/  notes  notes:(copy-of `url copies)
  %+  skip  ~(tap in ~(key by notes))
  |=(s=scope (~(has in have) s))
::
++  scope-list
  |=  [rows=(list scope) res=(unit resource) copies=(map resource scope-copy)]
  ^-  marl
  ?~  rows  ~
  :~  ;ul.reg
        ;*  (turn rows |=(s=scope (scope-reg s res copies)))
      ==
  ==
::
++  unregistered-scopes
  |=  [rows=(list scope) res=(unit resource) copies=(map resource scope-copy)]
  ^-  marl
  ?~  rows  ~
  :~  ;h4: Not registered
      ;ul.reg
        ;*  (turn rows |=(s=scope (scope-reg s res copies)))
      ==
  ==
::
++  scope-reg
  |=  [s=scope res=(unit resource) copies=(map resource scope-copy)]
  ^-  manx
  =/  lab  (label-of s res copies)
  =/  raw  (trip s)
  =/  c  (care-of s res copies)
  ?:  (hold-care c)
    ;li.reg.warn
      ;*  (scope-reg-body raw lab c)
    ==
  ;li.reg
    ;*  (scope-reg-body raw lab c)
  ==
::
++  scope-reg-body
  |=  [raw=tape lab=tape c=care]
  ^-  marl
  :~  (scope-head raw c)
      ;p.desc: {lab}
  ==
::
++  scope-head
  |=  [raw=tape c=care]
  ^-  manx
  ;div.scope-head
    ;code: {raw}
    ;*  (scope-flag c)
  ==
::
++  scope-flag
  |=  c=care
  ^-  marl
  ?.  (ship-care c)  ~
  :~  ;span.flag: Controls the ship
  ==
::
++  revoke-client-page
  |=  [who=client grants=@ud tokens=@ud]
  ^-  manx
  =/  nam  (client-name who)
  =/  cid  (trip id.who)
  =/  heading  :(weld "Revoke " nam "?")
  =/  line
    :(weld "This will delete " (scow %ud grants) " grants and " (scow %ud tokens) " tokens.")
  =/  back  (manage-href ~ `id.who)
  %-  page
  :-  "Wicket — revoke client"
  :~  ;main.card
        ;p.wordmark: Wicket
        ;h1: {heading}
        ;p.lede: Revoking this client deletes it, along with its grants and every token. You cannot undo that from this page.
        ;p.meta
          ;code: {cid}
        ==
        ;p: {line}
        ;form(method "post", action "/wicket/manage")
          ;input(type "hidden", name "action", value "revoke-client");
          ;input(type "hidden", name "client", value "{cid}");
          ;div.actions
            ;button(type "submit"): Revoke client
          ==
        ==
        ;p.alt
          ;a(href "{back}"): Cancel
        ==
      ==
  ==
::
++  manage-error
  |=  msg=tape
  ^-  manx
  %-  page
  :-  "Wicket"
  :~  ;main.card
        ;p.wordmark: Wicket
        ;h1: {msg}
        ;p.alt
          ;a(href "/wicket/manage"): Back to clients
        ==
      ==
  ==
::
+$  log-kind  ?(%registration %authorization %revocation %tokens)
::
++  log-filter
  |=  raw=(unit @t)
  ^-  (unit log-kind)
  ?:  ?=(~ raw)  ~
  ?+  u.raw  ~
    %'registration'    `%registration
    %'authorization'   `%authorization
    %'revocation'      `%revocation
    %'tokens'          `%tokens
  ==
::
++  kind-tape
  |=  k=log-kind
  ^-  tape
  ?-  k
    %registration    "registration"
    %authorization   "authorization"
    %revocation      "revocation"
    %tokens          "tokens"
  ==
::
++  body-kind
  |=  b=log-body:wicket
  ^-  log-kind
  ?-  -.b
    %registered      %registration
    %authorized      %authorization
    %revoked-scopes  %revocation
    %revoked-client  %revocation
    %issued          %tokens
    %revoked-token   %tokens
  ==
::
++  shown-events
  |=  [events=(list log-event:wicket) kind=(unit log-kind)]
  ^-  (list log-event:wicket)
  ?:  ?=(~ kind)  events
  =/  want  u.kind
  %+  skim  events
  |=  e=log-event:wicket
  =(want (body-kind body.e))
::
++  log-page
  |=  [our=@p events=(list log-event:wicket) kind=(unit log-kind)]
  ^-  manx
  %-  page
  :-  "Wicket — log"
  :~  (log-main our events kind)
  ==
::
++  log-main
  |=  [our=@p events=(list log-event:wicket) kind=(unit log-kind)]
  ^-  manx
  =/  heading  (weld "Log on " (scow %p our))
  =/  shown  (shown-events events kind)
  ;main.board
    ;p.wordmark: Wicket
    ;h1: {heading}
    ;p.lede: Registration, approval, revocation, and tokens. A token's expiry is recorded on the row that issued it.
    ;*  ~[(filter-bar kind)]
    ;*  (log-cards shown events)
    ;p.alt
      ;a(href "/wicket/manage"): Clients
    ==
  ==
::
++  log-cards
  |=  [shown=(list log-event:wicket) events=(list log-event:wicket)]
  ^-  marl
  ?:  ?=(^ shown)  (turn shown event-card)
  ?:  =(~ events)
    :~  ;p.muted: No events yet.
    ==
  :~  ;p.muted: No events of this kind.
  ==
::
++  filter-bar
  |=  cur=(unit log-kind)
  ^-  manx
  ;p.filters
    ;*  (filter-link ~ "All" cur)
    ;*  (filter-link `%registration "Registration" cur)
    ;*  (filter-link `%authorization "Authorization" cur)
    ;*  (filter-link `%revocation "Revocation" cur)
    ;*  (filter-link `%tokens "Tokens" cur)
  ==
::
++  filter-link
  |=  [kind=(unit log-kind) label=tape cur=(unit log-kind)]
  ^-  marl
  ?:  =(kind cur)
    :~  ;strong: {label}
    ==
  =/  href=tape
    ?:  ?=(~ kind)  "/wicket/manage/log"
    (weld "/wicket/manage/log?kind=" (kind-tape u.kind))
  :~  ;a(href "{href}"): {label}
  ==
::
++  event-card
  |=  e=log-event:wicket
  ^-  manx
  ;details.event
    ;summary
      ;span.what: {(event-summary e)}
    ==
    ;div.body
      ;*  (event-fields body.e)
    ==
  ==
::
++  event-summary
  |=  e=log-event:wicket
  ^-  tape
  (weld (fmt-da when.e) (weld " · " (summary-rest body.e)))
::
++  summary-rest
  |=  b=log-body:wicket
  ^-  tape
  ?-  -.b
    %registered      (weld "Registered · " (client-name client.b))
    %authorized      (summary-authorized b)
    %revoked-scopes  (summary-scopes b)
    %revoked-client  (summary-client b)
    %issued          (summary-issued b)
    %revoked-token   (summary-revoked b)
  ==
::
++  summary-authorized
  |=  b=log-body:wicket
  ?>  ?=(%authorized -.b)
  ^-  tape
  =/  who  (shown-name name.b client.b)
  =/  res  (resource-label resource.b)
  ?:  ?=(%deny decision.b)
    :(weld "Denied · " who " · " res)
  :(weld "Approved · " who " · " res " · " (join-mid ", " (turn granted.b trip)))
::
++  summary-scopes
  |=  b=log-body:wicket
  ?>  ?=(%revoked-scopes -.b)
  ^-  tape
  :(weld "Removed scope · " (shown-name name.b client.b) " · " (join-mid ", " (turn dropped.b trip)))
::
++  summary-client
  |=  b=log-body:wicket
  ?>  ?=(%revoked-client -.b)
  ^-  tape
  ?:  ?=(%sweep via.b)
    :(weld "Removed client · " (client-name client.b) " · not approved")
  (weld "Revoked client · " (client-name client.b))
::
++  summary-issued
  |=  b=log-body:wicket
  ?>  ?=(%issued -.b)
  ^-  tape
  :(weld "Issued tokens · " (shown-name name.b client.b) " · access expires " (fmt-da expires.access.b))
::
++  summary-revoked
  |=  b=log-body:wicket
  ?>  ?=(%revoked-token -.b)
  ^-  tape
  =/  kindt=tape
    ?:  ?=(%access kind.token.b)  "access"
    "refresh"
  :(weld "Revoked " kindt " token · " (shown-name name.b client.token.b) " · expires " (fmt-da expires.token.b))
::
++  event-fields
  |=  b=log-body:wicket
  ^-  marl
  ?-  -.b
    %registered      (fields-registered b)
    %authorized      (fields-authorized b)
    %revoked-scopes  (fields-scopes b)
    %revoked-client  (fields-client b)
    %issued          (fields-issued b)
    %revoked-token   (fields-token b)
  ==
::
++  shown-name
  |=  [name=@t cid=client-id]
  ^-  tape
  (trip ?:(=('' name) cid name))
::
++  yes-no
  |=  f=?
  ^-  tape
  ?:  f  "Yes"
  "No"
::
++  via-label
  |=  v=log-via:wicket
  ^-  tape
  ?-  v
    %page      "Owner page"
    %poke      "Local action"
    %endpoint  "Revocation endpoint"
    %sweep     "Not approved within 24 hours"
  ==
::
++  kind-name
  |=  k=?(%access %refresh)
  ^-  tape
  ?:  ?=(%access k)  "Access"
  "Refresh"
::
++  log-field
  |=  [label=tape value=tape]
  ^-  manx
  ;div.row
    ;span.k: {label}
    ;span.v: {value}
  ==
::
++  log-code
  |=  [label=tape value=tape]
  ^-  manx
  ;div.row
    ;span.k: {label}
    ;code: {value}
  ==
::
++  cord-item
  |=  c=@t
  ^-  manx
  ;li.reg
    ;code: {(trip c)}
  ==
::
++  cord-marl
  |=  [title=tape rows=(list @t)]
  ^-  marl
  ?:  =(~ rows)
    ~[(log-field title "None")]
  :~
    ;h4: {title}
    ;ul.reg
      ;*  (turn rows cord-item)
    ==
  ==
::
++  unit-scopes
  |=  [title=tape rows=(unit (list scope))]
  ^-  marl
  ?:  ?=(~ rows)
    ~[(log-field title "None")]
  (cord-marl title u.rows)
::
++  token-marl
  |=  t=logged-token:wicket
  ^-  marl
  :~
    (log-field "Kind" (kind-name kind.t))
    (log-code "Token" (trip prefix.t))
    (log-code "Client id" (trip client.t))
    (log-code "Resource" (resource-url resource.t))
    (log-field "Expires" (fmt-da expires.t))
  ==
::
++  token-card
  |=  t=logged-token:wicket
  ^-  manx
  ;div.token
    ;*  (token-marl t)
    ;*  (cord-marl "Scopes" scopes.t)
  ==
::
++  token-list
  |=  [title=tape rows=(list logged-token:wicket)]
  ^-  marl
  ?:  =(~ rows)  ~[(log-field title "None")]
  :-  ;h4: {title}
  (turn rows token-card)
::
++  next-scopes
  |=  next=(unit (list scope))
  ^-  marl
  ?:  ?=(~ next)
    ~[(log-field "Scopes after" "Removed")]
  (cord-marl "Scopes after" u.next)
::
++  edit-block
  |=  e=token-edit:wicket
  ^-  manx
  ;div.token
    ;*  (token-marl token.e)
    ;*  (cord-marl "Scopes before" scopes.token.e)
    ;*  (next-scopes next.e)
  ==
::
++  edit-marl
  |=  [title=tape rows=(list token-edit:wicket)]
  ^-  marl
  ?:  =(~ rows)  ~[(log-field title "None")]
  :-  ;h4: {title}
  (turn rows edit-block)
::
++  after-grant
  |=  after=(list scope)
  ^-  marl
  ?:  =(~ after)
    ~[(log-field "Grant" "Removed")]
  (cord-marl "Scopes remaining" after)
::
++  grant-card
  |=  a=authorization
  ^-  manx
  =/  head=marl
    :~
      (log-code "Resource" (resource-url resource.a))
      (log-field "Updated" (fmt-da updated.a))
    ==
  ;div.token
    ;*  head
    ;*  (cord-marl "Scopes" scopes.a)
  ==
::
++  grant-marl
  |=  rows=(list authorization)
  ^-  marl
  ?:  =(~ rows)  ~[(log-field "Grants" "None")]
  :-  ;h4: Grants
  (turn rows grant-card)
::
++  pending-card
  |=  a=authz
  ^-  manx
  =/  head=marl
    :~
      (log-code "Pending id" (scow %uv id.a))
      (log-code "Redirect URI" (trip redirect.a))
      (log-code "State" (trip state.a))
      (log-code "PKCE challenge" (trip challenge.a))
      (log-code "Resource" (resource-url resource.a))
      (log-field "Expires" (fmt-da expires.a))
    ==
  ;div.token
    ;*  head
    ;*  (cord-marl "Requested scopes" scopes.a)
  ==
::
++  pending-marl
  |=  rows=(list authz)
  ^-  marl
  ?:  =(~ rows)  ~[(log-field "Pending requests" "None")]
  :-  ;h4: Pending requests
  (turn rows pending-card)
::
++  code-card
  |=  c=code
  ^-  manx
  =/  head=marl
    :~
      (log-code "Code" (trip prefix.c))
      (log-code "Redirect URI" (trip redirect.c))
      (log-code "PKCE challenge" (trip challenge.c))
      (log-code "Resource" (resource-url resource.c))
      (log-field "Expires" (fmt-da expires.c))
      (log-field "Used" (yes-no used.c))
    ==
  ;div.token
    ;*  head
    ;*  (cord-marl "Scopes" scopes.c)
  ==
::
++  code-list
  |=  rows=(list code)
  ^-  marl
  ?:  =(~ rows)  ~[(log-field "Codes" "None")]
  :-  ;h4: Codes
  (turn rows code-card)
::
++  code-marl
  |=  c=(unit [id=@t expires=@da])
  ^-  marl
  ?:  ?=(~ c)  ~
  :~
    (log-code "Code" (trip id.u.c))
    (log-field "Code expires" (fmt-da expires.u.c))
  ==
::
++  redeemed-marl
  |=  r=redeemed:wicket
  ^-  marl
  ?:  ?=(%code -.r)
    :~
      (log-code "Code" (trip id.r))
      (log-field "Code expires" (fmt-da expires.r))
      (log-code "Redirect URI" (trip redirect.r))
      (log-code "PKCE challenge" (trip challenge.r))
    ==
  :~
    ;h4: Replaced refresh token
    (log-code "Token" (trip id.r))
    (log-field "Expires" (fmt-da expires.r))
  ==
::
++  fields-registered
  |=  b=log-body:wicket
  ?>  ?=(%registered -.b)
  ^-  marl
  ;:  welp
    ~[(log-code "Client id" (trip id.client.b))]
    ~[(log-field "Name" (client-name client.b))]
    (cord-marl "Redirect URIs" (sort ~(tap in redirect-uris.client.b) aor))
    (cord-marl "Grant types" grants.b)
    ~[(log-code "Token endpoint auth method" (trip auth.b))]
    ~[(log-field "Address" (render-address:wicket who.b))]
    ~[(log-field "Created" (fmt-da created.client.b))]
  ==
::
++  fields-authorized
  |=  b=log-body:wicket
  ?>  ?=(%authorized -.b)
  ^-  marl
  ;:  welp
    ~[(log-field "Decision" ?:(?=(%approve decision.b) "Approved" "Denied"))]
    ~[(log-code "Client id" (trip client.b))]
    ~[(log-field "Name" (shown-name name.b client.b))]
    ~[(log-code "Resource" (resource-url resource.b))]
    ~[(log-code "Redirect URI" (trip redirect.b))]
    ~[(log-code "State" (trip oauth-state.b))]
    ~[(log-code "PKCE challenge" (trip challenge.b))]
    (cord-marl "Requested scopes" requested.b)
    (approve-extra b)
    ~[(log-code "Pending id" (scow %uv pending-id.b))]
    ~[(log-field "Pending expires" (fmt-da pending-expires.b))]
  ==
::
++  approve-extra
  |=  b=log-body:wicket
  ?>  ?=(%authorized -.b)
  ^-  marl
  ?:  ?=(%deny decision.b)  ~
  ;:  welp
    (cord-marl "Scopes granted" granted.b)
    (unit-scopes "Previous scopes" previous.b)
    (code-marl code.b)
    ~[(log-field "First approval" (yes-no first.b))]
    (edit-marl "Tokens changed" edits.b)
  ==
::
++  fields-scopes
  |=  b=log-body:wicket
  ?>  ?=(%revoked-scopes -.b)
  ^-  marl
  ;:  welp
    ~[(log-field "Channel" (via-label via.b))]
    ~[(log-code "Client id" (trip client.b))]
    ~[(log-field "Name" (shown-name name.b client.b))]
    ~[(log-code "Resource" (resource-url resource.b))]
    (cord-marl "Scopes removed" dropped.b)
    (cord-marl "Scopes before" before.b)
    (after-grant after.b)
    (edit-marl "Tokens changed" edits.b)
  ==
::
++  fields-client
  |=  b=log-body:wicket
  ?>  ?=(%revoked-client -.b)
  ^-  marl
  ;:  welp
    ~[(log-field "Channel" (via-label via.b))]
    ~[(log-code "Client id" (trip id.client.b))]
    ~[(log-field "Name" (client-name client.b))]
    (cord-marl "Redirect URIs" (sort ~(tap in redirect-uris.client.b) aor))
    ~[(log-field "Created" (fmt-da created.client.b))]
    ~[(log-field "Approved" (yes-no approved.b))]
    (grant-marl grants.b)
    (token-list "Tokens" tokens.b)
    (pending-marl pending.b)
    (code-list codes.b)
  ==
::
++  fields-issued
  |=  b=log-body:wicket
  ?>  ?=(%issued -.b)
  ^-  marl
  =/  how=tape
    ?:  ?=(%code -.redeemed.b)  "Authorization code"
    "Refresh token"
  ;:  welp
    ~[(log-field "Grant" how)]
    ~[(log-code "Client id" (trip client.b))]
    ~[(log-field "Name" (shown-name name.b client.b))]
    ~[(log-code "Resource" (resource-url resource.b))]
    (cord-marl "Scopes" scopes.b)
    (token-list "Access token" ~[access.b])
    (token-list "Refresh token" ~[refresh.b])
    (redeemed-marl redeemed.b)
  ==
::
++  fields-token
  |=  b=log-body:wicket
  ?>  ?=(%revoked-token -.b)
  ^-  marl
  ;:  welp
    ~[(log-field "Channel" (via-label via.b))]
    ~[(log-field "Name" (shown-name name.b client.token.b))]
    (token-marl token.b)
    (cord-marl "Scopes" scopes.token.b)
  ==
--
