::  %keeper: management MCP for the %wicket authorization server
::
::    Lists and revokes clients, access tokens, and refresh tokens,
::    and drops scopes already granted. It cannot grant or add a scope.
::
/-  *wicket
/+  default-agent, dbug, server
/+  wicket, wicket-http, wicket-check
|%
+$  card  card:agent:gall
+$  inflight
  $:  id=json
      tool=@t
  ==
+$  versioned-state
  $:  %0
      wait=(map @ta inflight)
  ==
++  keeper-scopes
  ^-  (list scope)
  :~  'wicket.clients.read'
      'wicket.clients.revoke'
      'wicket.tokens.read'
      'wicket.tokens.revoke'
      'wicket.grants.read'
      'wicket.grants.drop'
  ==
++  protocol  %'2025-11-25'
::
++  str-schema
  ^-  json
  (pairs:enjs:format ~[['type' s+'string']])
::
++  schema
  |=  [props=(list [p=@t q=json]) req=(list @t)]
  ^-  json
  %-  pairs:enjs:format
  :~  ['type' s+'object']
      ['properties' [%o (malt props)]]
      ['required' a+(turn req |=(r=@t [%s r]))]
      ['additionalProperties' b+|]
  ==
::
++  empty-schema  (schema ~ ~)
::
++  tool-json
  |=  [name=@t desc=@t sch=json]
  ^-  json
  %-  pairs:enjs:format
  :~  ['name' s+name]
      ['description' s+desc]
      ['inputSchema' sch]
  ==
::
++  catalog
  ^-  (list [@t @t @t json])
  :~  :-  'list-clients'
      :*  'List OAuth clients registered with this authorization server.'
          'wicket.clients.read'
          empty-schema
      ==
      :-  'revoke-client'
      :*  'Delete an OAuth client and its tokens and grants.'
          'wicket.clients.revoke'
          (schema ~[['client_id' str-schema]] ~['client_id'])
      ==
      :-  'list-access-tokens'
      :*  'List access tokens. Secrets are not returned; id_prefix is the first 8 characters.'
          'wicket.tokens.read'
          (schema ~[['client_id' str-schema]] ~)
      ==
      :-  'list-refresh-tokens'
      :*  'List refresh tokens. Secrets are not returned; id_prefix is the first 8 characters.'
          'wicket.tokens.read'
          (schema ~[['client_id' str-schema]] ~)
      ==
      :-  'revoke-access-token'
      :*  'Revoke one access token. id_prefix is the first 8 characters and must match one token.'
          'wicket.tokens.revoke'
          (schema ~[['id_prefix' str-schema]] ~['id_prefix'])
      ==
      :-  'revoke-refresh-token'
      :*  'Revoke one refresh token. id_prefix is the first 8 characters and must match one token.'
          'wicket.tokens.revoke'
          (schema ~[['id_prefix' str-schema]] ~['id_prefix'])
      ==
      :-  'list-grants'
      :*  'List scopes granted to clients.'
          'wicket.grants.read'
          (schema ~[['client_id' str-schema]] ~)
      ==
      :-  'drop-scopes'
      :*  'Remove scopes already granted. Scopes that were not granted are rejected. This cannot add a scope.'
          'wicket.grants.drop'
          %-  schema
          :-  :~  ['client_id' str-schema]
                  ['resource' str-schema]
                  :-  'scopes'
                  %-  pairs:enjs:format
                  :~  ['type' s+'array']
                      ['items' str-schema]
                  ==
              ==
          ~['client_id' 'resource' 'scopes']
      ==
  ==
::
++  scope-of
  |=  name=@t
  ^-  (unit @t)
  =/  cat  catalog
  |-
  ?~  cat  ~
  ?:  =(name -.i.cat)  `+>-.i.cat
  $(cat t.cat)
::
++  cors
  ^-  header-list:http
  :~  ['access-control-allow-origin' '*']
      ['access-control-allow-headers' 'Authorization, Content-Type, MCP-Protocol-Version, Accept']
      ['access-control-allow-methods' 'POST, OPTIONS']
      ['access-control-max-age' '86400']
  ==
::
++  json-pay
  |=  [code=@ud jon=json extra=header-list:http]
  ^-  simple-payload:http
  :-  :-  code
      :(weld cors extra ['content-type' 'application/json']~)
  `(json-to-octs:server jon)
::
++  rpc-ok
  |=  [id=json result=json]
  ^-  json
  %-  pairs:enjs:format
  :~  ['jsonrpc' s+'2.0']
      ['id' id]
      ['result' result]
  ==
::
++  rpc-err
  |=  [id=json code=@t msg=@t]
  ^-  json
  %-  pairs:enjs:format
  :~  ['jsonrpc' s+'2.0']
      ['id' id]
      :-  'error'
      %-  pairs:enjs:format
      :~  ['code' n+code]
          ['message' s+msg]
      ==
  ==
::
++  text-result
  |=  text=@t
  ^-  json
  %-  pairs:enjs:format
  :~  :-  'content'
      :-  %a
      :~  %-  pairs:enjs:format
          :~  ['type' s+'text']
              ['text' s+text]
          ==
      ==
      ['isError' b+|]
  ==
::
++  joget
  |=  [jon=json key=@t]
  ^-  (unit json)
  ?.  ?=([%o *] jon)  ~
  (~(get by p.jon) key)
::
++  work
|_  [=bowl:gall wait=(map @ta inflight)]
+*  our  our.bowl
    now  now.bowl
::
++  bind
  ^-  card
  [%pass /eyre/connect %arvo %e %connect [~ /wicket/mcp] dap.bowl]
::
::  +ask-register: poke ourselves once init has returned. A scry from
::  +on-init runs while Gall is still starting the desk and crashes |install.
::
++  ask-register
  ^-  card
  [%pass /register %agent [our dap.bowl] %poke %noun !>(~)]
::
++  start
  ^-  (list card)
  ~[bind ask-register]
::
++  retry
  ^-  card
  [%pass /retry %arvo %b %wait (add now ~s5)]
::
++  try-register
  ^-  (list card)
  =/  reg  register-card
  ?~  reg  ~[retry]
  ~[u.reg]
::
++  origin-now
  ^-  (unit @t)
  =/  run
    %-  mule
    |.  .^(@t %gx /(scot %p our)/wicket/(scot %da now)/origin/noun)
  ?:  ?=(%| -.run)  ~
  ?:  =('' p.run)  ~
  `p.run
::
++  register-card
  ^-  (unit card)
  =/  org  origin-now
  ?~  org  ~
  =/  url  (cat 3 u.org '/wicket/mcp')
  =/  rec=registered-resource
    [url %keeper (silt keeper-scopes) url]
  :-  ~
  [%pass /wicket/reg %agent [our %wicket] %poke %wicket-action !>([%register-resource rec])]
::
++  audience
  |=  org=@t
  (cat 3 org '/wicket/mcp')
::
++  meta
  |=  org=@t
  (prm-url:wicket org (audience org))
::
++  gx-grant
  |=  tok=@t
  ^-  (unit (unit grant))
  =/  run
    %-  mule
    |.
    .^  (unit grant)
      %gx
      /(scot %p our)/wicket/(scot %da now)/grant/(scot %t tok)/noun
    ==
  ?:(?=(%| -.run) ~ `p.run)
::
++  scry-clients
  ^-  (unit (list client))
  =/  run
    %-  mule
    |.  .^((list client) %gx /(scot %p our)/wicket/(scot %da now)/clients/noun)
  ?:(?=(%| -.run) ~ `p.run)
::
++  scry-tokens
  |=  kind=?(%access %refresh)
  ^-  (unit (list token-info))
  =/  run
    %-  mule
    |.
    ?:  ?=(%access kind)
      .^((list token-info) %gx /(scot %p our)/wicket/(scot %da now)/access/noun)
    .^((list token-info) %gx /(scot %p our)/wicket/(scot %da now)/refresh/noun)
  ?:(?=(%| -.run) ~ `p.run)
::
++  scry-grants
  ^-  (unit (list authorization))
  =/  run
    %-  mule
    |.  .^((list authorization) %gx /(scot %p our)/wicket/(scot %da now)/grants/noun)
  ?:(?=(%| -.run) ~ `p.run)
::
++  handle
  |=  [eyre-id=@ta req=inbound-request:eyre]
  ^-  (quip card _wait)
  =/  request  request.req
  ?:  =(%'OPTIONS' method.request)
    [(give eyre-id [[204 cors] ~]) wait]
  =/  org  origin-now
  ?~  org
    [(give eyre-id (json-pay 503 (pairs:enjs:format ['error' s+'origin_unset']~) ~)) wait]
  =/  who  (admit req u.org)
  ?-    -.who
      %down
    [(give eyre-id (json-pay 503 (pairs:enjs:format ['error' s+'wicket_down']~) ~)) wait]
  ::
      %no
    =/  pay  (bearer-401:wicket-http (meta u.org))
    [(give eyre-id (cors-on pay)) wait]
  ::
      %yes
    ?.  =(%'POST' method.request)
      [(give eyre-id (json-pay 405 (pairs:enjs:format ['error' s+'method_not_allowed']~) ~[['allow' 'POST, OPTIONS']])) wait]
    =/  raw  (body-cord:wicket body.request)
    ?~  jon=(parse-json:wicket raw)
      [(give eyre-id (json-pay 400 (rpc-err ~ '-32700' 'parse error') ~)) wait]
    =/  method  (json-so:wicket u.jon 'method')
    ?~  method
      [(give eyre-id (json-pay 400 (rpc-err ~ '-32600' 'missing method') ~)) wait]
    =/  id  (fall (joget u.jon 'id') ~)
    ?:  ?|  =('notifications/initialized' u.method)
            =('notifications/cancelled' u.method)
        ==
      [(give eyre-id [[202 cors] ~]) wait]
    ?:  =('ping' u.method)
      [(give eyre-id (json-pay 200 (rpc-ok id [%o ~]) ~)) wait]
    ?:  =('initialize' u.method)
      [(give eyre-id (json-pay 200 (rpc-ok id initialize-result) ~)) wait]
    ?:  =('tools/list' u.method)
      [(give eyre-id (json-pay 200 (rpc-ok id (tools-result scopes.who)) ~)) wait]
    ?:  =('tools/call' u.method)
      (call-tool eyre-id id u.jon scopes.who u.org)
    [(give eyre-id (json-pay 200 (rpc-err id '-32601' 'method not found') ~)) wait]
  ==
::
++  cors-on
  |=  pay=simple-payload:http
  ^-  simple-payload:http
  pay(headers.response-header (weld cors headers.response-header.pay))
::
++  give
  |=  [eyre-id=@ta pay=simple-payload:http]
  ^-  (list card)
  (give-simple-payload:app:server eyre-id pay)
::
++  admit
  |=  [req=inbound-request:eyre org=@t]
  ^-  $%  [%down ~]
          [%no ~]
          [%yes scopes=(list scope)]
      ==
  ?:  ?&  authenticated.req
          =(src.bowl our.bowl)
      ==
    [%yes keeper-scopes]
  =/  tok  (bearer:wicket-check header-list.request.req)
  ?~  tok  [%no ~]
  =/  got  (gx-grant u.tok)
  ?~  got  [%down ~]
  ?~  u.got  [%no ~]
  ?.  =(`(audience org) resource.u.u.got)  [%no ~]
  [%yes scopes.u.u.got]
::
++  initialize-result
  ^-  json
  %-  pairs:enjs:format
  :~  ['protocolVersion' s+protocol]
      :-  'capabilities'
      %-  pairs:enjs:format
      :~  ['tools' (pairs:enjs:format ~[['listChanged' b+|]])]
      ==
      :-  'serverInfo'
      %-  pairs:enjs:format
      :~  ['name' s+'wicket-keeper']
          ['version' s+'0.1.0']
      ==
  ==
::
++  tools-result
  |=  have=(list scope)
  ^-  json
  =/  rows=(list json)
    %+  murn  catalog
    |=  [name=@t desc=@t sco=@t sch=json]
    ^-  (unit json)
    ?.  (lien have |=(s=scope =(s sco)))  ~
    `(tool-json name desc sch)
  (pairs:enjs:format ~[['tools' a+rows]])
::
++  call-tool
  |=  [eyre-id=@ta id=json jon=json have=(list scope) org=@t]
  ^-  (quip card _wait)
  =/  params  (fall (joget jon 'params') [%o ~])
  =/  name  (json-so:wicket params 'name')
  ?~  name
    [(give eyre-id (json-pay 200 (rpc-err id '-32602' 'missing tool name') ~)) wait]
  =/  sco  (scope-of u.name)
  ?~  sco
    [(give eyre-id (json-pay 200 (rpc-err id '-32602' 'unknown tool') ~)) wait]
  ?.  (lien have |=(s=scope =(s u.sco)))
    =/  pay  (bearer-403:wicket-http (meta org) u.sco)
    [(give eyre-id (cors-on pay)) wait]
  =/  args  (fall (joget params 'arguments') [%o ~])
  ?+    u.name
    [(give eyre-id (json-pay 200 (rpc-err id '-32602' 'unknown tool') ~)) wait]
  ::
      %'list-clients'
    (listed eyre-id id clients-json)
  ::
      %'list-access-tokens'
    (listed eyre-id id (tokens-json %access (json-so:wicket args 'client_id')))
  ::
      %'list-refresh-tokens'
    (listed eyre-id id (tokens-json %refresh (json-so:wicket args 'client_id')))
  ::
      %'list-grants'
    (listed eyre-id id (grants-json (json-so:wicket args 'client_id')))
  ::
      %'revoke-client'
    =/  cid  (json-so:wicket args 'client_id')
    ?~  cid
      [(give eyre-id (json-pay 200 (rpc-err id '-32602' 'client_id is required') ~)) wait]
    (defer eyre-id id u.name [%revoke-client u.cid])
  ::
      %'revoke-access-token'
    (revoke-one eyre-id id u.name %access args)
  ::
      %'revoke-refresh-token'
    (revoke-one eyre-id id u.name %refresh args)
  ::
      %'drop-scopes'
    (drop eyre-id id args)
  ==
::
++  listed
  |=  [eyre-id=@ta id=json jon=(unit json)]
  ^-  (quip card _wait)
  ?~  jon
    [(give eyre-id (json-pay 503 (pairs:enjs:format ['error' s+'wicket_down']~) ~)) wait]
  =/  text  (en:json:html u.jon)
  [(give eyre-id (json-pay 200 (rpc-ok id (text-result text)) ~)) wait]
::
++  defer
  |=  [eyre-id=@ta id=json tool=@t act=action]
  ^-  (quip card _wait)
  :_  (~(put by wait) eyre-id [id tool])
  :~  :*  %pass  /tool/[eyre-id]
          %agent  [our %wicket]
          %poke  %wicket-action
          !>(act)
      ==
  ==
::
++  revoke-one
  |=  [eyre-id=@ta id=json tool=@t kind=?(%access %refresh) args=json]
  ^-  (quip card _wait)
  =/  given  (json-so:wicket args 'id_prefix')
  ?~  given
    [(give eyre-id (json-pay 200 (rpc-err id '-32602' 'id_prefix is required') ~)) wait]
  =/  rows  (scry-tokens kind)
  ?~  rows
    [(give eyre-id (json-pay 503 (pairs:enjs:format ['error' s+'wicket_down']~) ~)) wait]
  =/  hit  (match-token:wicket u.given u.rows)
  ?~  hit
    [(give eyre-id (json-pay 200 (rpc-err id '-32602' 'token not found or not unique') ~)) wait]
  =/  act=action
    ?:  ?=(%access kind)
      [%revoke-access id-prefix.u.hit]
    [%revoke-refresh id-prefix.u.hit]
  (defer eyre-id id tool act)
::
++  drop
  |=  [eyre-id=@ta id=json args=json]
  ^-  (quip card _wait)
  =/  cid  (json-so:wicket args 'client_id')
  =/  res  (json-so:wicket args 'resource')
  =/  scs  (json-ar-so:wicket args 'scopes')
  ?:  |(?=(~ cid) ?=(~ res) ?=(~ scs) =(~ u.scs))
    [(give eyre-id (json-pay 200 (rpc-err id '-32602' 'client_id, resource, and scopes are required') ~)) wait]
  =/  rows  scry-grants
  ?~  rows
    [(give eyre-id (json-pay 503 (pairs:enjs:format ['error' s+'wicket_down']~) ~)) wait]
  =/  cur
    =/  as  u.rows
    |-  ^-  (unit authorization)
    ?~  as  ~
    ?:  ?&  =(client.i.as u.cid)
            =(`u.res resource.i.as)
        ==
      `i.as
    $(as t.as)
  ?~  cur
    [(give eyre-id (json-pay 200 (rpc-err id '-32602' 'unknown grant') ~)) wait]
  ?~  (without-scopes:wicket scopes.u.cur u.scs)
    [(give eyre-id (json-pay 200 (rpc-err id '-32602' 'scope is not granted') ~)) wait]
  (defer eyre-id id 'drop-scopes' [%drop-scopes u.cid `u.res u.scs])
::
++  clients-json
  ^-  (unit json)
  =/  rows  scry-clients
  ?~  rows  ~
  %-  some
  :-  %a
  %+  turn  u.rows
  |=  c=client
  %-  pairs:enjs:format
  :~  ['client_id' s+id.c]
      ['client_name' s+name.c]
      ['redirect_uris' a+(turn ~(tap in redirect-uris.c) |=(u=@t s+u))]
      ['created' s+(scot %da created.c)]
  ==
::
++  tokens-json
  |=  [kind=?(%access %refresh) filter=(unit @t)]
  ^-  (unit json)
  =/  rows  (scry-tokens kind)
  ?~  rows  ~
  =/  kept
    %+  skim  u.rows
    |=  t=token-info
    ?~(filter & =(client.t u.filter))
  %-  some
  :-  %a
  %+  turn  kept
  |=  t=token-info
  %-  pairs:enjs:format
  :~  ['id_prefix' s+id-prefix.t]
      ['client_id' s+client.t]
      ['resource' ?~(resource.t ~ s+u.resource.t)]
      ['scopes' a+(turn scopes.t |=(s=@t s+s))]
      ['expires' s+(scot %da expires.t)]
  ==
::
++  grants-json
  |=  filter=(unit @t)
  ^-  (unit json)
  =/  rows  scry-grants
  ?~  rows  ~
  =/  kept
    %+  skim  u.rows
    |=  a=authorization
    ?~(filter & =(client.a u.filter))
  %-  some
  :-  %a
  %+  turn  kept
  |=  a=authorization
  %-  pairs:enjs:format
  :~  ['client_id' s+client.a]
      ['resource' ?~(resource.a ~ s+u.resource.a)]
      ['scopes' a+(turn scopes.a |=(s=@t s+s))]
      ['updated' s+(scot %da updated.a)]
  ==
--
--
%-  agent:dbug
=|  versioned-state
=*  state  -
^-  agent:gall
|_  =bowl:gall
+*  this  .
    def   ~(. (default-agent this %.n) bowl)
    wrk   ~(. work [bowl wait])
::
++  on-init
  ^-  (quip card _this)
  [start:wrk this]
::
++  on-save  !>(state)
::
++  on-load
  |=  vaz=vase
  ^-  (quip card _this)
  =/  old  !<(versioned-state vaz)
  [start:wrk this(state old)]
::
++  on-poke
  |=  [=mark =vase]
  ^-  (quip card _this)
  ?+    mark  (on-poke:def mark vase)
      %noun
    ?>  =(src.bowl our.bowl)
    [try-register:wrk this]
  ::
      %handle-http-request
    =+  !<([eyre-id=@ta =inbound-request:eyre] vase)
    =^  caz  wait  (handle:wrk eyre-id inbound-request)
    [caz this]
  ==
::
++  on-watch
  |=  =path
  ^-  (quip card _this)
  ?:  ?=([%http-response *] path)  `this
  (on-watch:def path)
::
++  on-leave  on-leave:def
++  on-peek   on-peek:def
::
++  on-agent
  |=  [=wire =sign:agent:gall]
  ^-  (quip card _this)
  ?+    wire  (on-agent:def wire sign)
      [%register ~]
    ?.  ?=([%poke-ack *] sign)  (on-agent:def wire sign)
    `this
  ::
      [%wicket %reg ~]
    ?.  ?=([%poke-ack *] sign)  (on-agent:def wire sign)
    ?:  =(~ p.sign)  `this
    ~&  [%keeper %register-failed]
    [[retry:wrk]~ this]
  ::
      [%tool @ ~]
    ?.  ?=([%poke-ack *] sign)  (on-agent:def wire sign)
    =/  eid  i.t.wire
    =/  got  (~(get by wait) eid)
    ?~  got  `this
    =.  wait  (~(del by wait) eid)
    =/  jon
      ?:  =(~ p.sign)
        (rpc-ok id.u.got (text-result (cat 3 tool.u.got ' completed')))
      (rpc-err id.u.got '-32603' 'the authorization server rejected the change')
    :_  this
    (give-simple-payload:app:server eid (json-pay 200 jon ~))
  ==
::
++  on-arvo
  |=  [=wire sign=sign-arvo]
  ^-  (quip card _this)
  ?+    wire  (on-arvo:def wire sign)
      [%eyre %connect ~]
    ?.  ?=([%eyre %bound *] sign)  (on-arvo:def wire sign)
    ?:  accepted.sign  `this
    ~&  [%keeper %bind-failed binding.sign]
    `this
  ::
      [%retry ~]
    ?.  ?=([%behn %wake *] sign)  (on-arvo:def wire sign)
    ?^  error.sign  `this
    [try-register:wrk this]
  ==
::
++  on-fail  on-fail:def
--
