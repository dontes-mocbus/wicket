::  %wicket: ship-local OAuth 2.1 authorization server for MCP clients
::
::    A wicket is a small door in a larger gate. Earth MCP clients
::    (Grok connectors, Claude, OpenCode, Cursor, ChatGPT) complete
::    authorization-code + PKCE (S256) here, then call MCP HTTP
::    endpoints on the same origin. This agent owns discovery,
::    registration, authorize, token, revoke, and the token registry.
::    Resource agents (e.g. a later %larder) own MCP paths and scry
::    %wicket to check Bearer grants. Recipes are not stored here.
::
/-  *wicket
/+  default-agent, dbug, server
/+  wicket, wicket-http, wicket-html
::
|%
+$  card  card:agent:gall
+$  code     ^code
+$  access   ^access
+$  refresh  ^refresh
+$  versioned-state
  $:  %0
      origin=@t                    ::  public origin, no trailing slash
      clients=(map client-id client)
      resources=(map resource registered-resource)
      pending=(map @uv authz)
      codes=(map @ code)           ::  key is the hash of the code
      access=(map @ access)        ::  key is the hash of the bearer
      refresh=(map @ refresh)      ::  key is the hash of the bearer
      auths=(map [client-id (unit resource)] authorization)
      registration=?               ::  %.y opens dynamic client registration
      approved=(set client-id)     ::  owner has approved this client at least once
      denied=(set address:eyre)
      recent=rate-map:wicket       ::  accepted registrations in the current window
      sweep-at=(unit @da)
      copies=(map resource scope-copy)
      log=(list log-event:wicket)
  ==
++  work
  |_  [=bowl:gall state=versioned-state]
  +*  origin        origin.state
      clients       clients.state
      resources     resources.state
      pending       pending.state
      codes         codes.state
      access        access.state
      refresh       refresh.state
      auths         auths.state
      registration  registration.state
      approved      approved.state
      denied        denied.state
      recent        recent.state
      sweep-at      sweep-at.state
      copies        copies.state
      log           log.state
  ++  bind-eyre
    ^-  (list card)
    :~  :*  %pass  /eyre/connect/as
            %arvo  %e  %connect
            [~ /'.well-known'/oauth-authorization-server/wicket]
            dap.bowl
        ==
        :*  %pass  /eyre/connect/wicket
            %arvo  %e  %connect
            [~ /wicket]
            dap.bowl
        ==
    ==
  ::
  ++  poke-action
    |=  act=action
    ^-  (quip card _state)
    (apply-action %poke act)
  ::
  ++  apply-action
    |=  [via=log-via:wicket act=action]
    ^-  (quip card _state)
    ?-    -.act
        %set-origin
      =/  url  (chop-slash:wicket url.act)
      ~&  [%wicket %set-origin url]
      :_  state(origin url)
      :~  :*  %pass  /keeper/origin
              %agent  [our.bowl %keeper]
              %poke  %noun  !>(url)
          ==
      ==
    ::
        %set-registration
      `state(registration open.act)
    ::
        %deny-address
      `state(denied (~(put in denied) address.act))
    ::
        %allow-address
      `state(denied (~(del in denied) address.act))
    ::
        %register-resource
      =/  rec  registered-resource.act
      ?:  =('' origin)
        ~|  [%wicket %origin-unset]  !!
      ?:  !(on-origin:wicket origin url.rec)
        ~|  [%wicket %resource-off-origin url.rec origin]  !!
      ~&  %wicket-registered-resource
      `state(resources (~(put by resources) url.rec rec))
    ::
        %set-scope-copy
      ?:  =('' origin)
        ~|  [%wicket %origin-unset]  !!
      ?:  !(on-origin:wicket origin url.act)
        ~|  [%wicket %resource-off-origin url.act origin]  !!
      `state(copies (~(put by copies) url.act scope-copy.act))
    ::
        %unregister-resource
      `state(resources (~(del by resources) url.act), copies (~(del by copies) url.act))
    ::
        %revoke-client
      [~ (forget-client via id.act)]
    ::
        %revoke-access
      [~ (revoke-access-id via id.act)]
    ::
        %revoke-refresh
      [~ (revoke-refresh-id via id.act)]
    ::
        %drop-scopes
      (drop-scopes via client.act resource.act scopes.act)
    ==
  ::
  ++  drop-pending
    |=  cid=client-id
    %-  malt
    %+  skip  ~(tap by pending)
    |=  [* a=authz]
    =(client.a cid)
  ::
  ++  drop-codes
    |=  cid=client-id
    %-  malt
    %+  skip  ~(tap by codes)
    |=  [* c=^code]
    =(client.c cid)
  ::
  ++  drop-access
    |=  cid=client-id
    %-  malt
    %+  skip  ~(tap by access)
    |=  [* a=^access]
    =(client.a cid)
  ::
  ++  drop-refresh
    |=  cid=client-id
    %-  malt
    %+  skip  ~(tap by refresh)
    |=  [* r=^refresh]
    =(client.r cid)
  ::
  ++  drop-auths
    |=  cid=client-id
    %-  malt
    %+  skip  ~(tap by auths)
    |=  [[c=client-id *] *]
    =(c cid)
  ::
  ++  name-of
    |=  cid=client-id
    ^-  @t
    =/  c  (~(get by clients) cid)
    ?~  c  ''
    name.u.c
  ::
  ++  as-logged
    |=  $:  kind=?(%access %refresh)
            pre=@t
            client=client-id
            resource=(unit resource)
            scopes=(list scope)
            expires=@da
        ==
    ^-  logged-token:wicket
    [kind pre client resource scopes expires]
  ::
  ++  logged-access
    |=  pred=$-(^access ?)
    ^-  (list logged-token:wicket)
    %+  murn  ~(val by access)
    |=  a=^access
    ^-  (unit logged-token:wicket)
    ?.  (pred a)  ~
    `(as-logged %access prefix.a client.a resource.a scopes.a expires.a)
  ::
  ++  logged-refresh
    |=  pred=$-(^refresh ?)
    ^-  (list logged-token:wicket)
    %+  murn  ~(val by refresh)
    |=  r=^refresh
    ^-  (unit logged-token:wicket)
    ?.  (pred r)  ~
    `(as-logged %refresh prefix.r client.r resource.r scopes.r expires.r)
  ::
  ++  tokens-for
    |=  [cid=client-id res=(unit resource)]
    ^-  (list logged-token:wicket)
    =/  acc
      %-  logged-access
      |=  a=^access
      ?&  =(client.a cid)
          =(resource.a res)
      ==
    =/  ref
      %-  logged-refresh
      |=  r=^refresh
      ?&  =(client.r cid)
          =(resource.r res)
      ==
    (weld acc ref)
  ::
  ++  tokens-of-client
    |=  cid=client-id
    ^-  (list logged-token:wicket)
    %+  weld
      (logged-access |=(a=^access =(client.a cid)))
      (logged-refresh |=(r=^refresh =(client.r cid)))
  ::
  ++  grants-for
    |=  cid=client-id
    ^-  (list authorization)
    %+  skim  ~(val by auths)
    |=(a=authorization =(client.a cid))
  ::
  ++  pending-for
    |=  cid=client-id
    ^-  (list authz)
    %+  skim  ~(val by pending)
    |=(a=authz =(client.a cid))
  ::
  ++  codes-for
    |=  cid=client-id
    ^-  (list ^code)
    %+  skim  ~(val by codes)
    |=(c=^code =(client.c cid))
  ::
  ::  +resolve-secret: hash hit, else one prefix hit. ~ if none or several.
  ::
  ++  resolve-secret
    |=  [given=@t rows=(list [k=@ p=@t])]
    ^-  (unit @)
    =/  h  (secret-hash:wicket given)
    =/  hashed
      %+  skim  rows
      |=  row=[k=@ p=@t]
      =(k.row h)
    ?:  ?=(^ hashed)  `k.i.hashed
    =/  hits
      %+  skim  rows
      |=  row=[k=@ p=@t]
      =(p.row given)
    ?:  ?=(~ hits)  ~
    ?:  ?=(~ t.hits)  `k.i.hits
    ~
  ::
  ++  revoke-access-id
    |=  [via=log-via:wicket given=@t]
    ^-  _state
    =/  rows
      %+  turn  ~(tap by access)
      |=  [k=@ a=^access]
      [k prefix.a]
    =/  key  (resolve-secret given rows)
    ?:  ?=(~ key)  state
    =/  a  (~(got by access) u.key)
    =/  tok  (as-logged %access prefix.a client.a resource.a scopes.a expires.a)
    =/  body=log-body:wicket  [%revoked-token via (name-of client.tok) tok]
    %=  state
      access  (~(del by access) u.key)
      log     [[now.bowl body] log]
    ==
  ::
  ++  revoke-refresh-id
    |=  [via=log-via:wicket given=@t]
    ^-  _state
    =/  rows
      %+  turn  ~(tap by refresh)
      |=  [k=@ r=^refresh]
      [k prefix.r]
    =/  key  (resolve-secret given rows)
    ?:  ?=(~ key)  state
    =/  r  (~(got by refresh) u.key)
    =/  tok  (as-logged %refresh prefix.r client.r resource.r scopes.r expires.r)
    =/  body=log-body:wicket  [%revoked-token via (name-of client.tok) tok]
    %=  state
      refresh  (~(del by refresh) u.key)
      log      [[now.bowl body] log]
    ==
  ::
  ++  forget-client
    |=  [via=log-via:wicket cid=client-id]
    ^-  _state
    =/  who  (~(get by clients) cid)
    =/  wiped
      %=  state
        pending   (drop-pending cid)
        codes     (drop-codes cid)
        access    (drop-access cid)
        refresh   (drop-refresh cid)
        auths     (drop-auths cid)
        approved  (~(del in approved) cid)
      ==
    ?:  ?=(~ who)  wiped
    =/  body=log-body:wicket
      :*  %revoked-client
          via
          u.who
          (~(has in approved) cid)
          (grants-for cid)
          (tokens-of-client cid)
          (pending-for cid)
          (codes-for cid)
      ==
    %=  wiped
      clients  (~(del by clients.wiped) cid)
      log      [[now.bowl body] log.wiped]
    ==
  ::
  ++  waiting-count
    ^-  @ud
    %-  lent
    %+  skip  ~(val by clients)
    |=  c=client
    (~(has in approved) id.c)
  ::
  ++  run-sweep
    ^-  _state
    =/  dead  (idle-due:wicket now.bowl ~(val by clients) approved)
    |-  ^-  _state
    ?~  dead
      state(recent (prune-recent:wicket now.bowl recent))
    $(dead t.dead, state (forget-client %sweep i.dead))
  ::
  ::  A Behn timer stays on the duct that set it. A later HTTP poke cannot
  ::  %rest that timer, so we only arm one when none is pending. The wake
  ::  itself reschedules, which moves the deadline later after a revoke.
  ::
  ++  arm-sweep
    ^-  (quip card _state)
    =/  next  (next-wake:wicket ~(val by clients) approved)
    ?^  sweep-at
      ?:  ?=(^ next)  [~ state]
      [~ state(sweep-at ~)]
    ?~  next  [~ state]
    :_  state(sweep-at next)
    [%pass /registration/sweep %arvo %b %wait u.next]~
  ::
  ++  drop-scopes
    |=  [via=log-via:wicket cid=client-id res=(unit resource) sco=(list scope)]
    ^-  (quip card _state)
    =/  cur  (~(get by auths) [cid res])
    ?~  cur
      ~|  [%wicket %no-authorization cid res]  !!
    =/  left  (without-scopes:wicket scopes.u.cur sco)
    ?~  left
      ~|  [%wicket %scope-not-granted cid]  !!
    =/  keep  u.left
    =/  rows  (tokens-for cid res)
    =/  edits  (token-edits:wicket rows keep)
    =/  body=log-body:wicket
      :*  %revoked-scopes
          via
          cid
          (name-of cid)
          res
          sco
          scopes.u.cur
          keep
          edits
      ==
    =/  line=log-event:wicket  [now.bowl body]
    ?:  =(~ keep)
      :-  ~
      %=  state
        auths    (~(del by auths) [cid res])
        access   (forget-access cid res)
        refresh  (forget-refresh cid res)
        log      [line log]
      ==
    :-  ~
    %=  state
      auths    (~(put by auths) [cid res] [cid res keep now.bowl])
      access   (clip-access cid res keep)
      refresh  (clip-refresh cid res keep)
      log      [line log]
    ==
  ::
  ++  clip-access
    |=  [cid=client-id res=(unit resource) sco=(list scope)]
    %-  malt
    %+  murn  ~(tap by access)
    |=  [k=@ a=^access]
    ^-  (unit [@ ^access])
    ?.  ?&  =(client.a cid)
            =(resource.a res)
        ==
      `[k a]
    =/  next  (clip-scopes:wicket scopes.a sco)
    ?~  next  ~
    `[k a(scopes next)]
  ::
  ++  clip-refresh
    |=  [cid=client-id res=(unit resource) sco=(list scope)]
    %-  malt
    %+  murn  ~(tap by refresh)
    |=  [k=@ r=^refresh]
    ^-  (unit [@ ^refresh])
    ?.  ?&  =(client.r cid)
            =(resource.r res)
        ==
      `[k r]
    =/  next  (clip-scopes:wicket scopes.r sco)
    ?~  next  ~
    `[k r(scopes next)]
  ::
  ++  forget-access
    |=  [cid=client-id res=(unit resource)]
    %-  malt
    %+  skip  ~(tap by access)
    |=  [* a=^access]
    ?&  =(client.a cid)
        =(resource.a res)
    ==
  ::
  ++  forget-refresh
    |=  [cid=client-id res=(unit resource)]
    %-  malt
    %+  skip  ~(tap by refresh)
    |=  [* r=^refresh]
    ?&  =(client.r cid)
        =(resource.r res)
    ==
  ::
  ++  list-access
    ^-  (list token-info)
    %+  turn  ~(val by access)
    |=  a=^access
    (as-token-info:wicket prefix.a client.a resource.a scopes.a expires.a)
  ::
  ++  list-refresh
    ^-  (list token-info)
    %+  turn  ~(val by refresh)
    |=  r=^refresh
    (as-token-info:wicket prefix.r client.r resource.r scopes.r expires.r)
  ::
  ++  live-grant
    |=  tok=@t
    ^-  (unit grant)
    =/  acc  (~(get by access) (secret-hash:wicket tok))
    ?~  acc  ~
    ?:  (gte now.bowl expires.u.acc)  ~
    `[client.u.acc resource.u.acc scopes.u.acc expires.u.acc]
  ::
  ++  ok-grant
    |=  [aud=@t sco=@t tok=@t]
    ^-  ?
    =/  g  (live-grant tok)
    ?~  g  %.n
    ?&  (audience-ok aud u.g)
        (lien scopes.u.g |=(s=scope =(s sco)))
    ==
  ::
  ++  audience-ok
    |=  [aud=@t g=grant]
    ^-  ?
    ?~  resource.g
      ?|  =(aud origin)
          (~(has by resources) aud)
          %+  lien  ~(val by resources)
          |=(r=registered-resource =(aud audience.r))
      ==
    =(aud u.resource.g)
  ::
  ++  union-scopes
    ^-  (list @t)
    =/  acc=(set scope)
      %+  roll  ~(val by resources)
      |=  [r=registered-resource acc=(set scope)]
      (~(uni in acc) scopes.r)
    ~(tap in acc)
  ::
  ++  mint
    |=  salt=@tas
    ^-  @t
    %-  mint-opaque:wicket
    %+  shas  salt
    (cat 3 eny.bowl (scot %uv (end [0 64] (sham [salt now.bowl access refresh codes pending]))))
  ::
  ++  handle-http
    |=  =inbound-request:eyre
    ^-  (quip card [simple-payload:http _state])
    =/  req  request.inbound-request
    =/  lin  (parse-request-line:server url.req)
    ?:  =(%'OPTIONS' method.req)
      =^  caz  state  arm-sweep
      [caz [(options:wicket-http req) state]]
    =^  pay  state
      ?+    site.lin  [not-found:wicket-http state]
          [%'.well-known' %oauth-authorization-server %wicket ~]
        ?:  =(%'GET' method.req)
          [as-meta state]
        [method-not-allowed:wicket-http state]
      ::
          [%wicket %'.well-known' %openid-configuration ~]
        ?:  =(%'GET' method.req)
          [as-meta state]
        [method-not-allowed:wicket-http state]
      ::
          [%wicket %oauth %protected-resource *]
        ?:  =(%'GET' method.req)
          [(prm t.t.t.site.lin) state]
        [method-not-allowed:wicket-http state]
      ::
          [%wicket %oauth %register ~]
        (do-register inbound-request)
      ::
          [%wicket %oauth %authorize ~]
        (do-authorize inbound-request lin)
      ::
          [%wicket %oauth %token ~]
        (do-token req)
      ::
          [%wicket %oauth %revoke ~]
        (do-revoke req)
      ::
          [%wicket %tile ~]
        ?:  &(?=(%'GET' method.req) =(ext.lin `%jpg))
          [tile-image:wicket-http state]
        ?:  =(%'GET' method.req)
          [not-found:wicket-http state]
        [method-not-allowed:wicket-http state]
      ::
          [%wicket %manage ~]
        (do-manage inbound-request lin)
      ::
          [%wicket %manage %log ~]
        (do-manage-log inbound-request lin)
      ::
          [%wicket %manage %revoke ~]
        (do-manage-revoke inbound-request lin)
      ==
    =^  caz  state  arm-sweep
    =/  final
      ?:  ?|  ?=([%wicket %oauth %authorize *] site.lin)
              ?=([%wicket %manage ~] site.lin)
              ?=([%wicket %manage %log ~] site.lin)
              ?=([%wicket %manage %revoke ~] site.lin)
          ==
        pay
      (with-cors:wicket-http req pay)
    [caz [final state]]
  ::
  ++  as-meta
    ^-  simple-payload:http
    ?:  =('' origin)  origin-unset:wicket-http
    =/  iss  (issuer:wicket origin)
    =/  scops=(list json)
      (turn union-scopes |=(s=@t s+s))
    =,  enjs:format
    =/  rows=(list [@t json])
      ;:  welp
        :~  ['issuer' s+iss]
            ['authorization_endpoint' s+(cat 3 iss '/oauth/authorize')]
            ['token_endpoint' s+(cat 3 iss '/oauth/token')]
        ==
        ?:  registration
          ['registration_endpoint' s+(cat 3 iss '/oauth/register')]~
        ~
        :~  ['revocation_endpoint' s+(cat 3 iss '/oauth/revoke')]
            ['response_types_supported' a+~[s+'code']]
            ['grant_types_supported' a+~[s+'authorization_code' s+'refresh_token']]
            ['code_challenge_methods_supported' a+~[s+'S256']]
            ['token_endpoint_auth_methods_supported' a+~[s+'none']]
            ['scopes_supported' a+scops]
            ['resource_indicators_supported' b+&]
        ==
      ==
    (json-ok:wicket-http (pairs rows))
  ::
  ++  prm
    |=  rest=(list @t)
    ^-  simple-payload:http
    ?:  =('' origin)  origin-unset:wicket-http
    ?~  rest  not-found:wicket-http
    =/  url  (rap 3 [origin '/' (join-path:wicket rest) ~])
    =/  rec  (~(get by resources) url)
    ?~  rec  not-found:wicket-http
    (prm-json u.rec)
  ::
  ++  prm-json
    |=  rec=registered-resource
    ^-  simple-payload:http
    =/  iss  (issuer:wicket origin)
    =,  enjs:format
    %-  json-ok:wicket-http
    %-  pairs
    :~  ['resource' s+url.rec]
        ['authorization_servers' a+~[s+iss]]
        ['bearer_methods_supported' a+~[s+'header']]
        ['scopes_supported' a+(turn ~(tap in scopes.rec) |=(s=@t s+s))]
    ==
  ::
  ++  do-register
    |=  =inbound-request:eyre
    ^-  [simple-payload:http _state]
    =/  req  request.inbound-request
    =/  who  address.inbound-request
    ?.  =(%'POST' method.req)
      ?:  registration
        [method-not-allowed:wicket-http state]
      [(oauth-error:wicket-http 404 'invalid_request') state]
    =/  verdict
      %:  admit-registration:wicket
        registration
        who
        now.bowl
        denied
        waiting-count
        recent
      ==
    ?-    -.verdict
        %closed
      [(oauth-error:wicket-http 404 'invalid_request') state]
    ::
        %denied
      [(oauth-error:wicket-http 403 'access_denied') state]
    ::
        %full
      [(oauth-error:wicket-http 403 'access_denied') state]
    ::
        %limited
      :_  state
      %-  oauth-error-headers:wicket-http
      :*  429
          'invalid_request'
          ['retry-after' (crip (trip (scot %ud retry.verdict)))]~
      ==
    ::
        %ok
      (store-registration req who)
    ==
  ::
  ++  store-registration
    |=  [req=request:http who=address:eyre]
    ^-  [simple-payload:http _state]
    =/  raw  (body-cord:wicket body.req)
    ?~  jon=(parse-json:wicket raw)
      [(oauth-error:wicket-http 400 'invalid_client_metadata') state]
    =/  uris  (json-ar-so:wicket u.jon 'redirect_uris')
    ?~  uris
      [(oauth-error:wicket-http 400 'invalid_redirect_uri') state]
    ?:  =(~ u.uris)
      [(oauth-error:wicket-http 400 'invalid_redirect_uri') state]
    ?.  (levy u.uris redirect-ok:wicket)
      [(oauth-error:wicket-http 400 'invalid_redirect_uri') state]
    ?:  (gth (lent u.uris) uri-count-max:wicket)
      [(oauth-error:wicket-http 400 'invalid_redirect_uri') state]
    ?.  (levy u.uris |=(u=@t (lte (met 3 u) uri-max:wicket)))
      [(oauth-error:wicket-http 400 'invalid_redirect_uri') state]
    =/  auth  (json-so:wicket u.jon 'token_endpoint_auth_method')
    ?:  ?&  ?=(^ auth)
            !=('none' u.auth)
        ==
      [(oauth-error:wicket-http 400 'invalid_client_metadata') state]
    ?:  ?=(^ (json-so:wicket u.jon 'client_secret'))
      [(oauth-error:wicket-http 400 'invalid_client_metadata') state]
    =/  grants  (json-ar-so:wicket u.jon 'grant_types')
    =/  allowed  (silt ~['authorization_code' 'refresh_token'])
    ?~  grants
      [(oauth-error:wicket-http 400 'invalid_client_metadata') state]
    ?.  (levy u.grants |=(g=@t (~(has in allowed) g)))
      [(oauth-error:wicket-http 400 'invalid_client_metadata') state]
    =/  name  (json-so-or:wicket u.jon 'client_name' 'public-client')
    ?:  (gth (met 3 name) name-max:wicket)
      [(oauth-error:wicket-http 400 'invalid_client_metadata') state]
    =/  cid
      (mint-opaque:wicket (mix eny.bowl (mix now.bowl (sham clients))))
    =/  c=client
      [id=cid name=name redirect-uris=(silt u.uris) created=now.bowl]
    =/  gts=(list json)
      :~  s+'authorization_code'
          s+'refresh_token'
      ==
    =/  out=json
      %-  pairs:enjs:format
      :~  ['client_id' s+cid]
          ['client_name' s+name]
          ['redirect_uris' a+(turn u.uris |=(u=@t s+u))]
          ['token_endpoint_auth_method' s+'none']
          ['grant_types' a+gts]
      ==
    =/  body=log-body:wicket  [%registered who c u.grants 'none']
    :-  (json-created:wicket-http out)
    %=  state
      clients  (~(put by clients) cid c)
      recent   (note-registration:wicket now.bowl who recent)
      log      [[now.bowl body] log]
    ==
  ::
  ++  do-authorize
    |=  [=inbound-request:eyre lin=request-line:server]
    ^-  [simple-payload:http _state]
    ?:  =(%'GET' method.request.inbound-request)
      (get-authorize inbound-request lin)
    ?:  =(%'POST' method.request.inbound-request)
      (post-authorize inbound-request)
    [method-not-allowed:wicket-http state]
  ::
  ++  auth-fail
    |=  [safe=(unit @t) sta=@t err=@t msg=tape]
    ^-  simple-payload:http
    ?~  safe
      (html-code:wicket-http 400 (error-page:wicket-html 400 msg))
    (found:wicket-http (add-query:wicket u.safe ~[error+err state+sta]))
  ::
  ++  get-authorize
    |=  [=inbound-request:eyre lin=request-line:server]
    ^-  [simple-payload:http _state]
    =/  args  args.lin
    =/  cid  (need-arg:wicket 'client_id' args)
    =/  red  (need-arg:wicket 'redirect_uri' args)
    =/  sta  (need-arg:wicket 'state' args)
    =/  chal  (need-arg:wicket 'code_challenge' args)
    =/  meth  (need-arg:wicket 'code_challenge_method' args)
    =/  rty  (need-arg:wicket 'response_type' args)
    =/  scp  (need-arg:wicket 'scope' args)
    =/  res  (need-arg:wicket 'resource' args)
    =/  who  (~(get by clients) cid)
    =/  safe=(unit @t)
      ?~  who  ~
      ?:((~(has in redirect-uris.u.who) red) `red ~)
    ?~  who
      [(auth-fail ~ sta 'invalid_client' "unknown client") state]
    ?~  safe
      [(auth-fail ~ sta 'invalid_request' "redirect_uri is not registered") state]
    ?.  =('code' rty)
      :_  state
      (auth-fail safe sta 'unsupported_response_type' "response_type must be code")
    ?.  =('S256' meth)
      :_  state
      (auth-fail safe sta 'invalid_request' "code_challenge_method must be S256")
    ?.  (valid-challenge:wicket chal)
      :_  state
      (auth-fail safe sta 'invalid_request' "invalid code_challenge")
    ?:  =('' res)
      :_  state
      (auth-fail safe sta 'invalid_target' "resource is required")
    ?~  rec=(~(get by resources) res)
      :_  state
      (auth-fail safe sta 'invalid_target' "unknown resource")
    =/  want  (split-space:wicket scp)
    =.  want  ?~(want ~(tap in scopes.u.rec) want)
    ?.  (levy want |=(s=scope (~(has in scopes.u.rec) s)))
      :_  state
      (auth-fail safe sta 'invalid_scope' "invalid scope")
    (consent-or-login inbound-request u.who red sta chal `res want)
  ::
  ::  +owner-login: 303 to Eyre's /~/login. The redirect is percent-encoded
  ::  because a raw "=" never reaches that handler (urbit#7071).
  ::
  ++  owner-login
    |=  here=@t
    ^-  simple-payload:http
    (see-other:wicket-http (crip (eyre-login-href:wicket here)))
  ::
  ++  consent-or-login
    |=  $:  =inbound-request:eyre
            who=client
            red=@t
            sta=@t
            chal=@t
            resource=(unit resource)
            want=(list scope)
        ==
    ^-  [simple-payload:http _state]
    ?.  authenticated.inbound-request
      :_  state
      (owner-login url.request.inbound-request)
    =/  id  `@uv`(end [0 128] (shas %authz (mix eny.bowl now.bowl)))
    =/  az=authz
      :*  id=id
          client=id.who
          redirect=red
          state=sta
          challenge=chal
          resource=resource
          scopes=want
          expires=(add now.bowl ~m10)
      ==
    :-  (html-ok:wicket-http (consent-page:wicket-html our.bowl who az copies))
    state(pending (~(put by pending) id az))
  ::
  ++  post-authorize
    |=  =inbound-request:eyre
    ^-  [simple-payload:http _state]
    ?.  authenticated.inbound-request
      :_  state
      (owner-login url.request.inbound-request)
    =/  pairs  (form-pairs:wicket (body-cord:wicket body.request.inbound-request))
    =/  form  (malt (flop pairs))
    =/  picked  (pair-values:wicket 'scope' pairs)
    =/  idt  (~(gut by form) 'id' '')
    =/  dec  (~(gut by form) 'decision' '')
    =/  idu  (slaw %uv idt)
    ?~  idu
      [(html-code:wicket-http 400 (error-page:wicket-html 400 "invalid request")) state]
    =/  paz  (~(get by pending) u.idu)
    ?~  paz
      [(html-code:wicket-http 400 (error-page:wicket-html 400 "unknown or expired request")) state]
    ?:  (gte now.bowl expires.u.paz)
      :-  (html-code:wicket-http 400 (error-page:wicket-html 400 "expired request"))
      state(pending (~(del by pending) u.idu))
    =.  state  state(pending (~(del by pending) u.idu))
    ?:  =('deny' dec)
      :-  %-  found:wicket-http
          (add-query:wicket redirect.u.paz ~[error+'access_denied' state+state.u.paz])
      state(log [[now.bowl (denial-body u.paz)] log])
    ?.  =('approve' dec)
      [(html-code:wicket-http 400 (error-page:wicket-html 400 "invalid decision")) state]
    =/  granted=(list scope)
      %+  skim  scopes.u.paz
      |=(s=scope (lien picked |=(p=@t =(p s))))
    ?:  =(~ granted)
      :_  state
      (html-code:wicket-http 400 (error-page:wicket-html 400 "select at least one scope"))
    =/  who  client.u.paz
    =/  res  resource.u.paz
    =/  prev  (~(get by auths) [who res])
    =/  previous=(unit (list scope))
      ?:  ?=(~ prev)  ~
      `scopes.u.prev
    =/  rows  (tokens-for who res)
    =/  edits  (token-edits:wicket rows granted)
    =/  first=?  ?:((~(has in approved) who) %.n %.y)
    =.  auths
      %-  ~(put by auths)
      :-  [who res]
      [who res granted now.bowl]
    =.  access   (clip-access who res granted)
    =.  refresh  (clip-refresh who res granted)
    =.  approved  (~(put in approved) who)
    =/  code-id  (mint %code)
    =/  exp  (add now.bowl ~m10)
    =/  pre  (prefix-id:wicket code-id)
    =/  c=^code
      :*  prefix=pre
          client=who
          redirect=redirect.u.paz
          challenge=challenge.u.paz
          resource=res
          scopes=granted
          expires=exp
          used=|
      ==
    =/  body=log-body:wicket
      :*  %authorized
          %approve
          who
          (name-of who)
          res
          redirect.u.paz
          state.u.paz
          challenge.u.paz
          scopes.u.paz
          granted
          previous
          id.u.paz
          expires.u.paz
          `[pre exp]
          first
          edits
      ==
    :-  %-  found:wicket-http
        (add-query:wicket redirect.u.paz ~[code+code-id state+state.u.paz])
    %=  state
      codes     (~(put by codes) (secret-hash:wicket code-id) c)
      auths     auths
      access    access
      refresh   refresh
      approved  approved
      log       [[now.bowl body] log]
    ==
  ::
  ++  denial-body
    |=  paz=authz
    ^-  log-body:wicket
    :*  %authorized
        %deny
        client.paz
        (name-of client.paz)
        resource.paz
        redirect.paz
        state.paz
        challenge.paz
        scopes.paz
        ~
        ~
        id.paz
        expires.paz
        ~
        %.n
        ~
    ==
  ::
  ++  do-token
    |=  req=request:http
    ^-  [simple-payload:http _state]
    ?.  =(%'POST' method.req)
      [method-not-allowed:wicket-http state]
    =/  form  (form-or-json:wicket req)
    =/  gtyp  (~(gut by form) 'grant_type' '')
    ?:  =('authorization_code' gtyp)  (token-code form)
    ?:  =('refresh_token' gtyp)  (token-refresh form)
    [(oauth-error:wicket-http 400 'unsupported_grant_type') state]
  ::
  ++  token-code
    |=  form=(map @t @t)
    ^-  [simple-payload:http _state]
    =/  code-id  (~(gut by form) 'code' '')
    =/  red  (~(gut by form) 'redirect_uri' '')
    =/  cid  (~(gut by form) 'client_id' '')
    =/  ver  (~(gut by form) 'code_verifier' '')
    =/  key  (secret-hash:wicket code-id)
    =/  c  (~(get by codes) key)
    ?~  c
      [(oauth-error:wicket-http 400 'invalid_grant') state]
    ?:  used.u.c
      [(oauth-error:wicket-http 400 'invalid_grant') state]
    ?:  (gte now.bowl expires.u.c)
      [(oauth-error:wicket-http 400 'invalid_grant') state]
    ?.  =(client.u.c cid)
      [(oauth-error:wicket-http 400 'invalid_grant') state]
    ?.  =(redirect.u.c red)
      [(oauth-error:wicket-http 400 'invalid_grant') state]
    ?.  (valid-verifier:wicket ver)
      [(oauth-error:wicket-http 400 'invalid_request') state]
    ?.  =((s256:wicket ver) challenge.u.c)
      [(oauth-error:wicket-http 400 'invalid_grant') state]
    =/  res  (~(gut by form) 'resource' '')
    ?:  =('' res)
      [(oauth-error:wicket-http 400 'invalid_target') state]
    ?.  =(`res resource.u.c)
      [(oauth-error:wicket-http 400 'invalid_target') state]
    =/  how=redeemed:wicket
      [%code prefix.u.c expires.u.c redirect.u.c challenge.u.c]
    =.  state  state(codes (~(put by codes) key u.c(used &)))
    (issue-tokens client.u.c resource.u.c how)
  ::
  ++  token-refresh
    |=  form=(map @t @t)
    ^-  [simple-payload:http _state]
    =/  rid  (~(gut by form) 'refresh_token' '')
    =/  cid  (~(gut by form) 'client_id' '')
    =/  key  (secret-hash:wicket rid)
    =/  r  (~(get by refresh) key)
    ?~  r
      [(oauth-error:wicket-http 400 'invalid_grant') state]
    ?:  (gte now.bowl expires.u.r)
      [(oauth-error:wicket-http 400 'invalid_grant') state]
    ?.  =(client.u.r cid)
      [(oauth-error:wicket-http 400 'invalid_grant') state]
    =/  res  (~(gut by form) 'resource' '')
    ?:  =('' res)
      [(oauth-error:wicket-http 400 'invalid_target') state]
    ?.  =(`res resource.u.r)
      [(oauth-error:wicket-http 400 'invalid_target') state]
    =/  how=redeemed:wicket  [%refresh prefix.u.r expires.u.r]
    =.  state  state(refresh (~(del by refresh) key))
    (issue-tokens client.u.r resource.u.r how)
  ::
  ++  issue-tokens
    |=  [cid=client-id res=(unit resource) how=redeemed:wicket]
    ^-  [simple-payload:http _state]
    =/  a  (~(get by auths) [cid res])
    ?~  a
      [(oauth-error:wicket-http 400 'invalid_grant') state]
    =/  granted  scopes.u.a
    =/  at  (mint %access)
    =/  rt  (mint %refresh)
    =/  pre-a  (prefix-id:wicket at)
    =/  pre-r  (prefix-id:wicket rt)
    =/  exp-a  (add now.bowl ~h1)
    =/  exp-r  (add now.bowl ~d30)
    =/  acc=^access
      [prefix=pre-a client=cid resource=res scopes=granted expires=exp-a]
    =/  ref=^refresh
      [prefix=pre-r client=cid resource=res scopes=granted expires=exp-r]
    =/  body=log-body:wicket
      :*  %issued
          cid
          (name-of cid)
          res
          granted
          (as-logged %access pre-a cid res granted exp-a)
          (as-logged %refresh pre-r cid res granted exp-r)
          how
      ==
    ~&  %wicket-token-minted
    =/  jon=json
      =,  enjs:format
      %-  pairs
      :~  ['access_token' s+at]
          ['token_type' s+'Bearer']
          ['expires_in' n+'3600']
          ['refresh_token' s+rt]
          ['scope' s+(join-space:wicket granted)]
      ==
    :-  (json-code:wicket-http 200 jon ['cache-control' 'no-store']~)
    %=  state
      access   (~(put by access) (secret-hash:wicket at) acc)
      refresh  (~(put by refresh) (secret-hash:wicket rt) ref)
      log      [[now.bowl body] log]
    ==
  ::
  ++  do-revoke
    |=  req=request:http
    ^-  [simple-payload:http _state]
    ?.  =(%'POST' method.req)
      [method-not-allowed:wicket-http state]
    =/  tok  (~(gut by (form-or-json:wicket req)) 'token' '')
    =.  state  (revoke-access-id %endpoint tok)
    =.  state  (revoke-refresh-id %endpoint tok)
    [empty-ok:wicket-http state]
  ::
  ++  manage-notice
    |=  args=(list [p=@t q=@t])
    ^-  (unit tape)
    =/  code  (lookup:wicket 'done' args)
    ?~  code  ~
    ?+  u.code  ~
      %'scope'         `"Scope removed."
      %'access'        `"Access token revoked."
      %'refresh'       `"Refresh token revoked."
      %'client'        `"Client revoked."
      %'registration'  ?:(registration `"Registration open." `"Registration closed.")
      %'deny'          `"Address blocked."
      %'allow'         `"Address removed."
    ==
  ::
  ++  manage-open
    |=  args=(list [p=@t q=@t])
    ^-  (unit client-id)
    =/  id  (lookup:wicket 'open' args)
    ?~  id  ~
    ?:  =('' u.id)  ~
    `u.id
  ::
  ++  render-manage
    |=  [note=(unit tape) open=(unit client-id)]
    ^-  manx
    %-  manage-page:wicket-html
    :*  our.bowl
        now.bowl
        ~(val by clients)
        ~(val by auths)
        list-access
        list-refresh
        ~(val by resources)
        note
        open
        registration
        approved
        denied-tapes
        copies
    ==
  ::
  ++  denied-tapes
    ^-  (list @t)
    %+  sort
      %+  turn  ~(tap in denied)
      |=  a=address:eyre
      (crip (render-address:wicket a))
    aor
  ::
  ++  manage-fail
    |=  msg=tape
    ^-  simple-payload:http
    (html-private:wicket-http 400 (manage-error:wicket-html msg))
  ::
  ++  do-manage-log
    |=  [=inbound-request:eyre lin=request-line:server]
    ^-  [simple-payload:http _state]
    =/  req  request.inbound-request
    ?.  authenticated.inbound-request
      :_  state
      (owner-login url.req)
    ?.  =(%'GET' method.req)
      [method-not-allowed:wicket-http state]
    =/  kind  (log-filter:wicket-html (lookup:wicket 'kind' args.lin))
    :_  state
    %-  html-private:wicket-http
    :-  200
    (log-page:wicket-html our.bowl log kind)
  ::
  ++  do-manage
    |=  [=inbound-request:eyre lin=request-line:server]
    ^-  [simple-payload:http _state]
    =/  req  request.inbound-request
    ?.  authenticated.inbound-request
      :_  state
      (owner-login url.req)
    ?:  =(%'GET' method.req)
      :_  state
      (html-private:wicket-http 200 (render-manage (manage-notice args.lin) (manage-open args.lin)))
    ?:  =(%'POST' method.req)
      (post-manage inbound-request)
    [method-not-allowed:wicket-http state]
  ::
  ++  do-manage-revoke
    |=  [=inbound-request:eyre lin=request-line:server]
    ^-  [simple-payload:http _state]
    =/  req  request.inbound-request
    ?.  authenticated.inbound-request
      :_  state
      (owner-login url.req)
    ?.  =(%'GET' method.req)
      [method-not-allowed:wicket-http state]
    =/  cid  (lookup:wicket 'client' args.lin)
    ?~  cid
      :_  state
      (html-private:wicket-http 404 (manage-error:wicket-html "Unknown client."))
    ?~  who=(~(get by clients) u.cid)
      :_  state
      (html-private:wicket-http 404 (manage-error:wicket-html "Unknown client."))
    =/  n-grants
      (lent (skim ~(val by auths) |=(a=authorization =(client.a u.cid))))
    =/  n-tokens
      =/  acc  (skim list-access |=(t=token-info =(client.t u.cid)))
      =/  ref  (skim list-refresh |=(t=token-info =(client.t u.cid)))
      (add (lent acc) (lent ref))
    :_  state
    %-  html-private:wicket-http
    :-  200
    (revoke-client-page:wicket-html u.who n-grants n-tokens)
  ::
  ++  post-manage
    |=  =inbound-request:eyre
    ^-  [simple-payload:http _state]
    =/  req  request.inbound-request
    =/  here  (request-origin:wicket secure.inbound-request header-list.req)
    ?.  (posted-from-origin:wicket ~[origin here] header-list.req)
      :_  state
      (manage-fail "This request did not come from this page.")
    =/  pairs  (form-pairs:wicket (body-cord:wicket body.req))
    =/  act  (need-arg:wicket 'action' pairs)
    ?+    act
      :_  state
      (manage-fail "Unknown action.")
    ::
        %'set-registration'
      =/  flag  (need-arg:wicket 'open' pairs)
      ?:  =('yes' flag)
        (applied 'registration' ~ [%set-registration %.y])
      ?:  =('no' flag)
        (applied 'registration' ~ [%set-registration %.n])
      :_  state
      (manage-fail "Unknown action.")
    ::
        %'deny-address'
      =/  raw  (need-arg:wicket 'address' pairs)
      =/  got  (parse-address:wicket raw)
      ?:  ?=(~ got)
        :_  state
        (manage-fail "That address is not an IP address.")
      (applied 'deny' ~ [%deny-address u.got])
    ::
        %'allow-address'
      =/  raw  (need-arg:wicket 'address' pairs)
      =/  got  (parse-address:wicket raw)
      ?:  ?=(~ got)
        :_  state
        (manage-fail "That address is not an IP address.")
      ?.  (~(has in denied) u.got)
        :_  state
        (manage-fail "That address is not blocked.")
      (applied 'allow' ~ [%allow-address u.got])
    ::
        %'revoke-client'
      (post-revoke-client pairs)
    ::
        %'revoke-access'
      (post-revoke-token %access pairs)
    ::
        %'revoke-refresh'
      (post-revoke-token %refresh pairs)
    ::
        %'drop-scope'
      (post-drop-scope pairs)
    ==
  ::
  ++  form-resource
    |=  pairs=(list [p=@t q=@t])
    ^-  (unit resource)
    =/  got  (lookup:wicket 'resource' pairs)
    ?~  got  ~
    ?:  =('' u.got)  ~
    `u.got
  ::
  ++  applied
    |=  [done=@t who=(unit client-id) act=action]
    ^-  [simple-payload:http _state]
    =/  moved  (apply-action %page act)
    :-  (see-other:wicket-http (crip (manage-href:wicket-html `done who)))
    +.moved
  ::
  ++  post-revoke-client
    |=  pairs=(list [p=@t q=@t])
    ^-  [simple-payload:http _state]
    =/  cid  (need-arg:wicket 'client' pairs)
    ?~  (~(get by clients) cid)
      :_  state
      (manage-fail "Unknown client.")
    (applied 'client' ~ [%revoke-client cid])
  ::
  ++  post-revoke-token
    |=  [kind=?(%access %refresh) pairs=(list [p=@t q=@t])]
    ^-  [simple-payload:http _state]
    =/  given  (need-arg:wicket 'token' pairs)
    =/  rows  ?:(?=(%access kind) list-access list-refresh)
    ?~  hit=(match-token:wicket given rows)
      :_  state
      (manage-fail "That token was not found, or the prefix matches more than one token.")
    =/  act=action
      ?:  ?=(%access kind)
        [%revoke-access id-prefix.u.hit]
      [%revoke-refresh id-prefix.u.hit]
    (applied ?:(?=(%access kind) 'access' 'refresh') `client.u.hit act)
  ::
  ++  post-drop-scope
    |=  pairs=(list [p=@t q=@t])
    ^-  [simple-payload:http _state]
    =/  cid  (need-arg:wicket 'client' pairs)
    =/  sco  (need-arg:wicket 'scope' pairs)
    =/  res  (form-resource pairs)
    ?~  (~(get by clients) cid)
      :_  state
      (manage-fail "Unknown client.")
    =/  cur  (~(get by auths) [cid res])
    ?~  cur
      :_  state
      (manage-fail "Unknown grant.")
    ?~  (without-scopes:wicket scopes.u.cur ~[sco])
      :_  state
      (manage-fail "That scope is not granted.")
    (applied 'scope' `cid [%drop-scopes cid res ~[sco]])
  --
--
::
%-  agent:dbug
=|  versioned-state
=*  state  -
^-  agent:gall
|_  =bowl:gall
+*  this  .
    def   ~(. (default-agent this %.n) bowl)
    wrk   ~(. work [bowl state])
::
++  on-init
  ^-  (quip card _this)
  ::  ? bunts to %.y, which would open registration.
  =.  state  state(registration |)
  [bind-eyre:wrk this]
::
++  on-save  !>(state)
::
++  on-load
  |=  vaz=vase
  ^-  (quip card _this)
  =/  old  !<(versioned-state vaz)
  =.  state  old
  =^  caz  state  arm-sweep:wrk
  [(weld bind-eyre:wrk caz) this]
::
++  on-poke
  |=  [=mark =vase]
  ^-  (quip card _this)
  ?+    mark  (on-poke:def mark vase)
      %wicket-action
    ?>  =(src.bowl our.bowl)
    =^  caz  state  (poke-action:wrk !<(action vase))
    =^  arm  state  arm-sweep:wrk
    [(weld caz arm) this]
  ::
      %handle-http-request
    =+  !<([eyre-id=@ta =inbound-request:eyre] vase)
    =/  res  (handle-http:wrk inbound-request)
    =/  caz  -.res
    =/  pair  +.res
    =/  pay  -.pair
    =.  state  +.pair
    :_  this
    (weld caz (give-simple-payload:app:server eyre-id pay))
  ==
::
++  on-watch
  |=  =path
  ^-  (quip card _this)
  ?:  ?=([%http-response *] path)  `this
  (on-watch:def path)
::
++  on-leave  on-leave:def
::
++  on-peek
  |=  =path
  ^-  (unit (unit cage))
  ?+    path  [~ ~]
      [%x %origin ~]
    ``noun+!>(origin)
  ::
      [%x %issuer ~]
    ``noun+!>((issuer:wicket origin))
  ::
      [%x %resources ~]
    ``noun+!>(`(list registered-resource)`~(val by resources))
  ::
      [%x %clients ~]
    ``noun+!>(`(list client)`~(val by clients))
  ::
      [%x %auths ~]
    ``noun+!>(`(list authorization)`~(val by auths))
  ::
      [%x %grants ~]
    ``noun+!>(`(list authorization)`~(val by auths))
  ::
      [%x %access ~]
    ``noun+!>(list-access:wrk)
  ::
      [%x %refresh ~]
    ``noun+!>(list-refresh:wrk)
  ::
      [%x %resource @ ~]
    =/  url  (slaw %t i.t.t.path)
    ?~  url  ``noun+!>(*(unit registered-resource))
    ``noun+!>(`(unit registered-resource)`(~(get by resources) u.url))
  ::
      [%x %grant @ ~]
    =/  tok  (slaw %t i.t.t.path)
    ?~  tok  ``noun+!>(*(unit grant))
    ``noun+!>(`(unit grant)`(live-grant:wrk u.tok))
  ::
      [%x %ok @ @ @ ~]
    =/  aud  (slaw %t i.t.t.path)
    =/  sco  (slaw %t i.t.t.t.path)
    =/  tok  (slaw %t i.t.t.t.t.path)
    ?:  |(?=(~ aud) ?=(~ sco) ?=(~ tok))
      ``noun+!>(%.n)
    ``noun+!>((ok-grant:wrk u.aud u.sco u.tok))
  ==
::
++  on-agent
  |=  [=wire =sign:agent:gall]
  ^-  (quip card _this)
  ?+    wire  (on-agent:def wire sign)
      [%keeper %origin ~]
    ?.  ?=([%poke-ack *] sign)  (on-agent:def wire sign)
    `this
  ==
::
++  on-arvo
  |=  [=wire sign=sign-arvo]
  ^-  (quip card _this)
  ?+    wire  (on-arvo:def wire sign)
      [%eyre %connect *]
    ?.  ?=([%eyre %bound *] sign)  (on-arvo:def wire sign)
    ?:  accepted.sign  `this
    ~&  [%wicket %bind-failed binding.sign]
    `this
  ::
      [%registration %sweep ~]
    ?.  ?=([%behn %wake *] sign)  (on-arvo:def wire sign)
    ?^  error.sign
      =/  when  (add now.bowl ~h1)
      :_  this(state state(sweep-at `when))
      [%pass /registration/sweep %arvo %b %wait when]~
    =.  state  state(sweep-at ~)
    =.  state  run-sweep:wrk
    =^  caz  state  arm-sweep:wrk
    [caz this]
  ==
::
++  on-fail  on-fail:def
--
