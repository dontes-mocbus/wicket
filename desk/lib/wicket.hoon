::  /lib/wicket: PKCE S256, random ids, form/json helpers
::
::    Earth clients enter through this small door. Helpers here are
::    pure: SHA-256 + base64url (no pad) for PKCE, plus HTTP parsing
::    that must never crash the agent on bad input.
::
/-  *wicket
|%
::  +s256: RFC 7636 code_challenge = BASE64URL(SHA256(ASCII(verifier)))
::
++  s256
  |=  verifier=@t
  ^-  @t
  (en-b64url 32 (shax verifier))
::
::  +en-b64url: url-safe base64, no padding (RFC 4648 §5)
::
++  en-b64url
  |=  =octs
  ^-  @t
  %-  crip
  %+  skip
    %+  turn  (trip (en:base64:mimes:html octs))
    |=  c=@tD
    ?:  =(c '+')  '-'
    ?:  =(c '/')  '_'
    c
  |=(c=@tD =(c '='))
::
::  +unreserved: ALPHA / DIGIT / "-" / "." / "_" / "~"
::
++  unreserved
  |=  c=@
  ^-  ?
  ?|  &((gte c 'A') (lte c 'Z'))
      &((gte c 'a') (lte c 'z'))
      &((gte c '0') (lte c '9'))
      =(c '-')
      =(c '.')
      =(c '_')
      =(c '~')
  ==
::
++  unreserved-cord
  |=  t=@t
  ^-  ?
  =/  n  (met 3 t)
  =/  i  0
  |-  ^-  ?
  ?:  =(i n)  &
  ?.  (unreserved (cut 3 [i 1] t))  |
  $(i +(i))
::
++  valid-verifier
  |=  t=@t
  ^-  ?
  =/  n  (met 3 t)
  ?&  (gte n 43)
      (lte n 128)
      (unreserved-cord t)
  ==
::
++  valid-challenge  valid-verifier
::
::  +mint-opaque: unguessable token string (base64url of 32 bytes)
::
++  mint-opaque
  |=  entropy=@
  ^-  @t
  (en-b64url 32 (shax entropy))
::
::  +chop-slash: drop a single trailing slash; origin has none
::
++  chop-slash
  |=  u=@t
  ^-  @t
  =/  n  (met 3 u)
  ?:  =(0 n)  u
  ?:  =('/' (cut 3 [(dec n) 1] u))
    (end [3 (dec n)] u)
  u
::
::  +on-origin: resource URL is origin or origin + "/" + rest
::
++  on-origin
  |=  [org=@t url=@t]
  ^-  ?
  ?:  =(org url)  &
  =/  n  (met 3 org)
  ?:  =(0 n)  |
  ?&  (gte (met 3 url) +(n))
      =(org (end [3 n] url))
      =('/' (cut 3 [n 1] url))
  ==
::
::  +redirect-ok: public-client redirect URI allowlist
::
++  redirect-ok
  |=  uri=@t
  ^-  ?
  ?:  =('' uri)  |
  ?:  (has-prefix uri 'javascript:')  |
  ?:  (has-prefix uri 'data:')  |
  ?:  (has-prefix uri 'https://')  &
  ?|  (loopback-http uri 'http://127.0.0.1')
      (loopback-http uri 'http://localhost')
      (loopback-http uri 'http://[::1]')
  ==
::
++  has-prefix
  |=  [u=@t pre=@t]
  ^-  ?
  =/  n  (met 3 pre)
  ?:  (lth (met 3 u) n)  |
  =(pre (end [3 n] u))
::
++  loopback-http
  |=  [uri=@t host=@t]
  ^-  ?
  =/  n  (met 3 host)
  ?.  (has-prefix uri host)  |
  ?:  =((met 3 uri) n)  &
  =/  c  (cut 3 [n 1] uri)
  ?|(=(c '/') =(c ':'))
::
::  +header: case-insensitive lookup
::
++  header
  |=  [key=@t headers=header-list:http]
  ^-  (unit @t)
  =/  k  (cass (trip key))
  |-  ^-  (unit @t)
  ?~  headers  ~
  ?:  =(k (cass (trip key.i.headers)))
    `value.i.headers
  $(headers t.headers)
::
::  +request-origin: scheme plus Host for this request.
::    secure selects https. An absent Host is an empty cord.
::
++  request-origin
  |=  [secure=? headers=header-list:http]
  ^-  @t
  =/  host  (fall (header 'host' headers) '')
  ?:  =('' host)  ''
  (rap 3 ?:(secure 'https://' 'http://') host ~)
::
::  +posted-from-origin: POST Origin, or else Referer, matches one allowed
::    origin. The configured issuer and the Host of this request are both
::    allowed, so localhost and 127.0.0.1 can both be this ship. A host
::    that only shares a prefix, such as the origin plus ".evil", does not.
::
++  posted-from-origin
  |=  [allowed=(list @t) headers=header-list:http]
  ^-  ?
  =/  origins=(list @t)
    %+  skip  allowed
    |=  o=@t
    =('' o)
  ?:  =(~ origins)  %.n
  =/  got  (header 'origin' headers)
  ?:  ?=(^ got)
    (lien origins |=(o=@t (same-origin o u.got)))
  =/  ref  (header 'referer' headers)
  ?:  ?=(~ ref)  %.n
  (lien origins |=(o=@t (origin-prefix o u.ref)))
::
++  same-origin
  |=  [org=@t got=@t]
  ^-  ?
  =((lower org) (lower got))
::
++  lower
  |=  t=@t
  ^-  @t
  (crip (cass (trip t)))
::
++  origin-prefix
  |=  [org=@t uri=@t]
  ^-  ?
  =/  o  (lower org)
  =/  u  (lower uri)
  =/  n  (met 3 o)
  ?.  (has-prefix u o)  |
  ?:  =((met 3 u) n)  &
  =/  c  (cut 3 [n 1] u)
  ?|  =('/' c)
      =('?' c)
      =('#' c)
  ==
::
::  +match-token: one row whose prefix equals given.
::    ~ when nothing matches, or more than one row does.
::    The bearer itself is not in the row; the agent resolves that by hash.
::
++  match-token
  |=  [given=@t rows=(list token-info)]
  ^-  (unit token-info)
  =/  hits
    %+  skim  rows
    |=  t=token-info
    =(id-prefix.t given)
  ?~  hits  ~
  ?~  t.hits  `i.hits
  ~
::
++  body-cord
  |=  body=(unit octs)
  ^-  @t
  ?~(body '' q.u.body)
::
++  lookup
  |=  [key=@t args=(list [p=@t q=@t])]
  ^-  (unit @t)
  =/  a  (flop args)
  |-  ^-  (unit @t)
  ?~  a  ~
  ?:  =(p.i.a key)  `q.i.a
  $(a t.a)
::
++  need-arg
  |=  [key=@t args=(list [p=@t q=@t])]
  ^-  @t
  (fall (lookup key args) '')
::
::  +parse-form: application/x-www-form-urlencoded → map
::
++  parse-form
  |=  raw=@t
  ^-  (map @t @t)
  ?:  =('' raw)  ~
  %-  malt
  (fall (rush raw yquy:de-purl:html) ~)
::
::  +json-so: string field of a JSON object
::
++  json-so
  |=  [jon=json key=@t]
  ^-  (unit @t)
  ?.  ?=([%o *] jon)  ~
  =/  v  (~(get by p.jon) key)
  ?~  v  ~
  ?:(?=([%s *] u.v) `p.u.v ~)
::
++  json-so-or
  |=  [jon=json key=@t fallback=@t]
  (fall (json-so jon key) fallback)
::
++  json-ar-so
  |=  [jon=json key=@t]
  ^-  (unit (list @t))
  ?.  ?=([%o *] jon)  ~
  =/  v  (~(get by p.jon) key)
  ?~  v  `~
  ?.  ?=([%a *] u.v)  ~
  =/  acc=(list @t)  ~
  =/  xs  p.u.v
  |-  ^-  (unit (list @t))
  ?~  xs  `(flop acc)
  ?.  ?=([%s *] i.xs)  ~
  $(xs t.xs, acc [p.i.xs acc])
::
++  json-object-cords
  |=  jon=json
  ^-  (map @t @t)
  ?.  ?=([%o *] jon)  ~
  %-  malt
  %+  murn  ~(tap by p.jon)
  |=  [k=@t v=json]
  ?+  v  ~
    [%s *]  `[k p.v]
    [%n *]  `[k p.v]
  ==
::
++  parse-json
  |=  raw=@t
  ^-  (unit json)
  (de:json:html raw)
::
::  +form-or-json: token/revoke body as a cord map
::
++  form-or-json
  |=  =request:http
  ^-  (map @t @t)
  =/  raw  (body-cord body.request)
  =/  ct  (fall (header 'content-type' header-list.request) '')
  ?:  ?=(^ (find "application/json" (trip ct)))
    ?~  jon=(parse-json raw)  ~
    (json-object-cords u.jon)
  (parse-form raw)
::
::  +split-space: OAuth scope list
::
++  split-space
  |=  t=@t
  ^-  (list @t)
  ?:  =('' t)  ~
  %+  fall
    %+  rush  t
    %+  more  (plus ace)
    (cook crip (plus ;~(less ace next)))
  ~
::
++  join-space
  |=  s=(list @t)
  ^-  @t
  ?~  s  ''
  %+  rap  3
  |-  ^-  (list @)
  ?~  t.s  [i.s]~
  [i.s ' ' $(s t.s)]
::
++  join-path
  |=  p=(list @t)
  ^-  @t
  ?~  p  ''
  %+  rap  3
  |-  ^-  (list @)
  ?~  t.p  [i.p]~
  [i.p '/' $(p t.p)]
::
::  +prefix-id: first 8 bytes of a bearer or code. Idempotent on a
::  cord that is already that short.
::
++  prefix-id
  |=  t=@t
  ^-  @t
  =/  n  (met 3 t)
  (end [3 (min n 8)] t)
::
::  +secret-hash: map key for a bearer or authorization code.
::    Hash the exact cord the client presented.
::
++  secret-hash
  |=  t=@t
  ^-  @
  (shax t)
::
++  unique-scopes
  |=  s=(list scope)
  ^-  (list scope)
  ~(tap in (silt s))
::
::  +subset-scopes: every want is in have
::
++  subset-scopes
  |=  [want=(list scope) have=(list scope)]
  ^-  ?
  =/  h  (silt have)
  (levy want |=(s=scope (~(has in h) s)))
::
++  clip-scopes
  |=  [have=(list scope) keep=(list scope)]
  ^-  (list scope)
  =/  k  (silt keep)
  (skim have |=(s=scope (~(has in k) s)))
::
::  Owner log. Newest event is the head. Prefixes stay after the
::  maps that issued them have forgotten the bearer.
::
+$  log-via  ?(%page %poke %endpoint %sweep)
+$  logged-token
  $:  kind=?(%access %refresh)
      prefix=@t
      client=client-id
      resource=(unit resource)
      scopes=(list scope)
      expires=@da
  ==
::  next=~ means the token was removed. A missing edit means unchanged.
+$  token-edit
  $:  token=logged-token
      next=(unit (list scope))
  ==
+$  redeemed
  $%  $:  %code
          id=@t
          expires=@da
          redirect=@t
          challenge=@t
      ==
      $:  %refresh
          id=@t
          expires=@da
      ==
  ==
+$  log-body
  $%  $:  %registered
          who=address:eyre
          client=client
          grants=(list @t)
          auth=@t
      ==
      $:  %authorized
          decision=?(%approve %deny)
          client=client-id
          name=@t
          resource=(unit resource)
          redirect=@t
          oauth-state=@t
          challenge=@t
          requested=(list scope)
          granted=(list scope)
          previous=(unit (list scope))
          pending-id=@uv
          pending-expires=@da
          code=(unit [id=@t expires=@da])
          first=?
          edits=(list token-edit)
      ==
      $:  %revoked-scopes
          via=log-via
          client=client-id
          name=@t
          resource=(unit resource)
          dropped=(list scope)
          before=(list scope)
          after=(list scope)
          edits=(list token-edit)
      ==
      $:  %revoked-client
          via=log-via
          client=client
          approved=?
          grants=(list authorization)
          tokens=(list logged-token)
          pending=(list authz)
          codes=(list code)
      ==
      $:  %issued
          client=client-id
          name=@t
          resource=(unit resource)
          scopes=(list scope)
          access=logged-token
          refresh=logged-token
          redeemed=redeemed
      ==
      $:  %revoked-token
          via=log-via
          name=@t
          token=logged-token
      ==
  ==
+$  log-event
  $:  when=@da
      body=log-body
  ==
::
::  +token-edits: scope changes for these tokens if `keep` is what remains.
::
++  token-edits
  |=  [rows=(list logged-token) keep=(list scope)]
  ^-  (list token-edit)
  %+  murn  rows
  |=  t=logged-token
  ^-  (unit token-edit)
  =/  left  (clip-scopes scopes.t keep)
  ?:  =(left scopes.t)  ~
  ?:  =(~ left)  `[t ~]
  `[t `left]
::
++  as-token-info
  |=  [pre=@t client=client-id resource=(unit resource) scopes=(list scope) expires=@da]
  ^-  token-info
  [pre client resource scopes expires]
::
::  +add-query: append query params, encoding values
::
++  add-query
  |=  [uri=@t params=(list (pair @t @t))]
  ^-  @t
  ?~  params  uri
  =/  qs=tape
    |-  ^-  tape
    =/  piece
      :(weld (en-urlt:html (trip p.i.params)) "=" (en-urlt:html (trip q.i.params)))
    ?~  t.params  piece
    :(weld piece "&" $(params t.params))
  =/  has-q  ?=(^ (find "?" (trip uri)))
  (crip (weld (trip uri) (weld ?:(has-q "&" "?") qs)))
::
::  +login-target: path+query for Eyre's POST /~/login redirect field.
::    GET /~/login?redirect=... loops if the value contains "=" (urbit#7071),
::    so callers must POST the target or percent-encode it.
::
++  login-target
  |=  here=@t
  ^-  @t
  ?:  =('' here)  '/'
  ?:  (has-prefix here '/~/login')  '/'
  ?:  =('/' (cut 3 [0 1] here))  here
  =/  t  (trip here)
  =/  rest=tape
    ?:  =("https://" (scag 8 t))  (slag 8 t)
    ?:  =("http://" (scag 7 t))  (slag 7 t)
    ~
  =/  i  (find "/" rest)
  ?~  i  '/'
  (crip (slag u.i rest))
::
++  eyre-login-href
  |=  here=@t
  ^-  tape
  (weld "/~/login?redirect=" (en-urlt:html (trip (login-target here))))
::
::  +issuer: public issuer identifier. Metadata lives at the RFC 8414
::  path-insertion URL derived from this, not under the issuer path.
::
++  issuer
  |=  org=@t
  ^-  @t
  (cat 3 (chop-slash org) '/wicket')
::
::  +resource-path: path of a resource URL, including the leading slash
::
++  resource-path
  |=  [org=@t url=@t]
  ^-  @t
  =/  o  (chop-slash org)
  ?.  (on-origin o url)  ''
  =/  n  (met 3 o)
  ?:  =(o url)  ''
  (cut 3 [n (sub (met 3 url) n)] url)
::
::  +prm-url: protected-resource metadata URL served by %wicket
::
++  prm-url
  |=  [org=@t url=@t]
  ^-  @t
  (rap 3 (issuer org) '/oauth/protected-resource' (resource-path org url) ~)
::
::  +without-scopes: have, minus drop. ~ if drop is empty or not a subset.
::
++  without-scopes
  |=  [have=(list scope) drop=(list scope)]
  ^-  (unit (list scope))
  =/  d  (unique-scopes drop)
  ?:  =(~ d)  ~
  ?.  (subset-scopes d have)  ~
  `(skip have |=(s=scope (lien d |=(x=scope =(x s)))))
::
::  +form-pairs: urlencoded body, preserving duplicate keys
::
++  form-pairs
  |=  raw=@t
  ^-  (list [p=@t q=@t])
  ?:  =('' raw)  ~
  (fall (rush raw yquy:de-purl:html) ~)
::
++  pair-values
  |=  [key=@t pairs=(list [p=@t q=@t])]
  ^-  (list @t)
  %+  turn
    (skim pairs |=(pq=[p=@t q=@t] =(key p.pq)))
  |=(pq=[p=@t q=@t] q.pq)
::
::  Registration limits. Not owner-configurable.
::
++  idle-ttl        ~d1
++  unapproved-cap  32
++  rate-max        5
++  rate-window     ~h1
++  rate-map-cap    64
++  name-max        128
++  uri-max         512
++  uri-count-max   8
::
+$  rate-hit  [n=@ud since=@da]
+$  rate-map  (map address:eyre rate-hit)
+$  registration-verdict
  $%  [%ok ~]
      [%closed ~]
      [%denied ~]
      [%full ~]
      [%limited retry=@ud]
  ==
::
::  +window-open: since is still inside the rate window at now
::
++  window-open
  |=  [now=@da since=@da]
  ^-  ?
  (lth now (add since rate-window))
::
++  secs-until
  |=  [now=@da end=@da]
  ^-  @ud
  ?:  (gte now end)  1
  =/  s  (div (sub end now) ~s1)
  ?:  =(0 s)  1
  s
::
++  prune-recent
  |=  [now=@da recent=rate-map]
  ^-  rate-map
  %-  malt
  %+  skip  ~(tap by recent)
  |=  [a=address:eyre hit=rate-hit]
  ?:  (window-open now since.hit)  |
  &
::
++  fresh-count
  |=  [now=@da recent=rate-map]
  ^-  @ud
  (lent (skim ~(tap by recent) |=([a=address:eyre hit=rate-hit] (window-open now since.hit))))
::
++  soonest-retry
  |=  [now=@da recent=rate-map]
  ^-  @ud
  =/  ends=(list @da)
    %+  murn  ~(tap by recent)
    |=  [a=address:eyre hit=rate-hit]
    ?:  (window-open now since.hit)  `(add since.hit rate-window)
    ~
  ?~  ends  1
  (secs-until now (earliest i.ends t.ends))
::
++  earliest
  |=  [head=@da rest=(list @da)]
  ^-  @da
  |-
  ?~  rest  head
  ?:  (lth head i.rest)  $(rest t.rest)
  $(head i.rest, rest t.rest)
::
::  +admit-registration: whether this address may store a new client.
::    A refusal is decided from the maps as they are. Callers must not
::    write state when the result is anything but %ok.
::
++  admit-registration
  |=  $:  open=?
          =address:eyre
          now=@da
          denied=(set address:eyre)
          waiting=@ud
          recent=rate-map
      ==
  ^-  registration-verdict
  ?.  open  [%closed ~]
  ?:  (~(has in denied) address)  [%denied ~]
  ?:  (gte waiting unapproved-cap)  [%full ~]
  =/  hit  (~(get by recent) address)
  ?~  hit
    ?:  (gte (fresh-count now recent) rate-map-cap)
      [%limited (soonest-retry now recent)]
    [%ok ~]
  ?:  (window-open now since.u.hit)
    ?:  (gte n.u.hit rate-max)
      [%limited (secs-until now (add since.u.hit rate-window))]
    [%ok ~]
  ?:  (gte (fresh-count now recent) rate-map-cap)
    [%limited (soonest-retry now recent)]
  [%ok ~]
::
::  +note-registration: count one accepted registration and drop expired windows
::
++  note-registration
  |=  [now=@da =address:eyre recent=rate-map]
  ^-  rate-map
  =.  recent  (prune-recent now recent)
  =/  hit  (~(get by recent) address)
  ?~  hit
    (~(put by recent) address [1 now])
  (~(put by recent) address [+(n.u.hit) since.u.hit])
::
::  +idle-due: clients never approved whose created time is at least idle-ttl ago
::
++  idle-due
  |=  [now=@da clients=(list client) approved=(set client-id)]
  ^-  (list client-id)
  %+  murn  clients
  |=  c=client
  ?:  (~(has in approved) id.c)  ~
  ?:  (lte (add created.c idle-ttl) now)  `id.c
  ~
::
::  +next-wake: soonest removal time of an unapproved client, including a time
::    already past so a missed timer is armed again.
::
++  next-wake
  |=  [clients=(list client) approved=(set client-id)]
  ^-  (unit @da)
  =/  times=(list @da)
    %+  murn  clients
    |=  c=client
    ?:  (~(has in approved) id.c)  ~
    `(add created.c idle-ttl)
  ?~  times  ~
  `(earliest i.times t.times)
::
::  +sweep-idle: ids to delete, and the next wake among those that remain
::
++  sweep-idle
  |=  [now=@da clients=(list client) approved=(set client-id)]
  ^-  [dead=(list client-id) next=(unit @da)]
  =/  dead  (idle-due now clients approved)
  =/  gone  (silt dead)
  =/  live
    %+  skip  clients
    |=  c=client
    (~(has in gone) id.c)
  [dead (next-wake live approved)]
::
++  trim-ends
  |=  t=tape
  ^-  tape
  (flop (trim-lead (flop (trim-lead t))))
::
++  trim-lead
  |=  t=tape
  ^-  tape
  |-
  ?~  t  ~
  ?:  ?|  =(i.t ' ')
          =(i.t '\09')
      ==
    $(t t.t)
  t
::
++  split-char
  |=  [c=@tD t=tape]
  ^-  (list tape)
  =|  cur=tape
  =|  acc=(list tape)
  |-
  ?~  t  (flop [(flop cur) acc])
  ?:  =(i.t c)
    $(t t.t, cur ~, acc [(flop cur) acc])
  $(t t.t, cur [i.t cur])
::
++  parse-byte
  |=  t=tape
  ^-  (unit @ud)
  ?:  =(~ t)  ~
  =|  acc=@ud
  |-
  ?~  t  `acc
  ?.  &((gte i.t '0') (lte i.t '9'))  ~
  =/  next  (add (mul acc 10) (sub i.t '0'))
  ?:  (gth next 255)  ~
  $(t t.t, acc next)
::
++  parse-v4
  |=  t=tape
  ^-  (unit @if)
  =/  parts  (split-char '.' t)
  ?.  =((lent parts) 4)  ~
  =/  nums=(list @ud)
    %+  murn  parts
    |=  p=tape
    (parse-byte p)
  ?.  =((lent nums) 4)  ~
  =/  packed  `@if`(rep 3 (flop nums))
  `packed
::
++  hex-val
  |=  c=@tD
  ^-  (unit @)
  ?:  &((gte c '0') (lte c '9'))  `(sub c '0')
  ?:  &((gte c 'a') (lte c 'f'))  `(add 10 (sub c 'a'))
  ?:  &((gte c 'A') (lte c 'F'))  `(add 10 (sub c 'A'))
  ~
::
++  parse-hex-group
  |=  t=tape
  ^-  (unit @)
  =/  n  (lent t)
  ?:  |(=(0 n) (gth n 4))  ~
  =|  acc=@
  |-
  ?~  t  `acc
  ?~  v=(hex-val i.t)  ~
  $(t t.t, acc (add (mul acc 16) u.v))
::
++  colon-groups
  |=  t=tape
  ^-  (unit (list @))
  ?:  =(~ t)  `~
  =/  parts  (split-char ':' t)
  =|  acc=(list @)
  |-
  ?~  parts  `(flop acc)
  ?~  g=(parse-hex-group i.parts)  ~
  $(parts t.parts, acc [u.g acc])
::
++  pack-v6
  |=  gs=(list @)
  ^-  (unit @is)
  ?.  =((lent gs) 8)  ~
  =/  packed  `@is`(rep 4 (flop gs))
  `packed
::
++  parse-v6
  |=  t=tape
  ^-  (unit @is)
  =/  dbl  (find "::" t)
  ?~  dbl
    =/  gs  (colon-groups t)
    ?~  gs  ~
    (pack-v6 u.gs)
  =/  left  (scag u.dbl t)
  =/  right  (slag (add u.dbl 2) t)
  ?:  ?=(^ (find "::" right))  ~
  =/  lg  (colon-groups left)
  =/  rg  (colon-groups right)
  ?~  lg  ~
  ?~  rg  ~
  =/  n  (add (lent u.lg) (lent u.rg))
  ?:  (gte n 8)  ~
  (pack-v6 (weld u.lg (weld (reap (sub 8 n) 0) u.rg)))
::
::  +parse-address: dotted IPv4, or IPv6 with one "::" run. Brackets optional.
::
++  parse-address
  |=  raw=@t
  ^-  (unit address:eyre)
  =/  t  (trim-ends (trip raw))
  =?  t  &(?=(^ t) =('[' i.t) (gth (lent t) 2) =(']' (rear t)))
    (snip (tail t))
  =/  v4  (parse-v4 t)
  ?:  ?=(^ v4)  `[%ipv4 u.v4]
  =/  v6  (parse-v6 t)
  ?:  ?=(^ v6)  `[%ipv6 u.v6]
  ~
::
++  render-v4
  |=  a=@if
  ^-  tape
  :(weld (scow %ud (cut 3 [3 1] a)) "." (scow %ud (cut 3 [2 1] a)) "." (scow %ud (cut 3 [1 1] a)) "." (scow %ud (cut 3 [0 1] a)))
::
++  v6-groups
  |=  a=@is
  ^-  (list @)
  =/  i  0
  |-
  ?:  =(8 i)  ~
  [(cut 4 [(sub 7 i) 1] a) $(i +(i))]
::
++  hex-tape
  |=  n=@
  ^-  tape
  ?:  =(0 n)  "0"
  =|  acc=tape
  |-
  ?:  =(0 n)  acc
  $(n (rsh [2 1] n), acc [(nibble (end [2 1] n)) acc])
::
++  nibble
  |=  n=@
  ^-  @tD
  ?:  (lte n 9)  (add '0' n)
  (add 'a' (sub n 10))
::
++  zero-run
  |=  [gs=(list @) i=@ud]
  ^-  @ud
  =/  j  i
  |-
  ?:  =(8 j)  (sub j i)
  ?.  =(0 (snag j gs))  (sub j i)
  $(j +(j))
::
++  join-col
  |=  parts=(list tape)
  ^-  tape
  ?~  parts  ""
  ?~  t.parts  i.parts
  (weld i.parts (weld ":" $(parts t.parts)))
::
++  emit-v6
  |=  [gs=(list @) at=@ud len=@ud]
  ^-  tape
  ?:  (lth len 2)
    (join-col (turn gs hex-tape))
  =/  left  (scag at gs)
  =/  right  (slag (add at len) gs)
  (weld (join-col (turn left hex-tape)) (weld "::" (join-col (turn right hex-tape))))
::
++  compress-v6
  |=  gs=(list @)
  ^-  tape
  =/  best=[at=@ud len=@ud]  [0 0]
  =/  i  0
  |-
  ?:  =(8 i)  (emit-v6 gs at.best len.best)
  =/  run  (zero-run gs i)
  ?:  &((gth run 1) (gth run len.best))
    $(i +(i), best [i run])
  $(i +(i))
::
++  render-v6
  |=  a=@is
  ^-  tape
  (compress-v6 (v6-groups a))
::
++  render-address
  |=  a=address:eyre
  ^-  tape
  ?-  -.a
    %ipv4  (render-v4 +.a)
    %ipv6  (render-v6 +.a)
  ==
--
