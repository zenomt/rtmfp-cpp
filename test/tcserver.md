# TC Server

[`tcserver`](tcserver.cpp) is a simple live media server for [“TC” (RTMFP/RTMP
“_Tin-Can_”)](https://www.rfc-editor.org/rfc/rfc7425.html#section-5.1.1)
clients. It accepts RFC 7425 RTMFP, RTMP (TCP), and RFC 7425 styled
[RTWebSocket](https://github.com/zenomt/rtwebsocket) (TCP)
connections. It can be configured to use a simplified dialect of RTMP if
needed for compatibility with some buggy clients.

Currently TLS for RTMPS and Secure WebSockets (WSS) is not directly supported;
instead use a TLS reverse-proxy such as _nginx_ to terminate TLS connections.
Note however that real-time treatment of outbound media will not operate
ideally end-to-end in this configuration.

The server accepts the traditional TC control commands `connect`, `setPeerInfo`,
`createStream`, and `deleteStream`, and stream commands `publish`, `play`,
`closeStream`, `pause`, `receiveVideo`, and `receiveAudio`. A stream can have
any number of “data keyframes” controlled by `@setDataFrame` and `@clearDataFrame`
_data_ messages. Additionally, the server accepts `releaseStream`, `relay`,
`broadcast`, and `watch` commands, described below.

The server will perform P2P introduction to RTMFP clients that have issued
at least one `setPeerInfo` command.

RTWebSocket connections use the same message and metadata formats, and flow
association semantics, as described in RFC 7425 for RTMFP flows.

To help RTMFP clients rendezvous with RTMP and RTWebSocket clients at the
same server, especially when using _redirectors_, the server sends its RTMFP
fingerprint in the `serverFingerprint` member of the `connect` response _info
object_.

## Apps (Partitions)

Each client connects to a named partition (an “App”), specified by the `app`
member of the `connect` command’s argument object. The App provides a namespace
in the server for stream names, as well as the reach of the `broadcast` command
(described below). Within an App there may be at most one active publisher
for a stream name at a time; however, there can be any number of distinctly
named streams published in the same App at the same time.

Note: By convention, the `app` designator is typically set to the path component
of the `tcUrl` member of the `connect` command’s argument object, without the
leading slash (if any). However, this is not required.

If the `app` member is not present in the `connect` command’s argument object,
the App name will be derived from the `tcUrl` member in the conventional way.
If neither the `app` nor `tcUrl` members are present, the connection will be
rejected.

### Connection Parameters

Default settings for the connection can be overridden with query parameters
in the `tcUrl`. Parameters are specified as “`<name>=<value>`” and are separated
by `&`, `?`, or `;` characters. If there are multiple parameters with the
same name, a later one overrides the previous value.

The following parameter is recognized:

* `delaycc`: (Number) Infer congestion if the round-trip time exceeds
  the baseline/minimum observed round-trip time by at least this many
  seconds. Overrides the `-X` command-line setting.

## Authentication

One or more _authentication master keys_ can be set with the `-k` and `-K`
command-line options. If at least one key is set, then an _authentication
token_ is required to connect.

The `connect` command can take up to two additional string arguments after
the required command argument object. If one string argument is given, it is
interpreted as an _App-wide authentication token_. If two string arguments
are given, the first is interpreted as a _user name_, and the second is
interpreted as a _user-specific authentication token_ (or password).

The App-wide authentication token is the HMAC-SHA-256 keyed hash (expressed
in lower-case hexadecimal) of the App name with an authentication master key.
For example, for the App named `live/12345` and authentication master key
`supersecret`, the App-wide authentication token would be

    HMAC-SHA-256(k="supersecret", m="live/12345")
    df41d9cbe74f325250d6e0346dcd9e95fb837892f4a927c27cecf2664d639786

The user-specific authentication token is the HMAC-SHA-256 with an authentication
master key of the concatenation of the user name, an `@` (`COMMERCIAL AT`)
character, and the App name. For example, for a user name of `mike`, an App
named `live/12345`, and authentication master key `supersecret`, the user-specific
authentication token would be

    HMAC-SHA-256(k="supersecret", m="mike@live/12345")
    8bddf00ca7e31862fe17872c463df61eafde6518f565cb3def0e82a3b2d639d7

For convenience, the `tcserver` command can calculate these for you:

    $ ./tcserver -k supersecret live/12345 mike@live/12345
    {"@type":"auth","app":"live/12345","token":"df41d9cbe74f325250d6e0346dcd9e95fb837892f4a927c27cecf2664d639786"}
    {"@type":"auth","app":"mike@live/12345","token":"8bddf00ca7e31862fe17872c463df61eafde6518f565cb3def0e82a3b2d639d7"}

Give the App-wide authentication token as the first and only argument to the
`connect` command after the command argument object, where the user name would
go in a traditional `NetConnection.connect()`:

    "connect"
    1.0
    {
        "app": "live/12345",
        "objectEncoding": 0.0,
        "tcUrl": "rtmp://localhost/live/12345"
    }
    "df41d9cbe74f325250d6e0346dcd9e95fb837892f4a927c27cecf2664d639786"

Give the user name and user-specific authentication token as the first and
second arguments to the `connect` command after the command argument object,
where the user name and password would go in a traditional
`NetConnection.connect()`:

    "connect"
    1.0
    {
        "app": "live/12345",
        "objectEncoding": 0.0,
        "tcUrl": "rtmp://localhost/live/12345"
    }
    "mike"
    "8bddf00ca7e31862fe17872c463df61eafde6518f565cb3def0e82a3b2d639d7"

Note that the token would be in the clear in RTMP and RTWebSocket connections,
so RTMPS or WSS are recommended to protect the token from disclosure.

Note that RFC 7425 RTMFP connections are not authenticated with a public key
infrastructure (PKI), so connections are potentially vulnerable to man-in-the-middle
(MITM) attacks. To prevent disclosure of the authentication token to a MITM,
two mitigations are available:

1. The server can be run in
   “[Static Diffie-Hellman Keys](https://www.rfc-editor.org/rfc/rfc7425.html#section-4.3.3.5)”
   mode with the `-x` command-line option, such that the server has an
   [unforgeable](https://www.rfc-editor.org/rfc/rfc7425.html#section-4.3.4)
   [RFC 7425 fingerprint](https://www.rfc-editor.org/rfc/rfc7425.html#section-4.3.2).
   Clients can connect using an
   [endpoint discriminator](https://www.rfc-editor.org/rfc/rfc7425.html#section-4.4)
   [specifying the server’s fingerprint](https://www.rfc-editor.org/rfc/rfc7425.html#section-4.4.2.3)
   to ensure the connection is not intercepted. The server prints its
   fingerprint on startup.

2. RTMFP clients can prove possession of the authentication token to the server
   without disclosing it by further hashing it with HMAC-SHA-256 using the
   [server’s (binary) session nonce](https://www.rfc-editor.org/rfc/rfc7425.html#section-4.6.5)
   as the HMAC key. For example, for a plain authentication token string of
   `df41d9cbe74f325250d6e0346dcd9e95fb837892f4a927c27cecf2664d639786` and
   binary server nonce (that is, the “far nonce” at the client on its RTMFP
   connection to the server) of
   `55e154b9a21eaff92499897b384e2e9314b8c1305a383b66c365eaad3d83f4a0`, the
   client would send
   `a762c38f376a273a583714b342ee700348882476a2350fc4e74b700411246841` as the
   authentication token.

If the client successfully authenticates to the server over RTMFP, the
server will send an `authToken` to the client in the `connect` response _info
object_, hashed in the same way but using the client’s session nonce (that
is, the “near nonce” at the client) as the HMAC key, to prove to the client
that the server also knows the authentication token without disclosing it in
the clear. In the second case above, where the client didn’t disclose the plain
authentication token, this allows the client to know that there is
no MITM to the server. To continue the above examples, if the client’s near
binary session nonce (also the server’s far nonce) was
`cbc290212a52dad978da93870e6929a5050d838a18723620b92df9a530535442`, the server
would reply to the `connect` command with

    "_result"
    1.0
    NULL
    {
        "level": "status",
        "code": "NetConnection.Connect.Success",
        "description": "you connected!",
        "connectionID": "6965c14b8964ee016451bc44140504f1a67178cfca3a64b2df16683dd263c176",
        "objectEncoding": 0.0,
        "authToken": "bc4e260a541aa5c6cd498f414afd7f05c76bd6d731f726df268d0b1e8bf5a58c",
        "serverFingerprint": "4e47cbb7f2b5fdcaf9593ce1feb6d6639c639cfa8fb4691e7530c5dd5b029f8f",
        "serverInfo": "some info 12345",
        "capsEx": 0.0,
        "audioFourCcInfoMap": { "*": 4.0 },
        "videoFourCcInfoMap": { "*": 4.0 },
        "fourCcList": [ "*" ]
    }

The authentication token calculator can help you validate your implementation
using the `-K` option (capital `K` for a binary hex key); for example using
the values above including the client’s nonce:

    $ ./tcserver -K cbc290212a52dad978da93870e6929a5050d838a18723620b92df9a530535442 df41d9cbe74f325250d6e0346dcd9e95fb837892f4a927c27cecf2664d639786
    {"@type":"auth","app":"df41d9cbe74f325250d6e0346dcd9e95fb837892f4a927c27cecf2664d639786","token":"bc4e260a541aa5c6cd498f414afd7f05c76bd6d731f726df268d0b1e8bf5a58c"}

### User-Specific Properties

When authentication is enabled, user-specific properties and connection
settings can be encoded into the authenticated user name. The user name is
considered to be a list of settings of the form `<name>=<value>` (or just
`<name>` for flags) separated by `;` (`SEMICOLON`) characters. Unrecognized
setting names are ignored. The following setting names are currently recognized:

* `name`: (String) Publisher name. If not empty, it will appear as the `publisherName`
  member of `NetStream.Play.PublishNotify` stream status events, and as the
  `senderName` member of `onRelay` headers. The default publisher name is empty.
* `pri`: (Number) Maximum publishing priority. The default maximum publishing priority is 0.
* `xcl`: (Flag) “Exclusive”. If present, only one connection is allowed at a time for this
  authenticated user name. An existing connection in the same App with the same user name will be disconnected.
* `nbf`: (Number) “Not Before”; connections aren’t allowed before this Unix time (default negative infinity).
* `exp`: (Number) “Expires At”; disconnect by this Unix time (default infinity).
* `use_by`: (Number) Connect no later than this Unix time (default infinity).
* `exi`: (Number) “Expires In”; disconnect after this many seconds (default infinity).
* `pub`: (Number) Maximum number of simultaneous publishes allowed in this connection (default unlimited).

Example: user name `67890;name=mike;pri=5;exp=1832700000` encodes an ignored
portion `67890`, a publisher name of `mike`, a maximum publishing priority
of 5, and an expiration time of January 28 2028 19:20:00 UTC. To calculate the
user-specific authentication token for this user name assuming authentication
master key `supersecret` and app `live/12345`:

    $ ./tcserver -k supersecret '67890;name=mike;pri=5;exp=1832700000@live/12345'
    {"@type":"auth","app":"67890;name=mike;pri=5;exp=1832700000@live/12345","token":"5f9f4c0692998b02c15d7a8a1d80ca530db1b1e93fa69cb8bb1c765b32f3bab6"}

Example using [`tcpublish`](tcpublish.cpp) to publish Big Buck Bunny to
`localhost` with these authentication settings and credentials, using and
requiring hashed authentication tokens, and publishing at priority 3:

    $ ./tcpublish -mM 'rtmfp://67890;name=mike;pri=5;exp=1832700000:5f9f4c0692998b02c15d7a8a1d80ca530db1b1e93fa69cb8bb1c765b32f3bab6@localhost/live/12345#BigBuckBunny?priority=3' /path/to/bbb.flv

## Streaming

Subscribers can request a stream by the name under which it is originally
published, or with the SHA-256 hash of the name. Hashed stream names are
specified as `sha256:<hex-digits>`, where “hex-digits” are the 64 _lower case_
hexadecimal digits of the SHA-256 hash of the originally published name. For
example:

    sha256:2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae

is the hashed name of a stream called “`foo`”. You can’t publish to a hashed
name. This enables a simple access control, where just the hashed name of the
stream can be shared with clients that should only be able to subscribe, and
the plain name shared (or generated) only with (or by) clients authorized to
publish it. For convenience, the hashed name is sent to the publisher in the
`NetStream.Publish.Start` status event’s _info object_ as the `hashname`
member. A `NetStream.Publish.BadName` status event is sent if the stream name
is unacceptable or if a stream by that name is already being published and
it was not preempted.

By default, to match the expected behavior of traditional TC servers such as
Adobe Media Server, timestamps on stream messages are translated so that
streams begin at timestamp `0` on a new subscribe, and timestamps on new
publishes for the same stream name are stitched together to be contiguous for
a continuous subscriber. To disable this behavior and receive the timestamps
exactly as sent by the publisher, add an `asis` query parameter to the stream
name.  For example, to receive an as-is version of “`foo`”, issue a `play`
command for either of the following stream names:

    foo?asis
    sha256:2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae?asis

When subscribing to a stream that has already been published, the server will
send the most recently received video keyframe, if available, along with video
and audio configuration information and all data keyframes, to the new
subscriber. This provides an immediate start but may show a garbled picture
until the next keyframe, depending on the video codec being used and the
amount of motion.

Note: some clients (such as Videolan Client “VLC”) have trouble if there are
discontinuities in a TC stream, which can happen if video or audio frames
expire and are abandoned before they can be transmitted.

### Terminating Another Client’s Publish

Use the `releaseStream` control command to terminate the publish of a stream
by another client. You must use the plain (non-hashed) name of the stream,
just like when publishing. This is usually used when a publisher is stuck or
has crashed, to allow a new publish to replace the stuck one.

    "releaseStream"
    0.0
    NULL
    "foo"

This command has no effect if a stream by that name is not currently being
published, or if it is being published with the same or higher priority than
the caller’s maximum publishing priority (default 0, see below). If a publish
is terminated, a `NetStream.Publish.BadName` stream status event is sent to
the publisher.

### Adjusting Real-Time Treatment For Stream Playback

By default, when sending stream messages to a subscriber, the server will use
the queue lifetimes and other treatments as specified by the corresponding
command-line arguments or their default values. The subscriber can override
these default settings by specifying query parameters in the stream name
sent to the `play` command.

Like a query in a URI, query parameters follow the first `?` (`QUESTION MARK`)
in the stream name. Parameters are specified as “`<name>=<value>`” and are
separated by `&` (`AMPERSAND`), `?`, or `;` (`SEMICOLON`) characters. If there
are multiple parameters with the same name, a later one overrides the previous
value.

Any query parameters present in the stream name override their corresponding
default settings. The following parameters are recognized:

- `audioLifetime`: (Number) Audio queue lifetime (seconds).
- `videoLifetime`: (Number) Video queue lifetime.
- `finishByMargin`: (Number) Additional time to complete a video or audio frame if transmission has started.
- `expirePreviousGop`: Whether to expire the previous Group of Pictures (GOP) early
  when a new GOP starts. Disabled for values `0`, `no`, or `false`; any other value
  (including blank) enables.
- `previousGopStartByMargin`: (Number) Revised transmission start deadline
  when expiring the previous GOP (seconds after start of new GOP).
- `asis`: Whether to repeat the timestamps exactly as sent by the publisher as
  described above in **Streaming**. Disabled for values `0`, `no`, or `false`;
  any other value (including blank) enables.

For safety, the server caps each parameter above at 10 seconds or twice the
default value, whichever is greater.

Example: `BigBuckBunny?asis&audioLifetime=0.25&videoLifetime=1`

### Publish Priority and Preemption

Like the `play` command, the stream name for a `publish` can contain query
parameters. Query parameters follow the first `?` character in the stream
name and are separated by `&`, `?`, or `;` characters.

Streams are published with a _publish priority_, used for preempting or
overriding another publish to the same stream name. If unspecified in the
`publish` stream name’s query, the publish priority defaults to negative
infinity. A higher numeric priority overrides a lower priority value.

The following query parameter is recognized:

- `priority`: (Number) Publish priority. The publish priority is capped to
  the maximum for the user (capped to 0 by default; override the user’s
  cap with the `pri` user-specific property).

Example: `BigBuckBunny?priority=-1`

If a publisher is preempted, it will receive a `NetStream.Publish.BadName`
event. Otherwise the new publisher will receive a `NetStream.Publish.BadName`
event if the stream is already being published.

The priority of the stream is sent to subscribers as the `priority` member
of the `NetStream.Play.PublishNotify` status event.

## Relaying and Broadcasting Messages

Each connected client has a _Connection ID_ assigned by the server. For RTMFP
clients this is typically the client’s
[Peer ID](https://www.rfc-editor.org/rfc/rfc7425.html#section-4.3.2);
for other connections it is randomly assigned by the server. The Connection
ID is available in the `connect` response’s _info object_ as the `connectionID`
member.

A client can send a message directly to another client connected to the same
server (in the same or a different App) using the `relay` command. The first
normal argument (after the unused command argument object, which should be
AMF0 `NULL`) is the recipient’s connection ID. Relayed messages are sent as
an `onRelay` command to the target client on stream ID 0. The `onRelay` command
includes a header object with the sender’s connection ID in `sender` and, if
not empty, the sender’s publisher name in `senderName`. For example, to relay
a message to Connection ID `1f9a5f4769fef5884d321e969b6ef7b64fe8db5f11c12637`,
the client would send an AMF0 Command Message on stream ID 0:

    "relay"
    0.0
    NULL
    "1f9a5f4769fef5884d321e969b6ef7b64fe8db5f11c12637"
    "this is a relay message"
    5.0

The target client, if it is connected, would receive the following AMF0 Command
Message on stream ID 0 (assuming the sender’s connection ID is
`6965c14b8964ee016451bc44140504f1a67178cfca3a64b2df16683dd263c176`):

    "onRelay"
    0.0
    NULL
    { "sender": "6965c14b8964ee016451bc44140504f1a67178cfca3a64b2df16683dd263c176" }
    "this is a relay message"
    5.0

Command argument objects are not used or relayed, and should be `NULL` as
shown. The `relay` command is non-transactional so the transaction ID should
be `0` as shown.

A connected client can broadcast a message to all clients (including itself)
in the same App using the `broadcast` command. Broadcasts are treated like a
relay to all clients in the App, and each client receives the message as
though it was a relay. For example, sending:

    "broadcast"
    0.0
    NULL
    "this is a broadcast"
    "foo"

results in an `onRelay` command being sent to each client in the App on stream
ID 0, that looks like (assuming the sender’s connection ID is
`6965c14b8964ee016451bc44140504f1a67178cfca3a64b2df16683dd263c176` and its
publisher name is `mike`):

    "onRelay"
    0.0
    NULL
    {
        "sender": "6965c14b8964ee016451bc44140504f1a67178cfca3a64b2df16683dd263c176",
        "senderName": "mike"
    }
    "this is a broadcast"
    "foo"

## Watching For Client Disconnections

A client can request to be notified if another client disconnects from the
server with the `watch` command. The first normal argument (after the unused
command argument object, which should be AMF0 `NULL`) is the Connection ID
to watch. For example, to be notified when Connection ID
`1f9a5f4769fef5884d321e969b6ef7b64fe8db5f11c12637` disconnects:

    "watch"
    0.0
    NULL
    "1f9a5f4769fef5884d321e969b6ef7b64fe8db5f11c12637"

If the requested Connection ID disconnects (or is not currently connected),
an `onDisconnected` command is sent to the watcher:

    "onDisconnected"
    0.0
    NULL
    "1f9a5f4769fef5884d321e969b6ef7b64fe8db5f11c12637"

## Server Shutdown

To shut down the server gracefully, send it a `SIGTERM` signal. The server
will unregister from any RTMFP _redirectors_ and send a
`NetConnection.Shutdown.Notify` status event to all clients. The server will
shut down once all clients have disconnected. The server will disconnect any
remaining clients that have not voluntarily closed by the shutdown deadline
(set with the `-t` option, by default 5 minutes).

The server will shut down immediately on receiving a second `SIGTERM` signal,
or on receiving a `SIGINT` signal.

## TODO

* Support [`http://zenomt.com/ns/rtmfp#media`](http://zenomt.com/ns/rtmfp#media)
* User-specific constraints
  - relay and broadcast rate limits
