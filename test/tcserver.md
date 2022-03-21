# TC Server

This is a simple live media server for “TC” (RTMFP/RTMP “_Tin-Can_”) clients.
It accepts RFC 7425 RTMFP as well as RTMP (TCP) connections. It can be
configured to use a simplified dialect of RTMP for compatibility with some
buggy clients.

Currently RTMPS is not directly supported; instead use a TLS reverse-proxy
such as _nginx_ to terminate RTMPS. Note however that real-time treatment of
outbound media will not operate ideally end-to-end in this configuration.

The server accepts traditional TC commands such as `connect`, `setPeerInfo`,
`createStream`, `deleteStream`, `publish`, `play`, `closeStream`, `pause`,
`receiveVideo`, and `receiveAudio`. A stream can have any number of “data
keyframes” controlled by `@setDataFrame` and `@clearDataFrame` _data_ messages.

The server will perform RTMFP P2P introduction to clients that have issued
at least one `setPeerInfo` command.

## Apps

Each client connects to a server-side “App”, specified by the `app` member
of the `connect` command’s argument object. The App provides a namespace in
the server for stream names, as well as the reach of the `broadcast` command
(described below). Within an App there may be at most one publisher for any
stream name at once; however, there can be any number of distinctly named
streams published in the same App at once.

## Authentication

One or more _authentication master keys_ can be set with the `-k` and `-K`
command-line options. If at least one key is set, then an _authentication
token_ is required to connect. An authentication token is the HMAC-SHA-256
hash (expressed in lower-case hexadecimal) of the App name with an authentication
master key. For example, for the App named `live/12345` and authentication
master key `supersecret`, the authentication token would be

    HMAC-SHA-256(k="supersecret", m="live/12345")
    df41d9cbe74f325250d6e0346dcd9e95fb837892f4a927c27cecf2664d639786

For convenience, the `tcserver` command can calculate this for you:

    $ ./tcserver -k supersecret live/12345
    ,auth,df41d9cbe74f325250d6e0346dcd9e95fb837892f4a927c27cecf2664d639786,live/12345

The authentication token is given as the first normal argument to the `connect`
command, where the user name would go in a traditional `NetConnection.connect()`:

    "connect"
    1.0
    {
        "app": "live/12345",
        "objectEncoding": 0.0,
        "tcUrl": "rtmp://localhost/live/12345"
    }
    "df41d9cbe74f325250d6e0346dcd9e95fb837892f4a927c27cecf2664d639786"

Note that this token would be in the clear in RTMP connections, so RTMPS is
recommended to protect the token from disclosure.

Note that RFC 7425 RTMFP connections are not authenticated with a public key
infrastructure (PKI), so connections are potentially vulnerable to man-in-the-middle
(MITM) attacks. To prevent disclosure of the authentication token to a MITM,
two mitigations are available:

1. The server can be run in “Static Diffie-Hellman Keys” mode with the `-x`
   command-line option, such that the server has an unforgeable RFC 7425
   fingerprint. Clients can connect using an endpoint discriminator specifying
   the server’s fingerprint to ensure the connection is not intercepted. When
   run in this mode, the server prints its fingerprint on startup.

2. RTMFP clients can prove posession of the authentication token to the server
   without disclosing it by further hashing it with HMAC-SHA-256 using the
   server's (binary) session nonce as the HMAC key. For example, for a plain
   authentication token of
   `df41d9cbe74f325250d6e0346dcd9e95fb837892f4a927c27cecf2664d639786` and
   server nonce (that is, the “far nonce” at the client on its RTMFP connection
   to the server) of
   `55e154b9a21eaff92499897b384e2e9314b8c1305a383b66c365eaad3d83f4a0`, the
   client would send
   `a762c38f376a273a583714b342ee700348882476a2350fc4e74b700411246841` as the
   authentication token.

In either case, if the client successfully authenticates to the server, the
server will send an `authToken` to the client in the `connect` response _info
object_, hashed in the same way but using the client’s session nonce (that
is, the “near nonce” at the client) as the HMAC key, to prove to the client
that the server also knows the authentication token without disclosing it in
the clear. In the second case, this allows the client to know that there is
no MITM to the server. To continue the above examples, if the client’s near
nonce (also the server’s far nonce) was
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
        "authToken": "bc4e260a541aa5c6cd498f414afd7f05c76bd6d731f726df268d0b1e8bf5a58c"
    }

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
member.

By default, to match the expected behavior of traditional TC servers such as
Adobe Media Server, timestamps on stream messages are translated so that
streams begin at timestamp `0` on a new subscribe, and timestamps on new
publishes for the same stream name are stitched together to be contiguous for
a continuous subscriber. To disable this behavior and receive the timestamps
exactly as sent by the publisher, prepend `asis:` to the stream name. For
example, to receive an as-is version of “`foo`”, issue a `play` command for
either of the following stream names:

    asis:foo
    asis:sha256:2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae

When subscribing to a stream that has already been published, the server will
send the most recently received video keyframe, if available, along with video
and audio configuration information and all data keyframes, to the new
subscriber.  This provides an immediate start but may show a garbled picture
until the next keyframe, depending on the video codec being used and the
amount of motion.

Note: some clients (such as Videolan Client “VLC”) have trouble if there are
discontinuities in a TC stream, which can happen if video or audio frames
expire and are abandoned before they can be transmitted.

## Relaying and Broadcasting Messages

Each connected client has a _Connection ID_ assigned by the server. For RTMFP
clients this is typically the client’s Peer ID; for other connections it is
randomly assigned by the server. The Connection ID is available in the `connect`
response’s _info object_ as the `connectionID` member.

A client can send a message directly to another client connected to the same
server (in the same or a different App) using the `relay` command. The first
normal argument (after the unused command argument object, which should be
AMF0 `NULL`) is the recipient's connection ID. Relayed messages are sent as
an `onRelay` command to the target client on stream ID 0. The `onRelay` command
includes the sender's connection ID. For example, to relay a message to
Connection ID `1f9a5f4769fef5884d321e969b6ef7b64fe8db5f11c12637`, the client
would send an AMF0 Command Message on stream ID 0:

    "relay"
    0.0
    NULL
    "1f9a5f4769fef5884d321e969b6ef7b64fe8db5f11c12637"
    "this is a relay message"
    5.0

The target client, if it is connected, would receive the following AMF0 Command
Message on stream ID 0 (assuming the sender's connection ID is
`6965c14b8964ee016451bc44140504f1a67178cfca3a64b2df16683dd263c176`):

    "onRelay"
    0.0
    NULL
    "6965c14b8964ee016451bc44140504f1a67178cfca3a64b2df16683dd263c176"
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
`6965c14b8964ee016451bc44140504f1a67178cfca3a64b2df16683dd263c176`):

    "onRelay"
	0.0
    NULL
    "6965c14b8964ee016451bc44140504f1a67178cfca3a64b2df16683dd263c176"
    "this is a broadcast"
    "foo"

## TODO

* App constraints
  - lifetime
  - expiration date/time
  - max clients
  - max published streams
  - not-before date/time
  - relay and broadcast rate limits
* `releaseStream` command for override/preemption
* Stats