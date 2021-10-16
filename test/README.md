RTMFP Library Tests and Examples
================================
This directory contains unit tests for the library, as well as samples/examples.

Samples, Examples, and Manual Tests
-----------------------------------
These programs all answer brief usage info with the `-h` option. For more information on
what's going on in each, check the source.

* [`tcrelay`](tcrelay.cpp): A relay/translator/proxy for RTMFP and RTMP. It can also speak a
  simplified form of RTMP for compatibility with buggy implementations. Video and audio
  messages will expire after configurable deadlines to help stay live during congestion.
  Can register with `redirector` for load balancing.
* [`redirector`](redirector.cpp): A simple load balancer implementing the
  [`http://zenomt.com/ns/rtmfp#redirector`](http://zenomt.com/ns/rtmfp#redirector) protocol.
  Usable as-is or as an example starting point for more sophisticated applications.
* [`echoserver`](echoserver.cpp): A sink and echo server using `FlashCryptoAdapter_OpenSSL`
  (but not RTMP-over-RTMFP messages or metadata). Attempts to open a return flow for any
  incoming flow and echo received messages, and otherwise is a message sink. Multithreaded.
  Demonstrates shutting down on interrupt/terminate signals in a `RunLoop`. Can register with
  `redirector` as a RedirectorClient example.
* [`rtclient`](rtclient.cpp): Simulate “real-time” video and audio traffic
  (cadence, packet size, message expiration, prioritization) using FlashCrypto
  (but not RTMP-over-RTMFP messages or data formats). Use with `echoserver`.
* [`static-redirector`](static-redirector.cpp): A simple statically-configured
  [Redirector](https://tools.ietf.org/html/rfc7016#section-3.5.1.4) for FlashCrypto
  that redirects any new incoming connection to one or more other addresses.
* [`fcclient`](fcclient.cpp): A simple connection maker using `FlashCryptoAdapter_OpenSSL`
  (but not RTMP-over-RTMFP messages or metadata). Exercises opening to FlashCrypto EPDs with
  fingerprints, required hostnames, or RTMFP URIs. Exercises HMAC and Session Sequence Number
  negotiation. Sends a short burst and terminates after 30 seconds. Use with `echoserver`.
* [`server`](server.cpp): A simple connection sink using PlainCrypto (no encryption) to
  test basic functionality.
* [`testclient`](testclient.cpp): A simple connection maker using PlainCrypto to
  test basic functionality.
* [`t2`](t2.cpp): Another simple connection maker using PlainCrypto that sends as much
  data as quickly as it can to a sink (like `server`) for 60 seconds.
* [`addrlist.hpp`](addrlist.hpp): Utility functions for parsing IP addresses and port numbers
  from command-line arguments used by many of the above programs.

Unit Tests
----------
These programs are run on `make ci`.

* [`tis`](tis.cpp): Initially and primarily to exercise `IndexSet`, but also
  exercises `List`, `Timer`, and `SelectRunLoop`. Should be decomposed and assertions
  added to detect failures automatically rather than require human inspection.
* [`testperform`](testperform.cpp): Exercises `Performer`, `Timer`, `SelectRunLoop`, and
  multithreaded synchronization. Also requires human inspection.
* [`testchecksums`](testchecksums.cpp): Test the Internet Checksum and CRC32 implementations.
* [`testlist`](testlist.cpp): Test `List`.
* [`testvlu`](testvlu.cpp): Test the Variable Length Unsigned and Option functions.
* [`testaddress`](testaddress.cpp): Test `Address`.
* [`testamf`](testamf.cpp): Test AMF0 functions.
* [`testtcmsg`](testtcmsg.cpp): Test TC (RTMP Flash “TinCan”) metadata and message helper functions.
* [`testhex`](testhex.cpp): Test hex encode/decode functions.
* [`testflowsync`](testflowsync.cpp): Test `FlowSyncManager`.
* [`testreorder`](testreorder.cpp): Test `ReorderBuffer`.
* [`testmedia`](testmedia.cpp): Test [`http://zenomt.com/ns/rtmfp#media`](http://zenomt.com/ns/rtmfp#media)
  `Media` helper functions.
