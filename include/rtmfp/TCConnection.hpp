#pragma once

// Copyright © 2022 Michael Thornburgh
// SPDX-License-Identifier: MIT

// Tin-Can client-side session layer (traditional NetConnection & NetStream)

#include "FlowSyncManager.hpp"
#include "ReorderBuffer.hpp"
#include "TCMessage.hpp"

namespace com { namespace zenomt {

namespace rtmp {

class TCStream;

class TCConnection : public Object {
public:
	using Args = std::vector<std::shared_ptr<AMF0>>;

	// A transaction response handler. success is true if the server
	// responds with `_result`, and false if `_error` or if the connection
	// closes. result will be nullptr (distinct from AMF0Null) on a connection
	// error, and AMF0Undefined if the server doesn't send an explicit
	// response. result will never be nullptr if success is true.
	using Handler = std::function<void(bool success, std::shared_ptr<AMF0> result)>;

	TCConnection(int debugLevel = 0); // Set debugLevel > 0 for debug information to stdout.
	~TCConnection();

	bool isOpen() const; // true if not closed and transport is open.
	bool isConnected() const; // true if not closed and connect() has succeeded.
	void close();

	// Queue the connect transaction. You must at least queue a connect before queuing other
	// commands or creating streams. If argObject is not nullptr, it is sent instead of the
	// default. If tcUrl, app, or objectEncoding are not present in argObject, they are set
	// from the tcUrl parameter and objectEncoding 0. This does not initiate a transport
	// session; that is left to transport-specific subclasses. Answer true if the message
	// was successfully queued.
	//
	// Note that some servers, such as Adobe Media Server, process connect() asynchronously,
	// and may reject a connection if commands such as createStream are received before
	// the connect is completely processed. For greater compatibility, wait for connect’s
	// response before issuing more commands (such as createStream).
	bool connect(const Handler &onResult, const std::string &tcUrl, const AMF0Object *argObject = nullptr, const Args &args = {});

	// Queue a non-transactional command. args includes the unfortunate but
	// traditional "command argument object", which will almost always be
	// AMF0Null. Answer true if the command was successfully queued.
	bool command(const std::string &command, const Args &args = {});

	// Queue a transaction. Answer true if the transaction was successfully queued.
	bool transact(const Handler &onResult, const std::string &command, const Args &args = {});

	// Answer a new TCStream (queuing a createStream command to the server to allocate a stream ID),
	// or nullptr on error.
	std::shared_ptr<TCStream> createStream();

	bool ignoreSetKeepaliveUserCommand { false }; // If true, ignore TC_USERCONTROL_SET_KEEPALIVE from the server.
	Time reorderWindowPeriod { 1.0 }; // For transports that can receive out-of-order, like RTMFP.
	Task onTransportOpen; // Called when the transport layer is open (e.g. RTMFP session to the server is connected).
	Task onClose;
	std::function<void(std::shared_ptr<AMF0> info)> onStatus; // Called with NetStatusEvents from the server.
	std::function<void(const std::string &command, const Args &args)> onCommand; // Called when the server makes an RPC.

	static std::shared_ptr<AMF0> firstArg(const Args &args); // answer empty shared_ptr if args is empty
	static std::shared_ptr<AMF0> safeFirstArg(const Args &args); // answer AMF0Undefined if args is empty

protected:
	friend class TCStream;

	virtual std::shared_ptr<WriteReceipt> write(uint32_t streamID, uint8_t messageType, uint32_t timestamp, const void *payload, size_t len, Time startWithin, Time finishWithin) = 0;
	std::shared_ptr<WriteReceipt> write(uint32_t streamID, uint8_t messageType, uint32_t timestamp, const Bytes &payload, Time startWithin, Time finishWithin);

	void onMessage(uint32_t streamID, uint8_t messageType, uint32_t timestamp, const uint8_t *payload, size_t len);
	void onCommandMessage(uint32_t streamID, uint8_t messageType, const uint8_t *payload, size_t len);
	void onControlCommand(const std::string &command, double transactionID, const Args &args);
	void onControlStatusMessage(std::shared_ptr<AMF0> info);
	void onStreamCommand(uint32_t streamID, const std::string &command, const Args &args);
	void onStreamMessage(uint32_t streamID, uint8_t messageType, uint32_t timestamp, const uint8_t *payload, size_t len);
	virtual void onUserControlMessage(const uint8_t *payload, size_t len);

	virtual void basicClose(bool isError);
	bool basicCommand(const std::string &command, double transactionID, const Args &args);
	bool basicTransact(const Handler &onResult, const std::string &command, const Args &args);

	void onTransactionResponse(bool success, double transactionID, const Args &args);
	void onConnectResponse(bool success, std::shared_ptr<AMF0> result, const Handler &onResult);
	virtual void deleteStream(uint32_t streamID);
	virtual bool validateCommandName(const std::string &command);
	virtual void syncStream(uint32_t streamID);

	int m_debugLevel;
	bool m_userOpen { true };
	bool m_transportOpen { false };
	bool m_tcOpen { false };
	double m_nextTID { 1.0 };
	std::map<uint32_t, std::shared_ptr<TCStream>> m_netStreams;
	std::map<double, Handler> m_transactions;
};

class TCStream : public Object {
public:
	using Args = std::vector<std::shared_ptr<AMF0>>;

	bool isOpen() const; // Answer true if not deleted and the server has allocated a stream ID.
	void deleteStream(); // Close and delete the TCStream.

	void closeStream(); // Send a closeStream command to stop a publish or play (does not delete the stream).

	// Set receipt's parent to the previously chained receipt, if any, and append to the chain.
	// See WriteReceiptChain::append() for more information.
	void chain(std::shared_ptr<WriteReceipt> receipt);

	// Update each chained receipt to startBy/finishBy the earlier of deadline or its current
	// value, then clear the chain. A deadline of INFINITY clears the chain but doesn't
	// change any startBy or finishBy times. Calls WriteReceiptChain::expire().
	void expireChain(Time deadline);

	// Queue a publish command to the server to request publishing. Watch
	// for code `NetStream.Publish.Start` or `NetStream.Publish.BadName` in
	// onStatus() to know if the publish succeeded or failed.
	void publish(const std::string &name, const Args &args = {});

	// All send* methods and sync() require that the stream is open (that
	// is, the server has allocated a stream ID and onOpen was called).
	std::shared_ptr<WriteReceipt> send(const std::string &command, const Args &args = {});
	std::shared_ptr<WriteReceipt> send(uint32_t timestamp, const std::string &command, const Args &args = {});

	std::shared_ptr<WriteReceipt> sendAudio(uint32_t timestamp, const void *bytes, size_t len, Time startWithin = INFINITY, Time finishWithin = INFINITY);
	std::shared_ptr<WriteReceipt> sendAudio(uint32_t timestamp, const Bytes &bytes, Time startWithin = INFINITY, Time finishWithin = INFINITY);

	std::shared_ptr<WriteReceipt> sendVideo(uint32_t timestamp, const void *bytes, size_t len, Time startWithin = INFINITY, Time finishWithin = INFINITY);
	std::shared_ptr<WriteReceipt> sendVideo(uint32_t timestamp, const Bytes &bytes, Time startWithin = INFINITY, Time finishWithin = INFINITY);

	// Align delivery of all video, audio, and data messages sent so far.
	// See RFC 7425 §5.2. Synchronization can cause a priority inversion; use with care.
	void sync();

	// Queue a play command to the server to subscribe to a stream.
	void play(const std::string &name, const Args &args = {});

	// Queue a command to the server to suspend or resume receipt of the
	// stream (pause), or the audio or video portions thereof.
	void pause(bool paused);
	void receiveAudio(bool shouldReceive);
	void receiveVideo(bool shouldReceive);

	Task onOpen; // Called when the server has allocated a stream ID.
	std::function<void(std::shared_ptr<AMF0> info)> onStatus; // Called with NetStatusEvents from the server.

	std::function<void(uint32_t timestamp, const std::string &command, const Args &args)> onData;
	std::function<void(uint32_t timestamp, const uint8_t *bytes, size_t len)> onAudio;
	std::function<void(uint32_t timestamp, const uint8_t *bytes, size_t len)> onVideo;

protected:
	friend class TCConnection;

	TCStream(std::shared_ptr<TCConnection> owner);
	TCStream() = delete;
	~TCStream();

	bool setStreamID(uint32_t streamID);
	void onCommandMessage(const std::string &command, const Args &args);
	void onStreamMessage(uint8_t messageType, uint32_t timestamp, const uint8_t *paylaod, size_t len);
	void onDataMessage(uint8_t messageType, uint32_t timestamp, const uint8_t *paylaod, size_t len);
	void queueCommand(const std::string &command, std::shared_ptr<AMF0> insertArg, const Args &args);
	void flushCommands();

	std::shared_ptr<TCConnection> m_owner;
	bool m_userOpen { true };
	uint32_t m_streamID { 0 };
	std::queue<Bytes> m_pendingCommands;
	WriteReceiptChain m_chain;
};

} // namespace rtmp

namespace rtmfp {

class RTMFPTCConnection : public rtmp::TCConnection {
public:
	using TCConnection::TCConnection;

	// Initialize to use `rtmfp` and initiate a session to Endpoint Discriminator `epd`.
	// This must be called before connect(). onTransportOpen is called when the
	// session is established, in case the session nonces or other session
	// information is needed to construct the connect message. Answer true on success
	// or false on error.
	bool init(RTMFP *rtmfp, const Bytes &epd);

	// Add candidate addresses for establishing a session to epd.
	void addCandidateAddress(const Address &addr, Time delay = 0);
	void addCandidateAddress(const struct sockaddr *addr, Time delay = 0);
	void addCandidateAddresses(const std::vector<Address> &addrs);

	bool refreshSession(); // Send a pre-abandoned message, for example to hasten detection of an address change.

	// Answer a flow in the same session as this connection with which to get
	// or set session attributes (e.g. session nonces, far address, rtt, keepalive
	// period, etc.), or nullptr if the session isn't established yet.
	Flow *sessionOpt() const;

	Bytes getServerFingerprint() const; // Answer empty if session not established.

protected:
	struct NetStreamTransport {
		~NetStreamTransport();
		SendFlow * openFlowForType(const std::shared_ptr<RecvFlow> &control, uint32_t streamID, uint8_t messageType);
		std::shared_ptr<WriteReceipt> write(const std::shared_ptr<RecvFlow> &control, uint32_t streamID, uint8_t messageType, uint32_t timestamp, const uint8_t *payload, size_t len, Time startWithin, Time finishWithin);
		void sync(uint32_t syncID);

		std::shared_ptr<SendFlow> m_video;
		std::shared_ptr<SendFlow> m_audio;
		std::shared_ptr<SendFlow> m_data;
		std::set<std::shared_ptr<RecvFlow>> m_recvFlows;
	};

	using rtmp::TCConnection::write;
	std::shared_ptr<WriteReceipt> write(uint32_t streamID, uint8_t messageType, uint32_t timestamp, const void *payload, size_t len, Time startWithin, Time finishWithin) override;

	virtual std::shared_ptr<ReorderBuffer> reorderBufferFactory(Time windowPeriod) = 0;
	void acceptFlow(std::shared_ptr<RecvFlow> flow);
	void setOnMessage(std::shared_ptr<RecvFlow> flow, uint32_t streamID, std::shared_ptr<ReorderBuffer> reorderBuffer);
	void deliverMessage(uint32_t streamID, const uint8_t *bytes, size_t len);
	bool shouldAlwaysDeliver(const uint8_t *bytes, size_t len);

	void basicClose(bool isError) override;
	void deleteStream(uint32_t streamID) override;
	void syncStream(uint32_t streamID) override;

	void onUserControlMessage(const uint8_t *payload, size_t len) override;
	void onSetKeepaliveUserCommand(const uint8_t *payload, size_t len);

	RTMFP *m_rtmfp { nullptr };
	FlowSyncManager m_syncManager;
	uint32_t m_nextSyncID { 0 };
	std::shared_ptr<SendFlow> m_controlSend;
	std::shared_ptr<RecvFlow> m_controlRecv;
	std::shared_ptr<SendFlow> m_sessionOptFlow;
	std::map<uint32_t, NetStreamTransport> m_netStreamTransports;
};

class RunLoopRTMFPTCConnection : public RTMFPTCConnection {
public:
	RunLoopRTMFPTCConnection(RunLoop *runloop, int debugLevel = 0) :
		RTMFPTCConnection(debugLevel),
		m_runloop(runloop)
	{}

protected:
	std::shared_ptr<ReorderBuffer> reorderBufferFactory(Time windowPeriod) override
	{
		return share_ref(new RunLoopReorderBuffer(m_runloop, windowPeriod), false);
	}

	RunLoop *m_runloop;
};

} // namespace rtmfp

} } // namespace com::zenomt
