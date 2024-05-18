#pragma once

// Copyright © 2022 Michael Thornburgh
// SPDX-License-Identifier: MIT

#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "IStreamPlatformAdapter.hpp"

namespace com { namespace zenomt { namespace websock {

using Bytes = std::vector<uint8_t>;

class HeaderBodyStream : public Object {
public:
	HeaderBodyStream(std::shared_ptr<IStreamPlatformAdapter> platform);
	HeaderBodyStream() = delete;

	Time getCurrentTime();
	virtual bool init();
	virtual void close();
	virtual void shutdown();

	Task onError;

	// schedule bytes to be written. may be called at any time, but just once from
	// the onwritable notification gives the least buffering.
	void writeBytes(const void *bytes, size_t len);
	void writeBytes(const Bytes &bytes);
	void writeBytes(const std::string &s);

	using onwritable_f = IStreamPlatformAdapter::onwritable_f;
	void notifyWhenWritable(const onwritable_f &onwritable);

protected:
	enum State { S_OPEN, S_CLOSING, S_ERROR };
	virtual const uint8_t * onHeaderBytes(const uint8_t *bytes, const uint8_t *limit) { return limit; }
	virtual const uint8_t * onBodyBytes(const uint8_t *bytes, const uint8_t *limit) { return limit; }

	bool onReceiveBytes(const void *bytes, size_t len);
	virtual void clearCallbacks();
	void setClosedState();
	void scheduleWrite();
	bool onWritable();
	bool writeRawOutputBuffer();

	std::shared_ptr<IStreamPlatformAdapter> m_platform;
	bool m_headerComplete { false };
	State m_state { S_OPEN };
	bool m_writeScheduled { false };
	onwritable_f m_client_onwritable;
	Bytes m_rawOutputBuffer;
};

class SimpleHttpStream : public HeaderBodyStream {
public:
	using HeaderBodyStream::HeaderBodyStream;

	std::string getStartLine() const;
	bool hasHeader(const std::string &name) const;
	std::string getHeader(const std::string &name) const; // for everything except "set-cookie" RFC 7230 §3.2.2
	std::vector<std::string> getHeaderValues(const std::string &name) const; // pretty much just for "set-cookie"

	Task onHttpHeadersReceived;

protected:
	const uint8_t * onHeaderBytes(const uint8_t *bytes, const uint8_t *limit) override;

	virtual void onHeadersComplete();

	void reset();
	void parseHeaderBlock();
	void clearCallbacks() override;

	bool m_gotNewline { false };
	std::string m_headerBlock;
	std::map<std::string, std::vector<std::string>> m_headers;
	std::string m_startLine;
};

// Note: a simple *server* WebSocket
class SimpleWebSocket : public SimpleHttpStream {
public:
	using SimpleHttpStream::SimpleHttpStream;

	void sendBinaryMessage(const void *bytes, size_t len);
	void sendBinaryMessage(const Bytes &bytes);
	void sendTextMessage(const std::string &message);

	Task onOpen;
	std::function<void(const uint8_t *bytes, size_t len)> onBinaryMessage;
	std::function<void(const std::string &message)> onTextMessage;

	void cleanClose();

	virtual void sha1(void *dst, const void *msg, size_t len) = 0;

protected:
	const uint8_t * onBodyBytes(const uint8_t *bytes, const uint8_t *limit) override;
	void shiftInputBuffer(size_t amount);
	long onInput(const uint8_t *bytes, const uint8_t *limit);
	void onFrame(int opcode, bool isFinal, const uint8_t *bytes, size_t len);
	void onContinuationFrame(bool isFinal, const uint8_t *bytes, size_t len);
	void onPingFrame(const uint8_t *bytes, size_t len);
	void onPongFrame(const uint8_t *bytes, size_t len);
	void onCloseFrame();
	void onMessageFrame(int opcode, bool isFinal, const uint8_t *bytes, size_t len);
	void clearCallbacks() override;
	void onHeadersComplete() override;
	void writeFrame(int opcode, const void *bytes, size_t len);

	bool m_handshakeComplete { false };
	bool m_closing { false };
	Bytes m_inputBuffer;
	Bytes m_tmpFrame; // so we can re-use rather than allocating every time
	Bytes m_fragmentedMessage;
	int m_fragmentedMessageOpcode { -1 };
};

class SimpleWebSocket_OpenSSL : public SimpleWebSocket {
public:
	// This module provides a concrete SimpleWebSocket using OpenSSL for SHA-1.
	// Note: *not* WSS (TLS). That's a job for an IStreamPlatformAdapter.

	using SimpleWebSocket::SimpleWebSocket;

	void sha1(void *dst, const void *msg, size_t len) override;
};

} } } // namespace com::zenomt::websock
