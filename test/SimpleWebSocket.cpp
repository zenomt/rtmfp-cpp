// Copyright © 2022 Michael Thornburgh
// SPDX-License-Identifier: MIT

#include <cassert>
#include <cctype>
#include <cstring>
#include <regex>

#include "rtmfp/Retainer.hpp"
#include "rtmfp/URIParse.hpp"

#include "SimpleWebSocket.hpp"

namespace {

const uint8_t WS_FLAG_FIN = 0x80;
const uint8_t WS_FLAG_MSK = 0x80;
const uint8_t WS_OPCODE_MASK = 0x0f;
const uint8_t WS_LENGTH_MASK = 0x7f;
const size_t WS_LENGTH_16 = 126;
const size_t WS_LENGTH_64 = 127;
const size_t WS_MAX_FRAME = 1 << 24; // 16MB, big enough for anything reasonable

enum {
	WS_OP_CONTINUATION = 0x0,
	WS_OP_TEXT         = 0x1,
	WS_OP_BINARY       = 0x2,
	WS_OP_CLOSE        = 0x8,
	WS_OP_PING         = 0x9,
	WS_OP_PONG         = 0xa
};

std::string _replace(const std::string &s, const char *pattern, const char *fmt)
{
	return std::regex_replace(s, std::regex(pattern), fmt);
}

std::string _trim(const std::string &s)
{
	auto left = s.data();
	auto right = left + s.size();

	while((left < right) and std::isspace(*left))
		left++;
	while((right > left) and std::isspace(*(right - 1)))
		right--;
	return std::string(left, right);
}

bool _istchar(int c)
{
	// RFC 7230 §3.2.6
	switch(c)
	{
	case '!':
	case '#':
	case '$':
	case '%':
	case '&':
	case '\'':
	case '*':
	case '+':
	case '-':
	case '.':
	case '^':
	case '_':
	case '`':
	case '|':
	case '~':
		return true;
	default:
		return ::isdigit(c) or ::isalpha(c);
	}
}

std::string _base64enc(const void *bytes, size_t len, bool pad = true)
{
	const char *alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	const uint8_t *cursor = (const uint8_t *)bytes;
	const uint8_t *limit = cursor + len;
	std::string rv;
	uint8_t b;

	while(cursor < limit)
	{
		b = *cursor >> 2;
		rv.push_back(alphabet[b]);

		b = (*cursor & 0x03) << 4;
		cursor++;
		if(cursor < limit)
		{
			b += *cursor >> 4;
			rv.push_back(alphabet[b]);

			b = (*cursor & 0x0f) << 2;
			cursor++;
			if(cursor < limit)
			{
				b += *cursor >> 6;
				rv.push_back(alphabet[b]);
				rv.push_back(alphabet[*cursor & 0x3f]);

				cursor++;
			}
			else
			{
				rv.push_back(alphabet[b]);
				if(pad)
					rv.append("=");
			}
		}
		else
		{
			rv.push_back(alphabet[b]);
			if(pad)
				rv.append("==");
		}
	}

	return rv;
}

}

namespace com { namespace zenomt { namespace websock {

// --- HeaderBodyStream

HeaderBodyStream::HeaderBodyStream(std::shared_ptr<IStreamPlatformAdapter> platform) :
	m_platform(platform)
{
}

Time HeaderBodyStream::getCurrentTime()
{
	return m_platform->getCurrentTime();
}

bool HeaderBodyStream::init()
{
	auto myself = retain_ref(this);
	m_platform->setOnReceiveBytesCallback([myself] (const void *bytes, size_t len) { return myself->onReceiveBytes(bytes, len); });
	m_platform->setOnStreamDidCloseCallback([myself] { myself->setClosedState(); });
	return true;
}

void HeaderBodyStream::close()
{
	retain();
	clearCallbacks();
	setClosedState();
	release();
}

void HeaderBodyStream::shutdown()
{
	if(m_state < S_CLOSING)
	{
		m_state = S_CLOSING;
		scheduleWrite();
	}
}

void HeaderBodyStream::writeBytes(const void *bytes, size_t len)
{
	const uint8_t *cursor = (const uint8_t *)bytes;
	const uint8_t *limit = cursor + len;
	m_rawOutputBuffer.insert(m_rawOutputBuffer.end(), cursor, limit);
	scheduleWrite();
}

void HeaderBodyStream::writeBytes(const Bytes &bytes)
{
	writeBytes(bytes.data(), bytes.size());
}

void HeaderBodyStream::writeBytes(const std::string &s)
{
	writeBytes(s.data(), s.size());
}

bool HeaderBodyStream::onReceiveBytes(const void *bytes, size_t len)
{
	auto myself = retain_ref(this);

	const uint8_t *cursor = (const uint8_t *)bytes;
	const uint8_t *limit = cursor + len;

	while((m_state < S_CLOSING) and (cursor < limit))
	{
		if(m_headerComplete)
			cursor = onBodyBytes(cursor, limit);
		else
			cursor = onHeaderBytes(cursor, limit);
	}

	return true;
}

void HeaderBodyStream::notifyWhenWritable(const onwritable_f &onwritable)
{
	m_client_onwritable = onwritable;
	scheduleWrite();
}

void HeaderBodyStream::clearCallbacks()
{
	onError = nullptr;
	m_client_onwritable = nullptr;
}

void HeaderBodyStream::setClosedState()
{
	Task onError_f;

	if(m_state < S_ERROR)
	{
		m_state = S_ERROR;
		m_platform->onClientClosed();
		swap(onError_f, onError);
	}
	clearCallbacks();

	if(onError_f)
		onError_f();
}

void HeaderBodyStream::scheduleWrite()
{
	if((m_state < S_ERROR) and not m_writeScheduled)
	{
		auto myself = retain_ref(this);
		m_platform->notifyWhenWritable([myself] { return myself->onWritable(); });
		m_writeScheduled = true;
	}
}

bool HeaderBodyStream::onWritable()
{
	if(writeRawOutputBuffer())
		return true;

	if((m_state < S_CLOSING) and m_client_onwritable)
	{
		if(not m_client_onwritable())
			m_client_onwritable = nullptr;
		writeRawOutputBuffer();
		return true;
	}

	// if we get here then we're flushed
	if(S_CLOSING == m_state)
		setClosedState();
	
	m_writeScheduled = false;
	return false;
}

bool HeaderBodyStream::writeRawOutputBuffer()
{
	if((m_state < S_ERROR) and not m_rawOutputBuffer.empty())
	{
		m_platform->writeBytes(m_rawOutputBuffer.data(), m_rawOutputBuffer.size());
		m_rawOutputBuffer.clear();
		return true;
	}
	return false;
}

// --- SimpleHttpStream

std::string SimpleHttpStream::getStartLine() const
{
	return m_startLine;
}

bool SimpleHttpStream::hasHeader(const std::string &name) const
{
	return m_headers.count(URIParse::lowercase(name)) > 0;
}

std::string SimpleHttpStream::getHeader(const std::string &name) const
{
	std::string rv;
	auto vals = getHeaderValues(name);
	bool first = true;
	for(auto it = vals.begin(); it != vals.end(); it++)
	{
		if(not first)
			rv.push_back(',');
		rv.append(*it);
		first = false;
	}
	return rv;
}

std::vector<std::string> SimpleHttpStream::getHeaderValues(const std::string &name) const
{
	auto it = m_headers.find(URIParse::lowercase(name));
	if(it != m_headers.end())
		return it->second;
	return std::vector<std::string>();
}

bool SimpleHttpStream::isToken(const std::string &s)
{
	for(auto it = s.begin(); it != s.end(); it++)
		if(not _istchar(*it))
			return false;
	return not s.empty();
}

const uint8_t * SimpleHttpStream::onHeaderBytes(const uint8_t *bytes, const uint8_t *limit)
{
	const uint8_t *cursor = bytes;

	while(cursor < limit)
	{
		uint8_t c = *cursor++;
		m_headerBlock.push_back(c);

		if('\n' == c)
		{
			if(m_gotNewline)
			{
				parseHeaderBlock();
				break;
			}
			m_gotNewline = true;
		}
		else if('\r' != c)
			m_gotNewline = false;
	}

	return cursor;
}

void SimpleHttpStream::onHeadersComplete()
{
	if(onHttpHeadersReceived)
		onHttpHeadersReceived();
}

void SimpleHttpStream::parseHeaderBlock()
{
	m_headerComplete = true;

	std::string tmp = _replace(m_headerBlock, "\r\n", "\n");
	tmp = _replace(tmp, "\r", " ");
	tmp = _replace(tmp, "\n[ \t]", " ");

	auto lines = URIParse::split(tmp, "\n");
	bool needStartLine = true;
	for(auto it = lines.begin(); it != lines.end(); it++)
	{
		if(needStartLine)
		{
			m_startLine = *it;
			needStartLine = false;
		}
		else if(it->size())
		{
			auto parts = URIParse::split(*it, ":", 2);
			if((2 != parts.size()) or not isToken(parts[0]))
			{
				setClosedState();
				return;
			}

			m_headers[URIParse::lowercase(parts[0])].push_back(_trim(parts[1]));
		}
	}

	onHeadersComplete();
}

void SimpleHttpStream::clearCallbacks()
{
	HeaderBodyStream::clearCallbacks();
	onHttpHeadersReceived = nullptr;
}

void SimpleHttpStream::reset()
{
	m_gotNewline = false;
	m_headerBlock.clear();
	m_headers.clear();
	m_startLine.clear();
}

// --- SimpleWebSocket

void SimpleWebSocket::sendBinaryMessage(const void *bytes, size_t len)
{
	writeFrame(WS_OP_BINARY, bytes, len);
}

void SimpleWebSocket::sendBinaryMessage(const Bytes &bytes)
{
	sendBinaryMessage(bytes.data(), bytes.size());
}

void SimpleWebSocket::sendTextMessage(const std::string &message)
{
	writeFrame(WS_OP_TEXT, message.data(), message.size());
}

void SimpleWebSocket::cleanClose()
{
	writeFrame(WS_OP_CLOSE, nullptr, 0);
	m_closing = true;
}

const uint8_t * SimpleWebSocket::onBodyBytes(const uint8_t *bytes, const uint8_t *limit)
{
	auto myself = retain_ref(this);

	m_inputBuffer.insert(m_inputBuffer.end(), bytes, limit);
	const uint8_t *buffer = m_inputBuffer.data();
	const uint8_t *cursor = buffer;
	const uint8_t *inputLimit = cursor + m_inputBuffer.size();

	while(cursor < inputLimit)
	{
		long consumed = onInput(cursor, inputLimit);
		if(consumed < 0)
		{
			setClosedState();
			return limit;
		}
		if(0 == consumed)
			break;
		cursor += consumed;
	}

	shiftInputBuffer(cursor - buffer);

	(void) myself;

	return limit;
}

void SimpleWebSocket::shiftInputBuffer(size_t amount)
{
	if(amount)
	{
		assert(amount <= m_inputBuffer.size());
		size_t newSize = m_inputBuffer.size() - amount;
		uint8_t *buf = m_inputBuffer.data();
		::memmove(buf, buf + amount, newSize);
		m_inputBuffer.resize(newSize);
	}
}

long SimpleWebSocket::onInput(const uint8_t *bytes, const uint8_t *limit)
{
	size_t remaining = limit - bytes;
	assert(remaining > 0);
	const uint8_t *cursor = bytes;
	size_t needed = 2;

	if(remaining < needed)
		return 0;
	bool isFinal = *cursor & WS_FLAG_FIN;
	int opcode = *cursor & WS_OPCODE_MASK;
	cursor++;

	bool hasMask = *cursor & WS_FLAG_MSK;
	size_t payloadLength = *cursor & WS_LENGTH_MASK;
	cursor++;

	if(hasMask)
		needed += 4;
	if(WS_LENGTH_16 == payloadLength)
		needed += 2;
	else if(WS_LENGTH_64 == payloadLength)
		needed += 8;
	if(remaining < needed)
		return 0;

	if(WS_LENGTH_16 == payloadLength)
	{
		payloadLength = *cursor++; payloadLength <<= 8;
		payloadLength += *cursor++;
	}
	else if(WS_LENGTH_64 == payloadLength)
	{
		payloadLength = *cursor++; payloadLength <<= 8;
		payloadLength += *cursor++; payloadLength <<= 8;
		payloadLength += *cursor++; payloadLength <<= 8;
		payloadLength += *cursor++; payloadLength <<= 8;
		payloadLength += *cursor++; payloadLength <<= 8;
		payloadLength += *cursor++; payloadLength <<= 8;
		payloadLength += *cursor++; payloadLength <<= 8;
		payloadLength += *cursor++;
	}
	if(payloadLength > WS_MAX_FRAME)
		return -1;
	needed += payloadLength;
	if(remaining < needed)
		return 0;

	// at this point there's enough remaining for the entire frame
	uint32_t mask = 0;
	if(hasMask)
	{
		mask += *cursor++; mask <<=8;
		mask += *cursor++; mask <<=8;
		mask += *cursor++; mask <<=8;
		mask += *cursor++;
	}

	const uint8_t *payloadLimit = cursor + payloadLength;
	assert(payloadLimit <= limit);

	if(hasMask)
	{
		int maskShift = 24;
		m_tmpFrame.clear();

		while(cursor < payloadLimit)
		{
			m_tmpFrame.push_back(*cursor++ ^ ((mask >> maskShift) & 0xff));
			maskShift -= 8;
			if(maskShift < 0)
				maskShift = 24;
		}

		onFrame(opcode, isFinal, m_tmpFrame.data(), payloadLength);
	}
	else
		onFrame(opcode, isFinal, cursor, payloadLength);

	return needed;
}

void SimpleWebSocket::onFrame(int opcode, bool isFinal, const uint8_t *bytes, size_t len)
{
	switch(opcode)
	{
	case WS_OP_CONTINUATION:
		onContinuationFrame(isFinal, bytes, len);
		break;

	case WS_OP_PING:
		onPingFrame(bytes, len);
		break;

	case WS_OP_PONG:
		onPongFrame(bytes, len);
		break;

	case WS_OP_CLOSE:
		onCloseFrame();
		break;

	default:
		onMessageFrame(opcode, isFinal, bytes, len);
		break;
	}
}

void SimpleWebSocket::onContinuationFrame(bool isFinal, const uint8_t *bytes, size_t len)
{
	if(m_fragmentedMessageOpcode < 0)
	{
		setClosedState();
		return;
	}

	m_fragmentedMessage.insert(m_fragmentedMessage.end(), bytes, bytes + len);
	if(isFinal)
	{
		int opcode = m_fragmentedMessageOpcode;
		m_fragmentedMessageOpcode = -1;
		onMessageFrame(opcode, true, m_fragmentedMessage.data(), m_fragmentedMessage.size());
		m_fragmentedMessage.clear();
	}
}

void SimpleWebSocket::onPingFrame(const uint8_t *bytes, size_t len)
{
	writeFrame(WS_OP_PONG, bytes, len);
}

void SimpleWebSocket::onPongFrame(const uint8_t *bytes, size_t len)
{
}

void SimpleWebSocket::onCloseFrame()
{
	if(m_closing)
		setClosedState();
	else
		cleanClose();
}

void SimpleWebSocket::onMessageFrame(int opcode, bool isFinal, const uint8_t *bytes, size_t len)
{
	if(m_fragmentedMessageOpcode > 0)
	{
		setClosedState();
		return;
	}

	if(not isFinal)
	{
		m_fragmentedMessageOpcode = opcode;
		m_fragmentedMessage.insert(m_fragmentedMessage.end(), bytes, bytes + len);
	}
	else
	{
		switch(opcode)
		{
		case WS_OP_TEXT:
			if(onTextMessage)
				onTextMessage(std::string(bytes, bytes + len));
			break;

		case WS_OP_BINARY:
			if(onBinaryMessage)
				onBinaryMessage(bytes, len);
			break;

		default:
			break; // we don't know what this is.
		}
	}
}

void SimpleWebSocket::clearCallbacks()
{
	SimpleHttpStream::clearCallbacks();
	onOpen = nullptr;
	onBinaryMessage = nullptr;
	onTextMessage = nullptr;
}

void SimpleWebSocket::onHeadersComplete()
{
	SimpleHttpStream::onHeadersComplete();

	auto startline = URIParse::split(m_startLine, " ");
	if((startline.size() != 3) or (0 != startline[0].compare("GET")))
	{
		setClosedState();
		return;
	}

	std::string websocketKey = getHeader("sec-websocket-key");

	if( (0 != URIParse::lowercase(getHeader("upgrade")).compare("websocket"))
	 or (std::string::npos == URIParse::lowercase(getHeader("connection")).find("upgrade"))
	 or (0 != getHeader("sec-websocket-version").compare("13"))
	 or (websocketKey.empty())
	)
	{
		setClosedState();
		return;
	}

	websocketKey.append("258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
	uint8_t md[160/8] = { 0 };
	sha1(md, websocketKey.data(), websocketKey.size());
	std::string websocketAccept = _base64enc(md, sizeof(md));

	writeBytes(std::string(
		"HTTP/1.1 101 Switching Protocols\r\n"
		"Upgrade: websocket\r\n"
		"Connection: Upgrade\r\n"
		"Sec-WebSocket-Accept: ") + websocketAccept + std::string("\r\n"
		"\r\n"
	));

	m_handshakeComplete = true;
	if(onOpen)
		onOpen();
}

void SimpleWebSocket::writeFrame(int opcode, const void *bytes_, size_t len)
{
	const uint8_t *bytes = (const uint8_t *)bytes_;
	uint8_t basicLengthField = 0;

	if(len > 65535)
		basicLengthField = WS_LENGTH_64;
	else if(len > 125)
		basicLengthField = WS_LENGTH_16;
	else
		basicLengthField = len;

	Bytes frame;
	frame.push_back(WS_FLAG_FIN | (opcode & WS_OPCODE_MASK));
	frame.push_back(0 | basicLengthField); // servers don't mask data
	if(WS_LENGTH_64 == basicLengthField)
	{
		frame.push_back((len >> 56) & 0xff);
		frame.push_back((len >> 48) & 0xff);
		frame.push_back((len >> 40) & 0xff);
		frame.push_back((len >> 32) & 0xff);
		frame.push_back((len >> 24) & 0xff);
		frame.push_back((len >> 16) & 0xff);
		frame.push_back((len >>  8) & 0xff);
		frame.push_back((len      ) & 0xff);
	}
	else if(WS_LENGTH_16 == basicLengthField)
	{
		frame.push_back((len >>  8) & 0xff);
		frame.push_back((len      ) & 0xff);
	}

	if(len)
		frame.insert(frame.end(), bytes, bytes + len);

	writeBytes(frame);
}

} } } // namespace com::zenomt::websock
