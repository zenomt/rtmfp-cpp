// Copyright © 2022 Michael Thornburgh
// SPDX-License-Identifier: MIT

#include "SimpleWebSocketMessagePlatformAdapter.hpp"

using namespace com::zenomt::websock;

namespace com { namespace zenomt { namespace rtws {

SimpleWebSocketMessagePlatformAdapter::SimpleWebSocketMessagePlatformAdapter(std::shared_ptr<IStreamPlatformAdapter> platform) :
	m_platform(platform)
{}

bool SimpleWebSocketMessagePlatformAdapter::init(std::shared_ptr<SimpleWebSocket> websock)
{
	if(m_websock)
		return false;

	auto myself = share_ref(this);

	m_websock = websock;
	m_websock->onOpen = [this, myself] { (void)myself; onWebsockOpen(); };
	m_websock->onError = [this, myself] { (void)myself; onWebsockError(); };
	m_websock->init();

	return true;
}

Time SimpleWebSocketMessagePlatformAdapter::getCurrentTime()
{
	return m_platform->getCurrentTime();
}

void SimpleWebSocketMessagePlatformAdapter::notifyWhenWritable(const onwritable_f &onwritable)
{
	m_websock->notifyWhenWritable(onwritable);
}

void SimpleWebSocketMessagePlatformAdapter::setOnReceiveBytesCallback(const onreceivebytes_f &onreceivebytes)
{
	m_websock->onBinaryMessage = [onreceivebytes] (const uint8_t *bytes, size_t len) { onreceivebytes(bytes, len); return true; };
}

void SimpleWebSocketMessagePlatformAdapter::setOnStreamDidCloseCallback(const Task &onstreamdidclose)
{
	m_onstreamdidclose = onstreamdidclose;
}

void SimpleWebSocketMessagePlatformAdapter::doLater(const Task &task)
{
	m_platform->doLater(task);
}

bool SimpleWebSocketMessagePlatformAdapter::writeBytes(const void *bytes, size_t len)
{
	if(not m_websock)
		return false;

	m_websock->sendBinaryMessage(bytes, len);
	return true;
}

void SimpleWebSocketMessagePlatformAdapter::onClientClosed()
{
	onOpen = nullptr;

	if(m_websock)
		m_websock->close();
}

// ---

void SimpleWebSocketMessagePlatformAdapter::onWebsockOpen()
{
	if(onOpen)
		onOpen();
}

void SimpleWebSocketMessagePlatformAdapter::onWebsockError()
{
	if(m_onstreamdidclose)
		m_onstreamdidclose();
}

} } } // namespace com::zenomt::rtws
