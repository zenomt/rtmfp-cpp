#pragma once

// Copyright © 2022 Michael Thornburgh
// SPDX-License-Identifier: MIT

#include "RTWebSocket.hpp"
#include "SimpleWebSocket.hpp"

namespace com { namespace zenomt { namespace rtws {

class SimpleWebSocketMessagePlatformAdapter : public IMessagePlatformAdapter, public Object {
public:
	SimpleWebSocketMessagePlatformAdapter(std::shared_ptr<IStreamPlatformAdapter> platform);
	bool init(std::shared_ptr<websock::SimpleWebSocket> websock);

	Task onOpen;

	Time getCurrentTime() override;
	void notifyWhenWritable(const onwritable_f &onwritable) override;
	void setOnReceiveBytesCallback(const onreceivebytes_f &onreceivebytes) override;
	void setOnStreamDidCloseCallback(const Task &onstreamdidclose) override;
	void doLater(const Task &task) override;
	bool writeBytes(const void *bytes, size_t len) override;
	void onClientClosed() override;

protected:
	void onWebsockOpen();
	void onWebsockError();

	std::shared_ptr<IStreamPlatformAdapter> m_platform;
	std::shared_ptr<websock::SimpleWebSocket> m_websock;
	Task m_onstreamdidclose;
};

} } } // namespace com::zenomt::rtws
