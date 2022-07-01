#pragma once

// Copyright © 2021 Michael Thornburgh
// SPDX-License-Identifier: MIT

#include "List.hpp"
#include "RunLoop.hpp"
#include "rtmfp.hpp"

namespace com { namespace zenomt { namespace rtmfp {

class PosixPlatformAdapter : public IPlatformAdapter {
public:
	PosixPlatformAdapter(RunLoop *runloop);
	~PosixPlatformAdapter();

	void   setRtmfp(RTMFP *rtmfp);
	RTMFP *getRtmfp() const;

	RunLoop *getRunLoop() const;

	std::shared_ptr<Address> addUdpInterface(int port = 0, int family = AF_INET);
	std::shared_ptr<Address> addUdpInterface(const struct sockaddr *bindAddr);

	Task onShutdownCompleteCallback;

	virtual void close();

	Time getCurrentTime() override;
	void onHowLongToSleepDidChange() override;
	bool notifyWhenInterfaceWritable(int interfaceID, const std::function<bool(void)> &onwritable) override;
	bool writePacket(const void *bytes, size_t len, int interfaceID, const struct sockaddr *addr, socklen_t addrLen, int tos) override;
	bool perform(unsigned long thread, const Task &task) override;
	void onShutdownComplete() override;

	size_t maxWritesPerInterfaceWritable { 4 };

protected:
	struct UdpInterface {
		int m_fd;
		int m_family;
	};

	void onInterfaceReadable(int fd, int interfaceID);
	long receiveOnePacket(int fd, int interfaceID);

	RTMFP                  *m_rtmfp;
	RunLoop                *m_runloop;
	List<UdpInterface>      m_interfaces;
	std::shared_ptr<Timer>  m_rtmfpAlarm;
	std::shared_ptr<bool>   m_isOpen;
};

} } } // namespace com::zenomt::rtmfp
