// Copyright © 2021 Michael Thornburgh
// SPDX-License-Identifier: MIT

#include <unistd.h>
#include "../include/rtmfp/PosixPlatformAdapter.hpp"

namespace com { namespace zenomt { namespace rtmfp {

PosixPlatformAdapter::PosixPlatformAdapter(RunLoop *runloop) :
	m_rtmfp(nullptr),
	m_runloop(runloop)
{
	m_isOpen = std::make_shared<bool>(true);
}

PosixPlatformAdapter::~PosixPlatformAdapter()
{
	close();
}

void PosixPlatformAdapter::setRtmfp(RTMFP *rtmfp)
{
	if(rtmfp and not m_rtmfp)
	{
		m_rtmfp = rtmfp;
		m_rtmfpAlarm = m_runloop->scheduleRel(
			[rtmfp] (const std::shared_ptr<Timer> &sender, Time now) {
				rtmfp->doTimerWork();
				sender->setNextFireTime(now + rtmfp->howLongToSleep());
			}, 0, 1);
	}
}

RTMFP * PosixPlatformAdapter::getRtmfp() const
{
	return m_rtmfp;
}

RunLoop * PosixPlatformAdapter::getRunLoop() const
{
	return m_runloop;
}

std::shared_ptr<Address> PosixPlatformAdapter::addUdpInterface(int port, int family)
{
	Address addr;
	if(not addr.setFamily(family))
		return std::shared_ptr<Address>();
	addr.setPort(port);

	return addUdpInterface(addr.getSockaddr());
}

std::shared_ptr<Address> PosixPlatformAdapter::addUdpInterface(const struct sockaddr *addr)
{
	Address tmpAddr;
	struct UdpInterface uif;
	std::shared_ptr<Address> rv;

	if(not tmpAddr.setSockaddr(addr))
		return rv;

	uif.m_family = addr->sa_family;

	if((uif.m_fd = socket(uif.m_family, SOCK_DGRAM, 0)) < 0)
		return rv;

	union Address::in_sockaddr boundAddr;
	socklen_t addrLen = sizeof(boundAddr);
	if( (bind(uif.m_fd, tmpAddr.getSockaddr(), tmpAddr.getSockaddrLen()))
	 or (getsockname(uif.m_fd, &boundAddr.s, &addrLen))
	)
	{
		::close(uif.m_fd);
		return rv;
	}

	rv = share_ref(new Address(&boundAddr.s), false);

	int interfaceID = (int)m_interfaces.append(uif);
	m_runloop->registerDescriptor(uif.m_fd, RunLoop::READABLE,
		[interfaceID, uif, this] { this->onInterfaceReadable(uif.m_fd, interfaceID); });
	m_rtmfp->addInterface(interfaceID);

	return rv;
}

void PosixPlatformAdapter::close()
{
	*m_isOpen = false;

	long name;
	while((name = m_interfaces.first()))
	{
		int fd = m_interfaces.at(name).m_fd;
		m_runloop->unregisterDescriptor(fd);
		::close(fd);
		m_interfaces.remove(name);
	}

	if(m_rtmfpAlarm)
		m_rtmfpAlarm->cancel();
}

Time PosixPlatformAdapter::getCurrentTime()
{
	return m_runloop->getCurrentTime();
}

void PosixPlatformAdapter::onHowLongToSleepDidChange()
{
	m_rtmfpAlarm->setNextFireTime(getCurrentTime() + m_rtmfp->howLongToSleep());
}

bool PosixPlatformAdapter::notifyWhenInterfaceWritable(int interfaceID, const std::function<bool(void)> &onwritable)
{
	if(m_interfaces.has(interfaceID))
	{
		m_runloop->registerDescriptor(m_interfaces.at(interfaceID).m_fd, RunLoop::WRITABLE,
			[onwritable] (RunLoop *sender, int fd, RunLoop::Condition cond) {
				if(not onwritable())
					sender->unregisterDescriptor(fd, RunLoop::WRITABLE);
			});

		return true;
	}

	return false;
}

bool PosixPlatformAdapter::writePacket(const void *bytes, size_t len, int interfaceID, const struct sockaddr *addr, socklen_t addrLen)
{
	if(m_interfaces.has(interfaceID))
	{
		Address dstAddr(addr);
		const UdpInterface &uif = m_interfaces.at(interfaceID);

		if(dstAddr.canMapToFamily(uif.m_family))
			dstAddr.setFamily(uif.m_family);
		else
			return false;

		return sendto(uif.m_fd, bytes, len, 0, dstAddr.getSockaddr(), dstAddr.getSockaddrLen()) >= 0;
	}

	return false;
}

bool PosixPlatformAdapter::perform(unsigned long thread, const Task &task)
{
	std::shared_ptr<bool> isOpen = m_isOpen;
	m_runloop->doLater([isOpen, task] { if(*isOpen) task(); });
	return true;
}

void PosixPlatformAdapter::onShutdownComplete()
{
	if(onShutdownCompleteCallback)
		onShutdownCompleteCallback();
}

void PosixPlatformAdapter::onInterfaceReadable(int fd, int interfaceID)
{
	union Address::in_sockaddr addr_u;
	struct sockaddr *recvAddr = &addr_u.s;
	socklen_t addrLen = sizeof(addr_u);
	uint8_t buf[8192];

	int rv = recvfrom(fd, (char *)buf, sizeof(buf), 0, recvAddr, &addrLen);
	if(rv >= 0)
	{
		Address tmp(recvAddr);
		if(tmp.canMapToFamily(AF_INET))
			tmp.setFamily(AF_INET);

		m_rtmfp->onReceivePacket(buf, rv, interfaceID, tmp.getSockaddr());
	}
}

} } } // namespace com::zenomt::rtmfp
