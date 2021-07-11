// Copyright © 2021 Michael Thornburgh
// SPDX-License-Identifier: MIT

#include <cerrno>
#include <cstring>

#include "../include/rtmfp/PosixPlatformAdapter.hpp"

#include <unistd.h>
#include <netinet/ip.h>

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

	{
		// try to turn on receive of TOS/TCLASS for both families. depending
		// on OS, this might work for combo sockets (and be necessary to get
		// TOS from mapped senders). it shouldn't hurt.
		int on = 1;
		setsockopt(uif.m_fd, IPPROTO_IP, IP_RECVTOS, &on, sizeof(on));
		setsockopt(uif.m_fd, IPPROTO_IPV6, IPV6_RECVTCLASS, &on, sizeof(on));
	}

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

bool PosixPlatformAdapter::writePacket(const void *bytes, size_t len, int interfaceID, const struct sockaddr *addr, socklen_t addrLen, int tos)
{
	if(m_interfaces.has(interfaceID))
	{
		Address dstAddr(addr);
		const UdpInterface &uif = m_interfaces.at(interfaceID);

		if(dstAddr.canMapToFamily(uif.m_family))
			dstAddr.setFamily(uif.m_family);
		else
			return false;

		bool ipv6 = dstAddr.getFamily() == AF_INET6;

		struct cmsghdr cmsg[2]; // big enough and aligned
		cmsg[0].cmsg_len = CMSG_LEN(sizeof(int));
		cmsg[0].cmsg_level = ipv6 ? IPPROTO_IPV6 : IPPROTO_IP;
		cmsg[0].cmsg_type = ipv6 ? IPV6_TCLASS : IP_TOS;
		memcpy(CMSG_DATA(cmsg), &tos, sizeof(tos));

		struct iovec vec;
		vec.iov_base = (void *)bytes;
		vec.iov_len = len;

		struct msghdr msg;
		msg.msg_name = (void *)dstAddr.getSockaddr();
		msg.msg_namelen = dstAddr.getSockaddrLen();
		msg.msg_iov = &vec;
		msg.msg_iovlen = 1;
		msg.msg_control = tos ? cmsg : nullptr;
		msg.msg_controllen = tos ? CMSG_LEN(sizeof(int)) : 0;
		msg.msg_flags = 0;

		ssize_t rv = ::sendmsg(uif.m_fd, &msg, 0);
		if((rv < 0) and tos and (EINVAL == errno))
		{
			// FreeBSD has a long-standing bug for setting IPPROTO_IP/IP_TOS. and
			// maybe other operating systems behave poorly with ancillary data.
			// retry sendmsg without msg_control. if this was the problem, then
			// we should eventually stop trying to send ancillary data on this session.
			msg.msg_control = nullptr;
			msg.msg_controllen = 0;
			rv = ::sendmsg(uif.m_fd, &msg, 0);
		}

		return rv >= 0;
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
	uint8_t buf[8192];
	struct cmsghdr cmsg_buf[8]; // big enough to receive at least a few command messages, we should only need one

	struct iovec vec;
	vec.iov_base = buf;
	vec.iov_len = sizeof(buf);

	struct msghdr msg;
	msg.msg_name = &addr_u;
	msg.msg_namelen = sizeof(addr_u);
	msg.msg_iov = &vec;
	msg.msg_iovlen = 1;
	msg.msg_control = cmsg_buf;
	msg.msg_controllen = sizeof(cmsg_buf);
	msg.msg_flags = 0;

	ssize_t rv = recvmsg(fd, &msg, 0);
	if(rv >= 0)
	{
		Address tmp(&addr_u.s);
		if(tmp.canMapToFamily(AF_INET))
			tmp.setFamily(AF_INET);

		int tos = 0;
		for(struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg))
		{
			if( ((IPPROTO_IP == cmsg->cmsg_level) and (IP_TOS == cmsg->cmsg_type))
			 or ((IPPROTO_IPV6 == cmsg->cmsg_level) and (IPV6_TCLASS == cmsg->cmsg_type))
			)
			{
				memcpy(&tos, CMSG_DATA(cmsg), sizeof(tos));
				break;
			}
		}

		m_rtmfp->onReceivePacket(buf, rv, interfaceID, tmp.getSockaddr(), tos);
	}
}

} } } // namespace com::zenomt::rtmfp
