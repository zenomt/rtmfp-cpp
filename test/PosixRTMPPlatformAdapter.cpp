// Copyright © 2021 Michael Thornburgh
// SPDX-License-Identifier: MIT

#include <cerrno>
#include <cstdlib>
#include <cstring>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <unistd.h>

#include "PosixRTMPPlatformAdapter.hpp"

namespace com { namespace zenomt { namespace rtmp {

static const size_t INPUT_BUFFER_SIZE = 65536;
static const size_t WRITE_SIZE_PER_SELECT = 8192;
static const int UNSENT_LOWAT = 16384;

PosixRTMPPlatformAdapter::PosixRTMPPlatformAdapter(RunLoop *runloop) :
	m_rtmp(nullptr),
	m_rtmpOpen(false),
	m_runloop(runloop),
	m_fd(-1)
{
	m_inputBuffer = (uint8_t *)calloc(1, INPUT_BUFFER_SIZE);
}

PosixRTMPPlatformAdapter::~PosixRTMPPlatformAdapter()
{
	close();
	if(m_inputBuffer)
		free(m_inputBuffer);
	m_inputBuffer = nullptr;
}

void PosixRTMPPlatformAdapter::close()
{
	m_runloop->unregisterDescriptor(m_fd);
	::close(m_fd); // TODO really?
	m_fd = -1;
}

bool PosixRTMPPlatformAdapter::setSocketFd(int fd)
{
	if(m_fd >= 0)
		return false;
	m_fd = fd;

#ifdef TCP_NOTSENT_LOWAT
	{
		int val = UNSENT_LOWAT;
		::setsockopt(m_fd, IPPROTO_TCP, TCP_NOTSENT_LOWAT, &val, sizeof(val));
	}
#endif

#ifdef TCP_NODELAY
	{
		int val = 1;
		::setsockopt(m_fd, IPPROTO_TCP, TCP_NODELAY, &val, sizeof(val));
	}
#endif

	return true;
}

int PosixRTMPPlatformAdapter::getSocketFd() const
{
	return m_fd;
}

bool PosixRTMPPlatformAdapter::setRTMP(RTMP *rtmp)
{
	if(rtmp and (not m_rtmp) and m_fd >= 0)
	{
		m_rtmp = rtmp;
		m_rtmpOpen = true;
		m_runloop->registerDescriptor(m_fd, RunLoop::READABLE, [this] { onInterfaceReadable(); });
		return true;
	}
	return false;
}

Time PosixRTMPPlatformAdapter::getCurrentTime()
{
	return m_runloop->getCurrentTime();
}

void PosixRTMPPlatformAdapter::notifyWhenWritable(const onwritable_f &onwritable)
{
	if(m_fd >= 0)
	{
		m_onwritable = onwritable;
		m_runloop->registerDescriptor(m_fd, RunLoop::WRITABLE, [this] { onInterfaceWritable(); });
	}
}

bool PosixRTMPPlatformAdapter::writeBytes(const void *bytes_, size_t len)
{
	if(m_fd < 0)
		return false;

	const uint8_t *bytes = (const uint8_t *)bytes_;
	m_outputBuffer.insert(m_outputBuffer.end(), bytes, bytes + len);

	return true;
}

void PosixRTMPPlatformAdapter::onClosed()
{
	m_rtmpOpen = false;
	m_onwritable = nullptr;
	closeIfDone();
}

// ---

void PosixRTMPPlatformAdapter::onInterfaceReadable()
{
	ssize_t rv = ::recvfrom(m_fd, m_inputBuffer, INPUT_BUFFER_SIZE, 0, nullptr, nullptr);
	if(rv <= 0)
	{
		if((EAGAIN == errno) or (EINTR == errno))
			return;
		::perror("recvfrom");
		if(m_rtmpOpen)
			m_rtmp->onInterfaceDidClose();
		goto error;
	}

	if((not m_rtmpOpen) or not m_rtmp->onReceiveBytes(m_inputBuffer, (size_t)rv))
		goto error;

	return;

error:
	close();
}

void PosixRTMPPlatformAdapter::onInterfaceWritable()
{
	while(m_onwritable and (m_outputBuffer.size() < WRITE_SIZE_PER_SELECT))
	{
		if(not m_onwritable())
			m_onwritable = nullptr;
	}

	if(m_outputBuffer.size())
	{
		uint8_t *buf = m_outputBuffer.data();
		size_t len = m_outputBuffer.size();

		ssize_t rv = ::sendto(m_fd, buf, len, 0, nullptr, 0);
		if(rv < 0)
		{
			if(EAGAIN == errno) // this shouldn't happen because we select()ed
				return;
			::perror("sendto");
			close();
			if(m_rtmpOpen)
				m_rtmp->onInterfaceDidClose();
			return;
		}
		else if(rv < len)
		{
			::memmove(buf, buf + rv, len - rv);
			m_outputBuffer.resize(len - rv);
		}
		else
			m_outputBuffer.clear();
	}

	if(m_outputBuffer.empty() and not m_onwritable)
		m_runloop->unregisterDescriptor(m_fd, RunLoop::WRITABLE);

	closeIfDone();
}

void PosixRTMPPlatformAdapter::closeIfDone()
{
	if(m_outputBuffer.empty() and not m_rtmpOpen)
		close();
}

} } } // namespace com::zenomt::rtmp
