// Copyright © 2021 Michael Thornburgh
// SPDX-License-Identifier: MIT

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <fcntl.h>

#include "PosixStreamPlatformAdapter.hpp"

namespace com { namespace zenomt { namespace rtmp {

static const size_t INPUT_BUFFER_SIZE = 65536;

PosixRTMPPlatformAdapter::PosixRTMPPlatformAdapter(RunLoop *runloop, int unsent_lowat, size_t writeSizePerSelect) :
	m_clientOpen(true),
	m_shutdown(false),
	m_runloop(runloop),
	m_fd(-1),
	m_unsent_lowat(unsent_lowat),
	m_writeSizePerSelect(writeSizePerSelect),
	m_doLaterAllowed(std::make_shared<bool>(true))
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
	*m_doLaterAllowed = false;

	if(m_fd >= 0)
	{
		m_runloop->unregisterDescriptor(m_fd);
		::close(m_fd); // TODO really?
		m_fd = -1;
	}

	Task cb;
	swap(cb, onShutdownCompleteCallback);
	if(cb)
		cb();
}

bool PosixRTMPPlatformAdapter::setSocketFd(int fd)
{
	if(m_fd >= 0)
		return false;
	m_fd = fd;

#ifdef TCP_NOTSENT_LOWAT
	::setsockopt(m_fd, IPPROTO_TCP, TCP_NOTSENT_LOWAT, &m_unsent_lowat, sizeof(m_unsent_lowat));
#endif

#ifdef TCP_NODELAY
	{
		int val = 1;
		::setsockopt(m_fd, IPPROTO_TCP, TCP_NODELAY, &val, sizeof(val));
	}
#endif

#ifdef F_SETNOSIGPIPE
	fcntl(m_fd, F_SETNOSIGPIPE, 1);
#endif

	if(m_onreceivebytes)
		m_runloop->registerDescriptor(m_fd, RunLoop::READABLE, [this] { onInterfaceReadable(); });
	if(m_onwritable)
		m_runloop->registerDescriptor(m_fd, RunLoop::WRITABLE, [this] { onInterfaceWritable(); });

	return true;
}

int PosixRTMPPlatformAdapter::getSocketFd() const
{
	return m_fd;
}

Time PosixRTMPPlatformAdapter::getCurrentTime()
{
	return m_runloop->getCurrentTime();
}

void PosixRTMPPlatformAdapter::notifyWhenWritable(const onwritable_f &onwritable)
{
	m_onwritable = onwritable;
	if(m_fd >= 0)
		m_runloop->registerDescriptor(m_fd, RunLoop::WRITABLE, [this] { onInterfaceWritable(); });
}

void PosixRTMPPlatformAdapter::setOnReceiveBytesCallback(const onreceivebytes_f &onreceivebytes)
{
	m_onreceivebytes = onreceivebytes;
	if(m_fd >= 0)
		m_runloop->registerDescriptor(m_fd, RunLoop::READABLE, [this] { onInterfaceReadable(); });
}

void PosixRTMPPlatformAdapter::setOnStreamDidCloseCallback(const Task &onstreamdidclose)
{
	m_onstreamdidclose = onstreamdidclose;
}

void PosixRTMPPlatformAdapter::doLater(const Task &task)
{
	std::shared_ptr<bool> allowed = m_doLaterAllowed;
	m_runloop->doLater([allowed, task] {
		if(*allowed)
			task();
	});
}

bool PosixRTMPPlatformAdapter::writeBytes(const void *bytes_, size_t len)
{
	if(m_fd < 0)
		return false;

	const uint8_t *bytes = (const uint8_t *)bytes_;
	m_outputBuffer.insert(m_outputBuffer.end(), bytes, bytes + len);

	return true;
}

void PosixRTMPPlatformAdapter::onClientClosed()
{
	*m_doLaterAllowed = false;
	m_clientOpen = false;
	m_onwritable = nullptr;
	m_onreceivebytes = nullptr;
	m_onstreamdidclose = nullptr;
	closeIfDone();
}

// ---

void PosixRTMPPlatformAdapter::onInterfaceReadable()
{
	if(not m_onreceivebytes)
	{
		m_runloop->unregisterDescriptor(m_fd, RunLoop::READABLE);
		return;
	}

	ssize_t rv = ::recvfrom(m_fd, m_inputBuffer, INPUT_BUFFER_SIZE, 0, nullptr, nullptr);
	if(rv <= 0)
	{
		if((EAGAIN == errno) or (EINTR == errno))
			return;
		if(errno)
			::perror("recvfrom");
		goto error;
	}

	if(m_shutdown)
		return; // discard any read data if we're shutting down

	if(not m_clientOpen)
		goto error;

	if(not m_onreceivebytes(m_inputBuffer, (size_t)rv))
		m_onreceivebytes = nullptr;

	return;

error:
	close();
	if(m_onstreamdidclose)
		m_onstreamdidclose();
}

void PosixRTMPPlatformAdapter::onInterfaceWritable()
{
	while(m_onwritable and (m_outputBuffer.size() < m_writeSizePerSelect))
	{
		if(not m_onwritable())
			m_onwritable = nullptr;
	}

	if(m_outputBuffer.size())
	{
		uint8_t *buf = m_outputBuffer.data();
		size_t len = m_outputBuffer.size();
		int flags = 0;

#ifdef MSG_NOSIGNAL
		flags |= MSG_NOSIGNAL;
#endif

		ssize_t rv = ::sendto(m_fd, buf, len, flags, nullptr, 0);
		if(rv < 0)
		{
			if((EAGAIN == errno) or (EINTR == errno))
				return;
			::perror("sendto");
			close();
			if(m_onstreamdidclose)
				m_onstreamdidclose();
			return;
		}
		else if((size_t)rv < len)
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
	if(m_outputBuffer.empty() and (not m_clientOpen) and (not m_shutdown) and (m_fd >= 0))
	{
		m_shutdown = true;
		shutdown(m_fd, SHUT_WR);
	}
}

} } } // namespace com::zenomt::rtmp