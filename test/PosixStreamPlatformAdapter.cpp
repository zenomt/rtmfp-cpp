// Copyright © 2021 Michael Thornburgh
// SPDX-License-Identifier: MIT

#include <cassert>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <fcntl.h>

#include "rtmfp/Retainer.hpp"

#include "PosixStreamPlatformAdapter.hpp"

namespace com { namespace zenomt {

static const size_t INPUT_BUFFER_SIZE = 65536;

PosixStreamPlatformAdapter::PosixStreamPlatformAdapter(RunLoop *runloop, int unsent_lowat, size_t writeSizePerSelect) :
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

PosixStreamPlatformAdapter::~PosixStreamPlatformAdapter()
{
	close();
	if(m_inputBuffer)
		free(m_inputBuffer);
	m_inputBuffer = nullptr;
}

void PosixStreamPlatformAdapter::attachToRunLoop(RunLoop *runloop)
{
	assert(not m_runloop);
	m_runloop = runloop;
	tryRegisterReadable();
	tryRegisterWritable();
}

void PosixStreamPlatformAdapter::detachFromRunLoop()
{
	if(m_runloop)
		m_runloop->unregisterDescriptor(m_fd);
	m_runloop = nullptr;
}

void PosixStreamPlatformAdapter::close()
{
	*m_doLaterAllowed = false;

	if(m_fd >= 0)
	{
		if(m_runloop)
			m_runloop->unregisterDescriptor(m_fd);
		::close(m_fd);
		m_fd = -1;
	}

	Task cb;
	swap(cb, onShutdownCompleteCallback);
	if(cb)
		cb();
}

bool PosixStreamPlatformAdapter::setSocketFd(int fd)
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

	{
		int flags = fcntl(m_fd, F_GETFL);
		flags |= O_NONBLOCK;
		fcntl(m_fd, F_SETFL, flags);
	}

	tryRegisterReadable();
	tryRegisterWritable();

	return true;
}

int PosixStreamPlatformAdapter::getSocketFd() const
{
	return m_fd;
}

Time PosixStreamPlatformAdapter::getCurrentTime()
{
	assert(m_runloop);
	return m_runloop->getCurrentTime();
}

void PosixStreamPlatformAdapter::notifyWhenWritable(const onwritable_f &onwritable)
{
	m_onwritable = onwritable;
	tryRegisterWritable();
}

void PosixStreamPlatformAdapter::setOnReceiveBytesCallback(const onreceivebytes_f &onreceivebytes)
{
	m_onreceivebytes = onreceivebytes;
	tryRegisterReadable();
}

void PosixStreamPlatformAdapter::setOnStreamDidCloseCallback(const Task &onstreamdidclose)
{
	m_onstreamdidclose = onstreamdidclose;
}

void PosixStreamPlatformAdapter::doLater(const Task &task)
{
	assert(m_runloop);
	std::shared_ptr<bool> allowed = m_doLaterAllowed;
	m_runloop->doLater([allowed, task] {
		if(*allowed)
			task();
	});
}

bool PosixStreamPlatformAdapter::writeBytes(const void *bytes_, size_t len)
{
	if(m_fd < 0)
		return false;

	const uint8_t *bytes = (const uint8_t *)bytes_;
	m_outputBuffer.insert(m_outputBuffer.end(), bytes, bytes + len);

	return true;
}

void PosixStreamPlatformAdapter::onClientClosed()
{
	*m_doLaterAllowed = false;
	m_clientOpen = false;
	m_onwritable = nullptr;
	m_onreceivebytes = nullptr;
	m_onstreamdidclose = nullptr;
	closeIfDone();
}

// ---

void PosixStreamPlatformAdapter::onInterfaceReadable()
{
	auto myself = retain_ref(this);

	if(m_clientOpen and not m_onreceivebytes)
	{
		m_runloop->unregisterDescriptor(m_fd, RunLoop::READABLE);
		return;
	}

	ssize_t rv = ::recvfrom(m_fd, m_inputBuffer, INPUT_BUFFER_SIZE, 0, nullptr, nullptr);
	if(0 == rv)
		goto error; // if we select and get 0 from recvfrom, the other side has closed.
	if(rv < 0)
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

void PosixStreamPlatformAdapter::onInterfaceWritable()
{
	auto myself = retain_ref(this);

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

	if(m_outputBuffer.empty() and m_runloop and not m_onwritable)
		m_runloop->unregisterDescriptor(m_fd, RunLoop::WRITABLE);

	closeIfDone();
}

void PosixStreamPlatformAdapter::closeIfDone()
{
	if(m_outputBuffer.empty() and (not m_clientOpen) and (not m_shutdown) and (m_fd >= 0))
	{
		m_shutdown = true;
		shutdown(m_fd, SHUT_WR);
	}
}

void PosixStreamPlatformAdapter::tryRegisterReadable()
{
	if(m_runloop and (m_fd >= 0) and m_onreceivebytes)
	{
		auto myself = share_ref(this);
		m_runloop->registerDescriptor(m_fd, RunLoop::READABLE, [myself] { myself->onInterfaceReadable(); });
	}
}

void PosixStreamPlatformAdapter::tryRegisterWritable()
{
	if(m_runloop and (m_fd >= 0) and m_onwritable)
	{
		auto myself = share_ref(this);
		m_runloop->registerDescriptor(m_fd, RunLoop::WRITABLE, [myself] { myself->onInterfaceWritable(); });
	}
}

} } // namespace com::zenomt
