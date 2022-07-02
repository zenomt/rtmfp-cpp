// Copyright © 2022 Michael Thornburgh
// SPDX-License-Identifier: MIT

#include "../include/rtmfp/EPollRunLoop.hpp"

#ifdef __linux__

#if __cpp_exceptions
  #include <new>
#else
  #include <cstdlib>
#endif

#include <cerrno>

extern "C" {
#include <unistd.h>
#include <sys/epoll.h>
}

#endif // __linux__

namespace com { namespace zenomt {

#ifdef __linux__

struct EPollRunLoop::DescriptorItem : public Object {
	DescriptorItem(int fd, const Action &action) :
		m_fd(fd),
		m_action(action)
	{}

	int m_fd;
	bool m_canceled { false };
	Action m_action;
};

struct EPollRunLoop::Descriptor : public Object {
	uint32_t getPollEvents() const
	{
		uint32_t rv = 0;
		if(m_items[READABLE]) rv |= EPOLLIN;
		if(m_items[WRITABLE]) rv |= EPOLLOUT;
		if(m_items[EXCEPTION]) rv |= EPOLLERR;
		return rv;
	}

	std::shared_ptr<DescriptorItem> m_items[NUM_CONDITIONS];
};

EPollRunLoop::EPollRunLoop(bool sharedTimeOrigin) :
	RunLoop(sharedTimeOrigin)
{
	m_epoll = epoll_create(64);
	if(m_epoll < 0)
#if __cpp_exceptions
		throw std::bad_alloc();
#else
		abort();
#endif
}

EPollRunLoop::~EPollRunLoop()
{
	::close(m_epoll);
}

void EPollRunLoop::registerDescriptor(int fd, Condition cond, const Action &action)
{
	if(fd < 0)
		return;

	unregisterDescriptor(fd, cond);

	if(not action)
		return;

	int op = EPOLL_CTL_MOD;

	auto &descriptor = m_descriptors[fd];
	if(not descriptor)
	{
		op = EPOLL_CTL_ADD;
		descriptor = share_ref(new Descriptor(), false);
	}

	descriptor->m_items[cond] = share_ref(new DescriptorItem(fd, action), false);

	struct epoll_event ev;
	ev.events = descriptor->getPollEvents();
	ev.data.ptr = descriptor.get();

	epoll_ctl(m_epoll, op, fd, &ev);
}

void EPollRunLoop::unregisterDescriptor(int fd, Condition cond)
{
	if((fd < 0) or not m_descriptors.count(fd))
		return;

	auto descriptor = m_descriptors[fd];

	if(descriptor->m_items[cond])
		descriptor->m_items[cond]->m_canceled = true;
	else
		return;

	descriptor->m_items[cond].reset();

	struct epoll_event ev;
	ev.events = descriptor->getPollEvents();
	ev.data.ptr = descriptor.get();

	epoll_ctl(m_epoll, ev.events ? EPOLL_CTL_MOD : EPOLL_CTL_DEL, fd, &ev);

	if(0 == ev.events)
		m_descriptors.erase(fd);
}

void EPollRunLoop::run(Time runInterval, Time minSleep)
{
	std::shared_ptr<Timer> stopTimer = schedule(Timer::makeAction([&] { stop(); }), getCurrentTimeNoCache() + runInterval);
	const int maxEvents = 64; // this many file descriptors per loop, epoll_wait will round-robin
	struct epoll_event events[maxEvents];
	std::queue<std::shared_ptr<DescriptorItem>> activatedReads;
	std::queue<std::shared_ptr<DescriptorItem>> activatedWrites;
	std::queue<std::shared_ptr<DescriptorItem>> activatedExceptions;

	m_stopping = false;

	cacheTime();

	m_runningInThread = std::this_thread::get_id();

	do {
		Time sleepTime = hasDoLaters() ? 0.0 : m_timers.howLongToNextFire(getCurrentTime());
		if(sleepTime < minSleep)
			sleepTime = minSleep;
		if(sleepTime > 0.0)
			sleepTime += 0.0005; // round up, epoll timeout resolution is ms, epoll_pwait2 (ns) is too new

		uncacheTime();
		int rv = epoll_wait(m_epoll, events, maxEvents, int(sleepTime * 1000.0));
		cacheTime();

		if(rv > 0)
		{
			for(int x = 0; x < rv; x++)
			{
				Descriptor *descriptor = (Descriptor *)events[x].data.ptr;
				if(events[x].events & EPOLLIN)
					activatedReads.push(descriptor->m_items[READABLE]);
				if(events[x].events & EPOLLOUT)
					activatedWrites.push(descriptor->m_items[WRITABLE]);
				if(events[x].events & EPOLLERR)
					activatedExceptions.push(descriptor->m_items[EXCEPTION]);
			}

			processActivatedItems(activatedExceptions, EXCEPTION);
			processActivatedItems(activatedReads, READABLE);
			processActivatedItems(activatedWrites, WRITABLE);
		}
		else if(rv < 0)
		{
			if(EINTR != errno)
				break;
		}

		processDoLaters();

		if(not m_stopping)
			m_timers.fireDueTimers(getCurrentTime());

		if(onEveryCycle and not m_stopping)
			onEveryCycle();
	} while(not m_stopping);

	m_runningInThread = std::thread::id();

	uncacheTime();

	stopTimer->cancel();
}

void EPollRunLoop::clear()
{
	RunLoop::clear();

	auto safeDescriptors = m_descriptors;
	for(auto it = safeDescriptors.begin(); it != safeDescriptors.end(); it++)
		unregisterDescriptor(it->first);
}

// ---

void EPollRunLoop::processActivatedItems(std::queue<std::shared_ptr<DescriptorItem>> &activatedItems, Condition cond)
{
	while(not activatedItems.empty())
	{
		std::shared_ptr<DescriptorItem> each = activatedItems.front();
		activatedItems.pop();
		if(each and (not each->m_canceled) and (not m_stopping))
			each->m_action(this, each->m_fd, cond);
	}
}

#endif // __linux__

// --- make sure there's at least one symbol in the object file to avoid an archiver warning.

bool EPollRunLoop::isRunningInThisThread() const
{
	std::thread::id runningThread = m_runningInThread;
	return (std::this_thread::get_id() == runningThread) and (std::thread::id() != runningThread);
}

} } // namespace com::zenomt
