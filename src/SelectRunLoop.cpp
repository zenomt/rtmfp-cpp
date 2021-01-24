// Copyright © 2021 Michael Thornburgh
// SPDX-License-Identifier: MIT

#include <cerrno>
#include <queue>

#include <sys/select.h>

#include "../include/rtmfp/SelectRunLoop.hpp"

namespace com { namespace zenomt {

struct SelectRunLoop::Item {
	Item(int fd, Condition cond, const Action &action) :
		m_fd(fd),
		m_condition(cond),
		m_action(action),
		m_canceled(false)
	{ }

	int       m_fd;
	Condition m_condition;
	Action    m_action;
	bool      m_canceled;
};

void SelectRunLoop::registerDescriptor(int fd, Condition cond, const Action &action)
{
	if(fd < 0)
		return;

	unregisterDescriptor(fd, cond);

	if(action)
		m_items[cond][fd] = std::make_shared<Item>(fd, cond, action);
}

void SelectRunLoop::unregisterDescriptor(int fd, Condition cond)
{
	if(m_items[cond].count(fd))
	{
		m_items[cond][fd]->m_canceled = true;
		m_items[cond].erase(fd);
	}
}

static void setFdsetFromItems(fd_set *fdset, int &nfds, const std::map<int, std::shared_ptr<SelectRunLoop::Item> > &items)
{
	FD_ZERO(fdset);
	int maxFd = -1;

	for(auto it = items.begin(); it != items.end(); it++)
	{
		FD_SET(it->first, fdset);
		maxFd = it->first; // map is in order so this is safe
	}

	if(maxFd > nfds)
		nfds = maxFd;
}

static void getActivatedItemsToQueue(fd_set *fdset, const std::map<int, std::shared_ptr<SelectRunLoop::Item> > &items, std::queue<std::shared_ptr<SelectRunLoop::Item> > &queue)
{
	for(auto it = items.begin(); it != items.end(); it++)
		if(FD_ISSET(it->first, fdset))
			queue.push(it->second);
}

void SelectRunLoop::run(Time runInterval, Time minSleep)
{
	std::queue<std::shared_ptr<Item> > activatedItems;

	m_stopping = false;
	std::shared_ptr<Timer> stopTimer = schedule(Timer::makeAction([&] { stop(); }), getCurrentTimeNoCache() + runInterval);

	cacheTime();

	m_runningInThread = std::this_thread::get_id();

	do {
		struct timeval timeout;
		Time sleepTime =  hasDoLaters() ? 0 : m_timers.howLongToNextFire(getCurrentTime());
		if(sleepTime < minSleep)
			sleepTime = minSleep;
		sleepTime += 0.0000005; // 1/2 µs
		timeout.tv_sec = sleepTime;
		timeout.tv_usec = (sleepTime - timeout.tv_sec) * 1000000;

		fd_set readfds, writefds, errorfds;
		int nfds = 0;
		setFdsetFromItems(&readfds,  nfds, m_items[READABLE]);
		setFdsetFromItems(&writefds, nfds, m_items[WRITABLE]);
		setFdsetFromItems(&errorfds, nfds, m_items[EXCEPTION]);
		nfds++; // because select

		uncacheTime();
		int rv = select(nfds, &readfds, &writefds, &errorfds, &timeout);
		cacheTime();

		if(rv > 0)
		{
			getActivatedItemsToQueue(&errorfds, m_items[EXCEPTION], activatedItems); // do exceptions first
			getActivatedItemsToQueue(&readfds,  m_items[READABLE],  activatedItems);
			getActivatedItemsToQueue(&writefds, m_items[WRITABLE],  activatedItems);

			while((not m_stopping) and (not activatedItems.empty()))
			{
				std::shared_ptr<Item> each = activatedItems.front();
				activatedItems.pop();
				if(not each->m_canceled)
					each->m_action(this, each->m_fd, each->m_condition);
			}
		}
		else if(rv < 0)
		{
			if(EINTR != errno)
				break;
		}

		processDoLaters();

		if(not m_stopping)
			m_timers.fireDueTimers(getCurrentTime());
	} while(not m_stopping);

	m_runningInThread = std::thread::id();

	uncacheTime();

	stopTimer->cancel();
}

bool SelectRunLoop::isRunningInThisThread() const
{
	std::thread::id runningThread = m_runningInThread;
	return (std::this_thread::get_id() == runningThread) and (std::thread::id() != runningThread);
}

static void clearItems(std::map<int, std::shared_ptr<SelectRunLoop::Item> > &items)
{
	for(auto it = items.begin(); it != items.end(); it++)
		it->second->m_canceled = true;
	items.clear();
}

void SelectRunLoop::clear()
{
	RunLoop::clear();
	clearItems(m_items[READABLE]);
	clearItems(m_items[WRITABLE]);
	clearItems(m_items[EXCEPTION]);
}

} } // namespace com::zenomt
