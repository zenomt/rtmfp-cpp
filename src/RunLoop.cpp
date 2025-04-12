// Copyright © 2021 Michael Thornburgh
// SPDX-License-Identifier: MIT

#include "../include/rtmfp/RunLoop.hpp"

namespace com { namespace zenomt {

RunLoop::RunLoop(bool sharedTimeOrigin) :
	m_timeIsCached(false),
	m_stopping(false)
{
	m_origin = sharedTimeOrigin ? std::chrono::steady_clock::time_point() : std::chrono::steady_clock::now();
}

void RunLoop::registerDescriptor(int fd, Condition cond, const Task &task)
{
	registerDescriptor(fd, cond, [task] (RunLoop *sender, int fd, Condition cond) { if(task) task(); });
}

void RunLoop::unregisterDescriptor(int fd)
{
	unregisterDescriptor(fd, READABLE);
	unregisterDescriptor(fd, WRITABLE);
	unregisterDescriptor(fd, EXCEPTION);
}

std::shared_ptr<Timer> RunLoop::schedule(Time when, Duration recurInterval, bool catchup)
{
	return m_timers.schedule(when, recurInterval, catchup);
}

std::shared_ptr<Timer> RunLoop::schedule(const Timer::Action &action, Time when, Duration recurInterval, bool catchup)
{
	return m_timers.schedule(action, when, recurInterval, catchup);
}

std::shared_ptr<Timer> RunLoop::scheduleRel(Duration delta, Duration recurInterval, bool catchup)
{
	return schedule(getCurrentTime() + delta, recurInterval, catchup);
}

std::shared_ptr<Timer> RunLoop::scheduleRel(const Timer::Action &action, Duration delta, Duration recurInterval, bool catchup)
{
	return schedule(action, getCurrentTime() + delta, recurInterval, catchup);
}

void RunLoop::doLater(const Task &task)
{
	m_doLaters.push(task);
}

void RunLoop::stop()
{
	m_stopping = true;
}

Time RunLoop::getCurrentTime() const
{
	return m_timeIsCached ? m_timeCache : getCurrentTimeNoCache();
}

Time RunLoop::getCurrentTimeNoCache() const
{
	using namespace std::chrono;
	return duration_cast<duration<Time>>(steady_clock::now() - m_origin).count();
}

void RunLoop::cacheTime()
{
	m_timeCache = getCurrentTimeNoCache();
	m_timeIsCached = true;
}

void RunLoop::uncacheTime()
{
	m_timeIsCached = false;
}

bool RunLoop::hasDoLaters() const
{
	return not m_doLaters.empty();
}

void RunLoop::processDoLaters()
{
	while((not m_stopping) and hasDoLaters())
	{
		Task task = m_doLaters.front();
		m_doLaters.pop();
		if(task)
			task();
	}
}

void RunLoop::clear()
{
	m_timers.clear();

	while(hasDoLaters()) // std::queue doesn't have a clear
		m_doLaters.pop();
}

} } // namespace com::zenomt
