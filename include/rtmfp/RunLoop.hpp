#pragma once

// Copyright © 2021 Michael Thornburgh
// SPDX-License-Identifier: MIT

#include <chrono>
#include <cmath>
#include <queue>

#include "Timer.hpp"

// inspired by MObjRunLoop from amicima

namespace com { namespace zenomt {

class RunLoop : public Object {
public:
	static const size_t NUM_CONDITIONS = 3;

	enum Condition { READABLE, WRITABLE, EXCEPTION };
	using Action = std::function<void(RunLoop *sender, int fd, Condition cond)>;

	RunLoop(bool sharedTimeOrigin = false);

	virtual void registerDescriptor(int fd, Condition cond, const Action &action) = 0;
	virtual void registerDescriptor(int fd, Condition cond, const Task &task);
	virtual void unregisterDescriptor(int fd, Condition cond) = 0;
	virtual void unregisterDescriptor(int fd); // unregister any actions for fd

	std::shared_ptr<Timer> schedule(Time when, Time recurInterval = 0, bool catchup = true);
	std::shared_ptr<Timer> schedule(const Timer::Action &action, Time when, Time recurInterval = 0, bool catchup = true);

	std::shared_ptr<Timer> scheduleRel(Time delta, Time recurInterval = 0, bool catchup = true);
	std::shared_ptr<Timer> scheduleRel(const Timer::Action &action, Time delta, Time recurInterval = 0, bool catchup = true);

	virtual void doLater(const Task &task);

	virtual void run(Time runInterval = INFINITY, Time minSleep = 0) = 0;
	virtual void stop();
	virtual bool isRunningInThisThread() const = 0;

	virtual Time getCurrentTime() const;
	virtual Time getCurrentTimeNoCache() const;

	virtual void clear();

	// called every time through the run loop
	Task onEveryCycle;

protected:
	void cacheTime();
	void uncacheTime();

	virtual bool hasDoLaters() const;
	virtual void processDoLaters();

	std::chrono::steady_clock::time_point m_origin;
	Time             m_timeCache;
	bool             m_timeIsCached;
	TimerList        m_timers;
	volatile bool    m_stopping;
	std::queue<Task> m_doLaters;
};

} } // namespace com::zenomt
