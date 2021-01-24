#pragma once

// Copyright © 2021 Michael Thornburgh
// SPDX-License-Identifier: MIT

#include <map>
#include <thread>

#include "RunLoop.hpp"

namespace com { namespace zenomt {

class SelectRunLoop : public RunLoop {
public:
	using RunLoop::RunLoop;

	void registerDescriptor(int fd, Condition cond, const Action &action) override;
	void unregisterDescriptor(int fd, Condition cond) override;

	void run(Time runInterval = INFINITY, Time minSleep = 0) override;
	bool isRunningInThisThread() const override;

	void clear() override;

	struct Item;

protected:
	std::map<int, std::shared_ptr<Item> > m_items[NUM_CONDITIONS];
	std::atomic<std::thread::id> m_runningInThread;
};

} } // namespace com::zenomt
