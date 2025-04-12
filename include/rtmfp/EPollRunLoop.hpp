#pragma once

// Copyright © 2022 Michael Thornburgh
// SPDX-License-Identifier: MIT

#include <map>
#include <thread>
#include <queue>

#include "RunLoop.hpp"

namespace com { namespace zenomt {

class EPollRunLoop : public RunLoop {
public:
	EPollRunLoop(bool sharedTimeOrigin = false);
	~EPollRunLoop();

	using RunLoop::registerDescriptor;
	using RunLoop::unregisterDescriptor;

	void registerDescriptor(int fd, Condition cond, const Action &action) override;
	void unregisterDescriptor(int fd, Condition cond) override;

	void run(Duration runInterval = INFINITY, Duration minSleep = 0) override;
	bool isRunningInThisThread() const override;

	void clear() override;

protected:
	struct Descriptor;
	struct DescriptorItem;

	void processActivatedItems(std::queue<std::shared_ptr<DescriptorItem>> &activatedItems, Condition cond);

	int m_epoll;
	std::map<int, std::shared_ptr<Descriptor>> m_descriptors;
	std::atomic<std::thread::id> m_runningInThread;
};

} } // namespace com::zenomt
