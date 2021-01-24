#pragma once

// Copyright © 2021 Michael Thornburgh
// SPDX-License-Identifier: MIT

#include "RunLoop.hpp"

#include <mutex>

namespace com { namespace zenomt {

class Performer : public Object {
public:
	Performer(RunLoop *runLoop);
	~Performer();

	void perform(const Task &task, bool wait = false);

	void close();

protected:
	struct Item;

	void onSignaled();
	void fireItems();

	RunLoop         *m_runLoop;
	int              m_pipe[2];
	std::mutex       m_mutex;
	std::queue<std::shared_ptr<Item> > m_items;
	std::atomic_bool m_signaled;
	std::atomic_bool m_closed;
};

} } // namespace com::zenomt
