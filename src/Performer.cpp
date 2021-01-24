// Copyright © 2021 Michael Thornburgh
// SPDX-License-Identifier: MIT

#include "../include/rtmfp/Performer.hpp"

#include <condition_variable>

#if __cpp_exceptions
  #include <new>
#else
  #include <cstdlib>
#endif

#include <unistd.h>

namespace com { namespace zenomt {

static const int READ_PIPE_IDX  = 0;
static const int WRITE_PIPE_IDX = 1;

struct Performer::Item {
	Item(const Task &task, bool signalComplete) : m_task(task), m_complete(false)
	{
		if(signalComplete)
		{
			m_mutex = std::make_shared<std::mutex>();
			m_cond = std::make_shared<std::condition_variable>();
		}
	}

	void fire()
	{
		if(m_task)
			m_task();
		if(m_cond)
		{
			std::unique_lock<std::mutex> locked(*m_mutex);
			m_complete = true;
			m_cond->notify_all();
		}
	}

	Task m_task;
	volatile bool                            m_complete;
	std::shared_ptr<std::mutex>              m_mutex;
	std::shared_ptr<std::condition_variable> m_cond;
};

Performer::Performer(RunLoop *runLoop) :
	m_runLoop(runLoop),
	m_signaled(false),
	m_closed(false)
{
	if(pipe(m_pipe))
#if __cpp_exceptions
		throw std::bad_alloc();
#else
		abort();
#endif

	m_runLoop->registerDescriptor(m_pipe[READ_PIPE_IDX], RunLoop::READABLE, [this] { this->onSignaled(); });
}

Performer::~Performer()
{
	close();
}

void Performer::close()
{
	if(not m_closed)
	{
		m_closed = true;

		if(m_runLoop)
			m_runLoop->unregisterDescriptor(m_pipe[READ_PIPE_IDX]);
		m_runLoop = nullptr;
		::close(m_pipe[READ_PIPE_IDX]);
		::close(m_pipe[WRITE_PIPE_IDX]);

		fireItems();
	}
}

void Performer::perform(const Task &task, bool wait)
{
	if(m_closed)
		return;

	if(wait and m_runLoop->isRunningInThisThread())
	{
		fireItems();
		if(task)
			task();
		return;
	}

	std::shared_ptr<Item> item = std::make_shared<Item>(task, wait);
	{
		std::unique_lock<std::mutex> locked(m_mutex);
		m_items.push(item);
	}

	if(not m_signaled)
	{
		uint8_t buf[1];
		m_signaled = true;
		write(m_pipe[WRITE_PIPE_IDX], buf, sizeof(buf));
	}

	if(wait)
	{
		std::unique_lock<std::mutex> locked(*item->m_mutex);
		while(not item->m_complete)
			item->m_cond->wait(locked);
	}
}

void Performer::onSignaled()
{
	m_signaled = false;
	uint8_t buf[1];
	read(m_pipe[READ_PIPE_IDX], buf, sizeof(buf)); // shouldn't block because we were woken up for this
	fireItems();
}

void Performer::fireItems()
{
	while(true)
	{
		std::shared_ptr<Item> each;

		{
			std::unique_lock<std::mutex> locked(m_mutex);
			if(m_items.empty())
				break;
			each = m_items.front();
			m_items.pop();
		}

		if(not m_closed)
			each->fire();
	}
}

} } // namespace com::zenomt
