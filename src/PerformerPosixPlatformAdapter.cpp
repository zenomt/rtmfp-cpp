// Copyright © 2021 Michael Thornburgh
// SPDX-License-Identifier: MIT

#include "../include/rtmfp/PerformerPosixPlatformAdapter.hpp"

namespace com { namespace zenomt { namespace rtmfp {

PerformerPosixPlatformAdapter::PerformerPosixPlatformAdapter(RunLoop *mainRL, Performer *mainPerformer, Performer *workerPerformer) :
	PosixPlatformAdapter(mainRL),
	m_mainPerformer(mainPerformer),
	m_workerPerformer(workerPerformer)
{
	m_isOpen_performer = std::make_shared<std::atomic_bool>(true);
	if(!m_workerPerformer)
		m_workerPerformer = mainPerformer;
}

bool PerformerPosixPlatformAdapter::perform(unsigned long thread, const Task &task)
{
	std::shared_ptr<std::atomic_bool> isOpen = m_isOpen_performer;
	Performer *performer = thread ? m_workerPerformer : m_mainPerformer;
	performer->perform([isOpen, task] { if(*isOpen) task(); });
	return true;
}

void PerformerPosixPlatformAdapter::close()
{
	*m_isOpen_performer = false;
	PosixPlatformAdapter::close();
}

} } } // namespace com::zenomt::rtmfp
