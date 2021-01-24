#pragma once

// Copyright © 2021 Michael Thornburgh
// SPDX-License-Identifier: MIT

#include "PosixPlatformAdapter.hpp"
#include "Performer.hpp"

namespace com { namespace zenomt { namespace rtmfp {

class PerformerPosixPlatformAdapter : public PosixPlatformAdapter {
public:
	PerformerPosixPlatformAdapter(RunLoop *mainRL, Performer *mainPerformer, Performer *workerPerformer = nullptr);

	bool perform(unsigned long thread, const Task &task) override;

	void close() override;

protected:
	Performer *m_mainPerformer;
	Performer *m_workerPerformer;
	std::shared_ptr<std::atomic_bool> m_isOpen_performer;
};

} } } // namespace com::zenomt::rtmfp
