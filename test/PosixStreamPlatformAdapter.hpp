#pragma once

// Copyright © 2021 Michael Thornburgh
// SPDX-License-Identifier: MIT

#include "IStreamPlatformAdapter.hpp"
#include "rtmfp/RunLoop.hpp"

namespace com { namespace zenomt {

class PosixStreamPlatformAdapter : public IStreamPlatformAdapter, public Object {
public:
	PosixStreamPlatformAdapter(RunLoop *runloop, int unsent_lowat = 4096, size_t writeSizePerSelect = 2048);
	~PosixStreamPlatformAdapter();

	void close();

	bool setSocketFd(int fd);
	int  getSocketFd() const;

	Task onShutdownCompleteCallback;

	Time getCurrentTime() override;
	void notifyWhenWritable(const onwritable_f &onwritable) override;
	void setOnReceiveBytesCallback(const onreceivebytes_f &onreceivebytes) override;
	void setOnStreamDidCloseCallback(const Task &onstreamdidclose) override;
	void doLater(const Task &task) override;
	bool writeBytes(const void *bytes, size_t len) override;
	void onClientClosed() override;

protected:
	void onInterfaceReadable();
	void onInterfaceWritable();
	void closeIfDone();

	bool m_clientOpen;
	bool m_shutdown;
	RunLoop *m_runloop;
	int m_fd;
	uint8_t *m_inputBuffer;
	int m_unsent_lowat;
	size_t m_writeSizePerSelect;
	std::vector<uint8_t> m_outputBuffer;
	onwritable_f m_onwritable;
	onreceivebytes_f m_onreceivebytes;
	Task m_onstreamdidclose;
	std::shared_ptr<bool> m_doLaterAllowed;
};

} } // namespace com::zenomt
