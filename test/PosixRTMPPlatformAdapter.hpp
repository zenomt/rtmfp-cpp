#pragma once

// Copyright © 2021 Michael Thornburgh
// SPDX-License-Identifier: MIT

#include "RTMP.hpp"
#include "rtmfp/RunLoop.hpp"

namespace com { namespace zenomt { namespace rtmp {

class PosixRTMPPlatformAdapter : public IPlatformAdapter {
public:
	PosixRTMPPlatformAdapter(RunLoop *runloop, int unsent_lowat = 4096, size_t writeSizePerSelect = 2048);
	~PosixRTMPPlatformAdapter();

	void close();

	bool setSocketFd(int fd);
	int  getSocketFd() const;

	bool setRTMP(RTMP *rtmp);

	Task onShutdownCompleteCallback;

	Time getCurrentTime() override;
	void notifyWhenWritable(const onwritable_f &onwritable) override;
	void doLater(const Task &task) override;
	bool writeBytes(const void *bytes, size_t len) override;
	void onClosed() override;

protected:
	void tryRegisterDescriptors();
	void onInterfaceReadable();
	void onInterfaceWritable();
	void closeIfDone();

	RTMP *m_rtmp;
	bool m_rtmpOpen;
	bool m_shutdown;
	RunLoop *m_runloop;
	int m_fd;
	uint8_t *m_inputBuffer;
	int m_unsent_lowat;
	size_t m_writeSizePerSelect;
	std::vector<uint8_t> m_outputBuffer;
	onwritable_f m_onwritable;
	std::shared_ptr<bool> m_doLaterAllowed;
};

} } } // namespace com::zenomt::rtmp
