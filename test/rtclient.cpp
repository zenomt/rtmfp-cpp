#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>

#include "rtmfp/rtmfp.hpp"
#include "rtmfp/SelectRunLoop.hpp"
#include "rtmfp/FlashCryptoAdapter_OpenSSL.hpp"
#include "rtmfp/PosixPlatformAdapter.hpp"
#include "rtmfp/Hex.hpp"
#include "addrlist.hpp"

using namespace com::zenomt;
using namespace com::zenomt::rtmfp;

namespace {

int verbose = 0;
const char frameNames[] = "Kabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz";
bool interleave = false;
bool flushGop = true;
bool chainGop = true;
bool audioRetransmit = true;
Time pfLifetime = 2.000;
Time delaycc_delay = INFINITY;
bool interrupted = false;
double keyframeMult = 5;

void signal_handler(int unused)
{
	interrupted = true;
}

class Stream : public Object {
public:
	Stream(int fps, double videoRate) : m_fps(fps), m_frame(0), m_videoRate(videoRate), m_audioRate(96000./8), m_videoBytesDelivered(0)
	{
		m_frameSize = 2.0 * m_videoRate / (2. * m_fps - 1 + keyframeMult);
	}

	void publish(const std::shared_ptr<Flow> pilot, RunLoop *rl)
	{
		m_video = pilot->openFlow("video", 5, PRI_PRIORITY);
		if(interleave)
			m_audio = m_video;
		else
			m_audio = pilot->openFlow("audio", 5, PRI_IMMEDIATE);

		rl->scheduleRel([this] (const std::shared_ptr<Timer> &sender, Time now) { if(not sendVideoFrame(now)) sender->cancel(); }, 0, 1. / m_fps, false);
		rl->scheduleRel([this] (const std::shared_ptr<Timer> &sender, Time now) { if(not sendAudioFrame()) sender->cancel(); }, 0, 1024. / 48000, false);

		m_video->onFarAddressDidChange = [this] { onFarAddressDidChange(); };
	}

	bool sendVideoFrame(Time now)
	{
		if(++m_frame > m_fps * 2)
			m_frame = 1;
		bool keyframe = 1 == m_frame;
		int frameIdx = m_frame - 1;
		double rtt = m_video->getSafeSRTT();

		double frameSize = m_frameSize;
		if(keyframe)
		{
			frameSize *= keyframeMult;
			while(not m_gop.empty())
			{
				auto &front = m_gop.front();
				if(flushGop)
					front->startBy = std::min(front->startBy, now + 0.1 + 2*rtt);
				m_gop.pop();
			}
			if(verbose)
				printf("\nCWND:%lu RTT:%.4Lf (base:%.4Lf) bw-est:%.0Lf buffered:%lu outstanding:%lu/%lu v-delivered-bw:%lu\n",
					(unsigned long)(m_video->getCongestionWindow()),
					m_video->getSafeSRTT(),
					m_video->getBaseRTT(),
					m_video->getCongestionWindow() * 8. / (m_video->getSafeSRTT() + 0.002),
					m_video->getBufferedSize(),
					m_video->getOutstandingBytes(),
					m_audio->getOutstandingBytes(),
					m_videoBytesDelivered * 8 / 2);
			m_videoBytesDelivered = 0;
		}

		size_t frameSizeBytes = size_t(ceil(frameSize));
		Bytes frame(frameSizeBytes);
		auto receipt = m_video->write(frame, (keyframe ? 2 : pfLifetime) + rtt, 3);
		if(not receipt)
			return false;
		receipt->onFinished = [this, frameIdx, receipt, frameSizeBytes] (bool abn) {
			if(not abn)
				m_videoBytesDelivered += frameSizeBytes;
			printf("%c", abn ? (receipt->isStarted() ? '!' : '-') : frameNames[frameIdx]);
			fflush(stdout);
		};
		if(chainGop and not keyframe)
			receipt->parent = m_lastReceipt;
		m_lastReceipt = receipt;
		if(flushGop)
			m_gop.push(receipt);
		return true;
	}

	bool sendAudioFrame()
	{
		double rtt = m_audio->getSafeSRTT();

		Bytes frame(int(ceil(m_audioRate * 1024. / 48000.)));
		auto receipt = m_audio->write(frame, 1 + rtt + .1, 2);
		if(not receipt)
			return false;
		receipt->retransmit = audioRetransmit;
		receipt->onFinished = [] (bool abn) {
			if(abn)
				printf("_");
			else if(verbose > 1)
				printf("A");
			fflush(stdout);
		};
		return true;
	}

	void onFarAddressDidChange()
	{
		// servers shouldn't change their addresses, but sometimes this happens
		// when the client is changing addresses and briefly connects with the
		// server using a link-local, private, or unique-local address on the
		// same network as the server.
		printf("\nonFarAddressDidChange: %s\n", m_video->getFarAddress().toPresentation().c_str());
	}

protected:
	int    m_fps;
	int    m_frame;
	double m_videoRate;
	double m_audioRate;
	double m_frameSize;
	size_t m_videoBytesDelivered;
	std::shared_ptr<SendFlow> m_video;
	std::shared_ptr<SendFlow> m_audio;
	std::shared_ptr<WriteReceipt> m_lastReceipt;
	std::queue<std::shared_ptr<WriteReceipt> > m_gop;
};

bool addInterface(PosixPlatformAdapter *platform, int port, int family)
{
	const char *familyName = (AF_INET6 == family) ? "IPv6" : "IPv4";
	auto addr = platform->addUdpInterface(port, family);
	if(addr)
		printf("bound to %s port %d\n", familyName, addr->getPort());
	else
		printf("error: couldn't bind to %s port %d\n", familyName, port);
	return !!addr;
}

}

static int usage(const char *name, const char *msg, int rv)
{
	if(msg)
		printf("%s\n", msg);
	printf("usage: %s [options] dstaddr port [dstaddr port]\n", name);
	printf("  -n name   -- require hostname\n");
	printf("  -f 30|60  -- set frames per second (30* or 60)\n");
	printf("  -k mult   -- keyframe multiplier (size times regular frames, default %.3f)\n", keyframeMult);
	printf("  -r vbps   -- set video bits per second, default 1000000\n");
	printf("  -l secs   -- set video P-frame lifetime, default %Lf\n", pfLifetime);
	printf("  -i        -- interleave audio and video on same flow\n");
	printf("  -A        -- don't retransmit lost audio frames\n");
	printf("  -E        -- don't expire previous GOP\n");
	printf("  -C        -- don't chain GOP\n");
	printf("  -H        -- don't require HMAC\n");
	printf("  -S        -- don't require session sequence numbers\n");
	printf("  -4        -- only bind to 0.0.0.0\n");
	printf("  -6        -- only bind to [::]\n");
	printf("  -X secs   -- set congestion extra delay threshold (default %.3Lf)\n", delaycc_delay);
	printf("  -v        -- increase verboseness\n");
	printf("  -h        -- show this help\n");
	return rv;
}

int main(int argc, char **argv)
{
	bool ipv4 = true;
	bool ipv6 = true;
	bool requireHMAC = true;
	bool requireSSEQ = true;
	const char *name = NULL;
	int fps = 30;
	double videoRate = 1000000. / 8;
	int ch;

	srand(time(NULL));

	while((ch = getopt(argc, argv, "h46HSn:f:k:r:l:iAECX:v")) != -1)
	{
		switch(ch)
		{
		case '4':
			ipv4 = true;
			ipv6 = false;
			break;
		case '6':
			ipv4 = false;
			ipv6 = true;
			break;
		case 'H':
			requireHMAC = false;
			break;
		case 'S':
			requireSSEQ = false;
			break;
		case 'n':
			name = optarg;
			break;
		case 'f':
			fps = atoi(optarg);
			if((30 != fps) and (60 != fps))
				return usage(argv[0], "fps must be 30 or 60", 1);
			break;
		case 'k':
			keyframeMult = atof(optarg);
			break;
		case 'r':
			videoRate = atof(optarg) / 8;
			break;
		case 'l':
			pfLifetime = atof(optarg);
			break;
		case 'i':
			interleave = true;
			break;
		case 'A':
			audioRetransmit = false;
			break;
		case 'E':
			flushGop = false;
			break;
		case 'C':
			chainGop = false;
			break;
		case 'X':
			delaycc_delay = atof(optarg);
			break;
		case 'v':
			verbose++;
			break;
		case 'h':
		default:
			return usage(argv[0], NULL, 'h' == ch);
		}
	}

	Bytes epd;
	if(not FlashCryptoAdapter::makeEPD(NULL, "rtmfp:", name, epd))
	{
		printf("error: bad endpoint discriminator\n");
		return 1;
	}

	if(argc - optind < 2)
		return usage(argv[0], "specify at least one dstaddr port", 1);

	std::vector<Address> dstAddrs;
	if(not addrlist_parse(argc, argv, optind, false, dstAddrs))
		return 1;

	FlashCryptoAdapter_OpenSSL crypto;
	if(not crypto.init(false, NULL))
	{
		printf("can't init crypto\n");
		return 1;
	}
	crypto.setHMACSendAlways(requireHMAC);
	crypto.setHMACRecvRequired(requireHMAC);
	crypto.setSSeqSendAlways(requireSSEQ);
	crypto.setSSeqRecvRequired(requireSSEQ);
	printf("my fingerprint: %s\n", Hex::encode(crypto.getFingerprint()).c_str());

	SelectRunLoop rl;
	PosixPlatformAdapter platform(&rl);
	RTMFP rtmfp(&platform, &crypto);
	platform.setRtmfp(&rtmfp);

	::signal(SIGINT, signal_handler);
	::signal(SIGTERM, signal_handler);
	rl.onEveryCycle = [&rtmfp] { if(interrupted) { interrupted = false; rtmfp.shutdown(true); printf("interrupted. shutting down.\n"); } };
	platform.onShutdownCompleteCallback = [&rl] { rl.stop(); };

	if(ipv4 and not addInterface(&platform, 0, AF_INET))
		return 1;
	if(ipv6 and not addInterface(&platform, 0, AF_INET6))
		return 1;

	auto pilot = rtmfp.openFlow(epd.data(), epd.size(), "pilot", 5);
	add_candidates(pilot, dstAddrs);
	Stream stream(fps, videoRate);

	pilot->onWritable = [&, pilot] {
		pilot->setSessionRetransmitLimit(20);
		pilot->setSessionCongestionDelay(delaycc_delay);
		stream.publish(pilot, &rl);
		return false;
	};
	pilot->onException = [&rtmfp] (uintmax_t reason) { printf("pilot exception: shutdown\n"); rtmfp.shutdown(true); };
	pilot->notifyWhenWritable();

	rl.run();

	printf("end.\n");
	return 0;
}
