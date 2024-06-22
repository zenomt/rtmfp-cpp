// Copyright © 2022 Michael Thornburgh
// SPDX-License-Identifier: MIT

// TC Publish: publish an FLV to a (currently only RTMFP) TC server.
// Implements `tcserver`’s hashed auth-token for authentication (use
// `-m` and `-M` options). Note that the auth-token is specified in the
// userinfo of the rtmfp-uri (example: `rtmfp://auth-token@server.example/app/name`).

// Limitations: the FLV should start at timestamp 0, and be less than 24 days long.
// TODO: When looping an FLV, account for the duration of the last audio frame to
//       decrease player drift, desync, or buffer creep.
// TODO: (maybe) Suppress @setDataFrame(onMetaData) on loop if there’s
//       only one onMetaData in the FLV.
// TODO: Extract FLVReader to library?

#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <netdb.h>

#include "rtmfp/rtmfp.hpp"
#include "rtmfp/RunLoops.hpp"
#include "rtmfp/FlashCryptoAdapter_OpenSSL.hpp"
#include "rtmfp/PerformerPosixPlatformAdapter.hpp"
#include "rtmfp/Hex.hpp"
#include "rtmfp/TCConnection.hpp"
#include "rtmfp/URIParse.hpp"
#include "rtmfp/Algorithm.hpp"

using namespace com::zenomt;
using namespace com::zenomt::rtmfp;
using namespace com::zenomt::rtmp;

namespace {

int verbose = 0;
Time delaycc_delay = INFINITY;
bool interrupted = false;
int dscp = 0;
Time videoLifetime = 2.0;
Time audioLifetime = 2.2;
Time finishByMargin = 0.1;
Time previousGopStartByMargin = 0.1;
bool expirePreviousGop = true;
bool hashAuthToken = false;
bool requireHashAuthToken = false;
bool releaseStream = false;
bool loop = false;

PreferredRunLoop mainRL;
Performer mainPerformer(&mainRL);
PreferredRunLoop workerRL;
Performer workerPerformer(&workerRL);

void signal_handler(int unused)
{
	interrupted = true;
}

class FLVReader : public Object {
public:
	FLVReader(FILE *flv) :
		m_flv(flv)
	{}

	~FLVReader()
	{
		fclose(m_flv);
	}

	void rewind()
	{
		::rewind(m_flv);
		m_headerRead = false;
	}

	bool skipOverHeader()
	{
		if(m_headerRead)
			return true;

		uint8_t flvHeader[9];
		if(1 != fread(flvHeader, sizeof(flvHeader), 1, m_flv))
			return false; // short file

		size_t headerLength = (flvHeader[5] << 24) + (flvHeader[6] << 16) + (flvHeader[7] << 8) + flvHeader[8];
		if( ('F' != flvHeader[0])
		 or ('L' != flvHeader[1])
		 or ('V' != flvHeader[2])
		 or (headerLength < sizeof(flvHeader))
		)
			return false; // not an FLV

		// skip over any extra header info
		size_t extra = headerLength - sizeof(flvHeader);
		while(extra--)
		{
			if(EOF == fgetc(stdin))
				return false;
		}

		m_headerRead = true;

		return true;
	}

	bool getNextTag(uint8_t &type, uint32_t &timestamp, Bytes &dst)
	{
		if(not skipOverHeader())
			return false;

		uint8_t tagHeader[4+11]; // previous tag offset plus actual tag header
		size_t tagLength;

		if(1 != fread(tagHeader, sizeof(tagHeader), 1, m_flv))
			return false;

		type = tagHeader[4];
		tagLength = (tagHeader[5] << 16) + (tagHeader[6] << 8) + tagHeader[7];
		timestamp = (tagHeader[11] << 24) + (tagHeader[8] << 16) + (tagHeader[9] << 8) + tagHeader[10];

		if(tagLength)
		{
			dst.resize(tagLength);
			if(1 != fread(dst.data(), tagLength, 1, m_flv))
				return false;
		}
		else
			dst.resize(0);

		return true;
	}

	struct Tag : public Object {
		uint8_t type;
		uint32_t timestamp;
		Bytes data;
	};

	std::shared_ptr<Tag> getNextTag()
	{
		std::shared_ptr<Tag> rv = share_ref(new Tag(), false);
		if(not getNextTag(rv->type, rv->timestamp, rv->data))
			return nullptr;
		return rv;
	}

protected:
	FILE *m_flv { nullptr };
	bool m_headerRead { false };
};

class Publisher : public Object {
public:
	Publisher(RTMFP *rtmfp, FlashCryptoAdapter *crypto, const URIParse &uri, const char *fingerprint, const std::string &publishName, FILE *flvFile) :
		m_rtmfp(rtmfp),
		m_crypto(crypto),
		m_destFingerprint(fingerprint ? fingerprint : ""),
		m_publishName(publishName),
		m_uri(uri)
	{
		if(verbose) printf("new Publisher %p\n", (void *)this);

		if(not m_uri.userinfoPart.empty())
		{
			m_connectArgs = collect<std::shared_ptr<AMF0>>(AMF0::String, collect<std::string>(URIParse::safePercentDecode, URIParse::split(m_uri.userinfo, ':')));
			m_authToken = m_connectArgs.back();
		}

		m_flvReader = share_ref(new FLVReader(flvFile), false);
	}

	~Publisher()
	{
		if(verbose) printf("~Publisher %p\n", (void *)this);
	}

	bool start()
	{
		if(m_tcconn)
			return false;

		if(not m_flvReader->skipOverHeader())
		{
			printf("error reading FLV\n");
			return false;
		}

		Bytes epd = FlashCryptoAdapter::makeEPD(m_destFingerprint.empty() ? nullptr : m_destFingerprint.c_str(), m_uri.publicUri.c_str(), nullptr);
		if(epd.empty())
		{
			printf("couldn't construct EPD: bad fingerprint %s\n", m_destFingerprint.c_str());
			return false;
		}

		m_tcconn = share_ref(new RunLoopRTMFPTCConnection(&mainRL, std::max(0, verbose - 1)), false);
		if(not m_tcconn->init(m_rtmfp, epd))
			return false;

		m_tcconn->onTransportOpen = [this] { onTransportOpen(); };
		m_tcconn->onClose = [this] { onClose(); };
		m_tcconn->onStatus = [this] (std::shared_ptr<AMF0> info) { onConnectionStatus(info); };

		int lookupError = 0;
		m_tcconn->addCandidateAddresses(Address::lookup(URIParse::safePercentDecode(m_uri.host).c_str(), m_uri.effectivePort.c_str(), &lookupError));
		if(lookupError)
		{
			printf("couldn't look up hostinfo: %s\n", gai_strerror(lookupError));
			return false;
		}

		return true;
	}

	void onTransportOpen()
	{
		printf("onTransportOpen\n");
		printf("  far address: %s\n", m_tcconn->sessionOpt()->getFarAddress().toPresentation().c_str());
		printf("  fingerprint: %s\n", Hex::encode(m_tcconn->getServerFingerprint()).c_str());
		printf("   near nonce: %s\n", Hex::encode(m_tcconn->sessionOpt()->getNearNonce()).c_str());
		printf("    far nonce: %s\n", Hex::encode(m_tcconn->sessionOpt()->getFarNonce()).c_str());
		printf("\n");

		m_tcconn->sessionOpt()->setSessionTrafficClass(dscp << 2);
		m_tcconn->sessionOpt()->setSessionCongestionDelay(delaycc_delay);

		if(m_authToken and hashAuthToken)
			m_connectArgs.back() = AMF0::String(hexHMACSHA256(m_tcconn->sessionOpt()->getFarNonce(), m_authToken->stringValue()));

		m_tcconn->connect(
			[this] (bool success, std::shared_ptr<AMF0> result) { onConnectResult(success, result); }
			, m_uri.publicUri
			, AMF0::Object()
				->putValueAtKey(AMF0::Number(0), "capsEx") // no multitrack, no reconnect
				->putValueAtKey(AMF0::Object()->putValueAtKey(AMF0::Number(2), "*"), "videoFourCcInfoMap") // can encode all
				->putValueAtKey(AMF0::Object()->putValueAtKey(AMF0::Number(2), "*"), "audioFourCcInfoMap") // can encode all
			, m_connectArgs
		);
	}

	void onConnectResult(bool success, std::shared_ptr<AMF0> result)
	{
		printf("onConnect %s: %s\n", success ? "success" : "fail", result ? result->repr().c_str() : "");
		if(not success)
			return;

		if(m_authToken and requireHashAuthToken)
		{
			auto serverAuthToken = result->getValueAtKey("authToken");
			if( (not serverAuthToken->isString())
			 or (hexHMACSHA256(m_tcconn->sessionOpt()->getNearNonce(), m_authToken->stringValue()) != serverAuthToken->stringValue())
			)
			{
				printf("!!! server didn't authenticate. closing...\n\n");
				m_tcconn->close();
				return;
			}
		}

		if(releaseStream)
			m_tcconn->command("releaseStream", { AMF0::Null(), AMF0::String(m_publishName) });

		m_publishStream = m_tcconn->createStream();
		m_publishStream->onStatus = [this] (std::shared_ptr<AMF0> info) { onStreamStatus(info); };
		m_publishStream->publish(m_publishName);

		// wait for NetStream.Publish.Start in onStatus
	}

	void onClose()
	{
		printf("connection onClose\n");
		m_rtmfp->shutdown(true);
	}

	void onConnectionStatus(std::shared_ptr<AMF0> info)
	{
		printf("connection onStatus: %s\n", info->repr().c_str());
	}

	void onStreamStatus(std::shared_ptr<AMF0> info)
	{
		printf("stream  onStatus: %s\n", info->repr().c_str());
		auto code = info->getValueAtKey("code");
		if(not code->isString())
			return; // ignore

		std::string codestr = code->stringValue();

		if(codestr == "NetStream.Publish.BadName")
		{
			// note this can happen after publish start, for example if someone else does a releaseStream
			printf("publish rejected. stopping.\n");
			m_tcconn->close();
		}
		else if(codestr == "NetStream.Publish.Start")
			publishStart();
	}

	void publishStart()
	{
		if(m_publishing)
			return;
		m_publishing = true;

		printf("publish start.\n");

		auto myself = share_ref(this);
		workerPerformer.perform([this, myself] { workerPublishStart(); });
	}

	void publishStop()
	{
		printf("publish stop.\n");
		m_tcconn->close();
	}

	void workerPublishStart()
	{
		m_origin = workerRL.getCurrentTime();
		workerScheduleNextFrame(false);
	}

	void workerScheduleNextFrame(bool stopOnEmpty)
	{
		auto myself = share_ref(this);
		auto tag = m_flvReader->getNextTag();
		if(not tag)
		{
			// TODO: this can cause drift with players that don’t handle audio timestamps properly.
			// TODO: this also has a problem if FLV timestamps don’t start at 0 (but they should).
			m_timestampAdjust = m_highestTimestamp;
			m_origin = workerRL.getCurrentTime();

			m_flvReader->rewind();
			if((not loop) or stopOnEmpty or not m_flvReader->skipOverHeader())
			{
				mainPerformer.perform([this, myself] { publishStop(); });
				return;
			}

			workerScheduleNextFrame(true);
			return;
		}

		tag->timestamp += m_timestampAdjust;
		if(Message::timestamp_gt(tag->timestamp, m_highestTimestamp))
			m_highestTimestamp = tag->timestamp;

		// BUG: this doesn’t work for FLVs longer than 24.8 days.
		// WORKAROUND: only publish FLVs that start at 0 and are less than 24 days long. :)
		Time when = m_origin + (Message::timestamp_diff(tag->timestamp, m_timestampAdjust) / 1000.0);
		workerRL.schedule([myself, this, tag] (const std::shared_ptr<Timer> &sender, Time now) { workerOnTagAlarm(tag); }, when);
	}

	void workerOnTagAlarm(std::shared_ptr<FLVReader::Tag> tag)
	{
		auto myself = share_ref(this);
		mainPerformer.perform([this, myself, tag] { onTag(tag); });

		workerScheduleNextFrame(false);
	}

	void onTag(std::shared_ptr<FLVReader::Tag> tag)
	{
		switch(tag->type)
		{
		case TCMSG_VIDEO:
			onVideoTag(tag);
			break;

		case TCMSG_AUDIO:
			onAudioTag(tag);
			break;

		case TCMSG_DATA:
			onDataTag(tag);
			break;
		}
	}

	void onVideoTag(std::shared_ptr<FLVReader::Tag> tag)
	{
		Time startWithin = Message::isVideoSequenceSpecial(tag->data.data(), tag->data.size()) ? INFINITY : videoLifetime;
		auto receipt = m_publishStream->sendVideo(tag->timestamp, tag->data, startWithin, startWithin + finishByMargin);

		if(Message::isVideoKeyframe(tag->data.data(), tag->data.size()))
			m_publishStream->expireChain(
				expirePreviousGop ? mainRL.getCurrentTime() + previousGopStartByMargin : INFINITY,
				expirePreviousGop ? mainRL.getCurrentTime() + finishByMargin : INFINITY);

		if(startWithin < INFINITY)
			m_publishStream->chain(receipt);

		if(verbose and receipt)
			receipt->onFinished = [] (bool abandoned) { if(abandoned) { printf("-"); fflush(stdout); } };
	}

	void onAudioTag(std::shared_ptr<FLVReader::Tag> tag)
	{
		Time startWithin = Message::isAudioSequenceSpecial(tag->data.data(), tag->data.size()) ? INFINITY : audioLifetime;
		auto receipt = m_publishStream->sendAudio(tag->timestamp, tag->data, startWithin, startWithin + finishByMargin);
		if(verbose and receipt)
			receipt->onFinished = [] (bool abandoned) { if(abandoned) { printf("_"); fflush(stdout); } };
	}

	void onDataTag(std::shared_ptr<FLVReader::Tag> tag)
	{
		TCConnection::Args args;
		AMF0::decode(tag->data.data(), tag->data.data() + tag->data.size(), args);
		if(args.empty() or not args[0]->isString())
			return;

		if(std::string(args[0]->stringValue()) == "onMetaData") // special
			m_publishStream->send(tag->timestamp, "@setDataFrame", args);
		else
		{
			std::string command = args[0]->stringValue();
			args.erase(args.begin());
			m_publishStream->send(tag->timestamp, command, args);
		}
	}

	std::string hexHMACSHA256(const Bytes &key, const std::string &msg)
	{
		uint8_t md[32] = { 0 };
		m_crypto->hmacSHA256(md, key.data(), key.size(), msg.data(), msg.size());
		return Hex::encode(md, sizeof(md));
	}

protected:
	RTMFP *m_rtmfp;
	FlashCryptoAdapter *m_crypto;
	std::string m_destFingerprint;
	std::string m_publishName;
	URIParse m_uri;
	std::shared_ptr<RTMFPTCConnection> m_tcconn;
	std::shared_ptr<TCStream> m_publishStream;
	std::vector<std::shared_ptr<AMF0>> m_connectArgs;
	std::shared_ptr<AMF0> m_authToken;
	bool m_publishing { false };
	std::shared_ptr<FLVReader> m_flvReader;
	Time m_origin { 0 };
	uint32_t m_highestTimestamp { 0 };
	uint32_t m_timestampAdjust { 0 };
};

std::string streamNameFromFilename(std::string filename)
{
	// C++17 has std::filesystem::path::stem, but we’re targeting C++11

	size_t lastSlash = filename.rfind('/');
	std::string basename = (std::string::npos == lastSlash) ? filename : filename.substr(lastSlash + 1);
	if((basename.size() > 4) and (basename.substr(basename.size() - 4) == ".flv"))
		return basename.substr(0, basename.size() - 4);
	return basename;
}

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

int errormsg(const char *name, int rv, const char *msg = nullptr, const char *arg = nullptr)
{
	printf("%s: %s%s\n", name, msg ? msg : "", arg ? arg : "");
	return rv;
}

int usage(const char *name, int rv, const char *msg = nullptr, const char *arg = nullptr)
{
	if(msg)
		printf("%s", msg);
	if(arg)
		printf("%s", arg);
	if(msg or arg)
		printf("\n");

	printf("usage: %s [options] rtmfp-uri flv-file\n", name);
	printf("  -V secs      -- video queue lifetime (default %.3Lf)\n", videoLifetime);
	printf("  -A secs      -- audio queue lifetime (default %.3Lf)\n", audioLifetime);
	printf("  -F secs      -- finish-by margin (default %.3Lf)\n", finishByMargin);
	printf("  -e secs      -- expire previous GOP start-by margin (default %.3Lf)\n", previousGopStartByMargin);
	printf("  -E           -- don't expire previous GOP\n");
	printf("  -L           -- loop stream forever\n");
	printf("  -R           -- send releaseStream before publish\n");
	printf("  -f finger    -- set required server fingerprint in endpoint discriminator\n");
	printf("  -m           -- hash auth-token (tcserver)\n");
	printf("  -M           -- require hashed auth-token in connect response (tcserver)\n");
	printf("  -T DSCP|name -- set DiffServ field on outgoing packets (default %d)\n", dscp);
	printf("  -X secs      -- set congestion extra delay threshold (default %.3Lf)\n", delaycc_delay);
	printf("  -H           -- don't require HMAC\n");
	printf("  -S           -- don't require session sequence numbers\n");
	printf("  -4           -- only bind to 0.0.0.0\n");
	printf("  -6           -- only bind to [::]\n");
	printf("  -v           -- increase verboseness\n");
	printf("  -h           -- show this help\n");
	printf("\n");
	printf("default stream name is basename of flv-file minus \".flv\". override with\n");
	printf("rtmfp-uri fragment identifier.\n");
	printf("\n");
	printf("example rtmfp-uris:\n");
	printf("  rtmfp://server.example/live/instance\n");
	printf("  rtmfp://auth-token@server.example/live/instance#stream-name\n");
	printf("  rtmfp://username:password@server.example/live/instance#stream-name\n");
	return rv;
}

// https://www.iana.org/assignments/dscp-registry/dscp-registry.xhtml
std::map<std::string, int> dscp_codepoints({
	{ "CS0", 0 }, { "CS1", 8 }, { "CS2", 16 }, { "CS3", 24 }, { "CS4", 32 }, { "CS5", 40 }, { "CS6", 48 }, { "CS7", 56 },
	{ "AF11", 10 }, { "AF12", 12 }, { "AF13", 14 },
	{ "AF21", 18 }, { "AF22", 20 }, { "AF23", 22 },
	{ "AF31", 26 }, { "AF32", 28 }, { "AF33", 30 },
	{ "AF41", 34 }, { "AF42", 36 }, { "AF43", 38 },
	{ "EF", 46 }, { "VOICE-ADMIT", 44 },
	{ "LE", 1 }
});
int convert_dscp(const std::string &name)
{
	errno = 0;
	if(dscp_codepoints.count(name))
		return dscp_codepoints[name];
	const char *s = name.c_str();
	char *endptr = nullptr;
	int rv = int(strtol(s, &endptr, 0));
	if((0 == rv) and (endptr == s)) // no conversion, not all strtol() set errno
		errno = EINVAL;
	return rv;
}

}

int main(int argc, char **argv)
{
	bool ipv4 = true;
	bool ipv6 = true;
	bool requireHMAC = true;
	bool requireSSEQ = true;
	const char *fingerprint = nullptr;
	int ch;

	while((ch = getopt(argc, argv, "V:A:F:e:ELRf:mMT:X:HS46vh")) != -1)
	{
		switch(ch)
		{
		case 'V':
			videoLifetime = atof(optarg);
			break;

		case 'A':
			audioLifetime = atof(optarg);
			break;

		case 'F':
			finishByMargin = atof(optarg);
			break;

		case 'e':
			previousGopStartByMargin = atof(optarg);
			break;

		case 'E':
			expirePreviousGop = false;
			break;

		case 'L':
			loop = true;
			break;

		case 'R':
			releaseStream = true;
			break;

		case 'f':
			fingerprint = optarg;
			break;

		case 'm':
			hashAuthToken = true;
			break;

		case 'M':
			requireHashAuthToken = true;
			break;

		case 'T':
			dscp = convert_dscp(optarg);
			if(errno)
			{
				printf("DiffServ names: ");
				for(auto it = dscp_codepoints.begin(); it != dscp_codepoints.end(); it++)
					printf("%s ", it->first.c_str());
				printf("\n");
				return usage(argv[0], 1, "unrecognized DiffServ name: ", optarg);
			}
			break;

		case 'X':
			delaycc_delay = atof(optarg);
			break;

		case 'H':
			requireHMAC = false;
			break;

		case 'S':
			requireSSEQ = false;
			break;

		case '4':
			ipv4 = true;
			ipv6 = false;
			break;

		case '6':
			ipv4 = false;
			ipv6 = true;
			break;

		case 'v':
			verbose++;
			break;

		case 'h':
		default:
			return usage(argv[0], 'h' != ch);
		}
	}

	if(argc <= optind + 1)
		return usage(argv[0], 1, "specify rtmfp uri and FLV filename\n");

	URIParse uri(argv[optind]);
	if(uri.canonicalScheme != "rtmfp") // maybe more later
		return usage(argv[0], 1, "unsupported scheme: ", uri.scheme.c_str());
	if(uri.host.empty() or uri.effectivePort.empty())
		return usage(argv[0], 1, "can't parse uri hostinfo: ", argv[optind]);

	if(not uri.userinfoPart.empty())
		memset(argv[optind], '#', strlen(argv[optind]));

	if(hashAuthToken and uri.userinfoPart.empty())
		printf("warning: auth-token hashing requested but no auth-token in uri userinfo\n");

	if(requireHashAuthToken and uri.userinfoPart.empty())
		return usage(argv[0], 1, "error: -M missing auth-token in uri (e.g. rtmfp://auth-token@server.example)");

	FILE *flvFile = fopen(argv[optind + 1], "rb");
	if(not flvFile)
	{
		perror(argv[optind + 1]);
		return 1;
	}

	std::string publishName = uri.fragmentPart.empty() ? streamNameFromFilename(argv[optind + 1]) : URIParse::safePercentDecode(uri.fragment);

	printf("publish %s to %s\n", publishName.c_str(), uri.publicUri.c_str());

	FlashCryptoAdapter_OpenSSL crypto;
	if(not crypto.init(false, nullptr))
		return errormsg(argv[0], 1, "can't init crypto");
	crypto.setHMACSendAlways(requireHMAC);
	crypto.setHMACRecvRequired(requireHMAC);
	crypto.setSSeqSendAlways(requireSSEQ);
	crypto.setSSeqRecvRequired(requireSSEQ);
	printf("my fingerprint: %s\n", Hex::encode(crypto.getFingerprint()).c_str());

	PerformerPosixPlatformAdapter platform(&mainRL, &mainPerformer, &workerPerformer);
	RTMFP rtmfp(&platform, &crypto);
	platform.setRtmfp(&rtmfp);

	if(ipv6 and not addInterface(&platform, 0, AF_INET6))
		return 1;
	if(ipv4 and not addInterface(&platform, 0, AF_INET))
		return 1;

	auto publisher = share_ref(new Publisher(&rtmfp, &crypto, uri, fingerprint, publishName, flvFile), false);
	if(not publisher->start())
		return 1;

	::signal(SIGINT, signal_handler);
	::signal(SIGTERM, signal_handler);
	mainRL.onEveryCycle = [&rtmfp] { if(interrupted) { interrupted = false; rtmfp.shutdown(true); printf("interrupted. shutting down.\n"); } };
	platform.onShutdownCompleteCallback = [] { mainRL.stop(); };

	auto workerThread = std::thread([] { workerRL.run(); });

	mainRL.run();

	workerPerformer.perform([] { workerRL.stop(); });
	workerThread.join();

	printf("end.\n");
	return 0;
}
