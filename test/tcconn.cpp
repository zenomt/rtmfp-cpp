#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <netdb.h>

#include "rtmfp/rtmfp.hpp"
#include "rtmfp/RunLoops.hpp"
#include "rtmfp/FlashCryptoAdapter_OpenSSL.hpp"
#include "rtmfp/PosixPlatformAdapter.hpp"
#include "rtmfp/Hex.hpp"
#include "rtmfp/TCConnection.hpp"
#include "rtmfp/URIParse.hpp"
#include "rtmfp/Algorithm.hpp"

#ifndef IPTOS_DSCP_AF41
#define IPTOS_DSCP_AF41 0x88
#endif

using namespace com::zenomt;
using namespace com::zenomt::rtmfp;
using namespace com::zenomt::rtmp;
using Args = std::vector<std::shared_ptr<AMF0>>;

namespace {

int verbose = 0;
Time delaycc_delay = INFINITY;
bool interrupted = false;
int tos = 0;

void signal_handler(int unused)
{
	interrupted = true;
}

std::string hexHMACSHA256(FlashCryptoAdapter *crypto, const Bytes &key, const std::string &msg)
{
	uint8_t md[32] = { 0 };
	crypto->hmacSHA256(md, key.data(), key.size(), msg.data(), msg.size());
	return Hex::encode(md, sizeof(md));
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

	printf("usage: %s [options] rtmfp-uri\n", name);
	printf("  -H        -- don't require HMAC\n");
	printf("  -S        -- don't require session sequence numbers\n");
	printf("  -4        -- only bind to 0.0.0.0\n");
	printf("  -6        -- only bind to [::]\n");
	printf("  -f finger -- set required fingerprint in endpoint discriminator\n");
	printf("  -m        -- hash auth token (tcserver)\n");
	printf("  -M        -- require hashed auth token in connect response (tcserver)\n");
	printf("  -x        -- set DSCP AF41 on outgoing packets\n");
	printf("  -X secs   -- set congestion extra delay threshold (default %.3Lf)\n", delaycc_delay);
	printf("  -v        -- increase verboseness\n");
	printf("  -h        -- show this help\n");
	printf("\n");
	printf("default stream name is \"live\". override with rtmfp-uri fragment identifier.\n");
	printf("\n");
	printf("example rtmfp-uris:\n");
	printf("  rtmfp://server.example/app/instance\n");
	printf("  rtmfp://server.example/app/instance#stream-name\n");
	printf("  rtmfp://user:pass@server.example/app#stream-name\n");
	return rv;
}

}

int main(int argc, char **argv)
{
	bool ipv4 = true;
	bool ipv6 = true;
	bool requireHMAC = true;
	bool requireSSEQ = true;
	bool hashAuthToken = false;
	bool requireHashAuthToken = false;
	const char *fingerprint = nullptr;
	int ch;

	while((ch = getopt(argc, argv, "h46HSf:mMxX:v")) != -1)
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
		case 'f':
			fingerprint = optarg;
			break;
		case 'm':
			hashAuthToken = true;
			break;
		case 'M':
			requireHashAuthToken = true;
			break;
		case 'x':
			tos = IPTOS_DSCP_AF41;
			break;
		case 'X':
			delaycc_delay = atof(optarg);
			break;
		case 'v':
			verbose++;
			break;
		case 'h':
		default:
			return usage(argv[0], 'h' != ch);
		}
	}

	if(argc <= optind)
		return usage(argv[0], 1, "specify rtmfp uri");

	URIParse uri(argv[optind]);
	if(uri.canonicalScheme != "rtmfp") // maybe more later
		return usage(argv[0], 1, "unsupported scheme: ", uri.scheme.c_str());
	if(uri.host.empty() or uri.effectivePort.empty())
		return usage(argv[0], 1, "can't parse uri hostinfo: ", argv[optind]);

	std::string streamName = uri.fragmentPart.empty() ? "live" : uri.fragment;

	printf("play %s from: %s\n", streamName.c_str(), uri.publicUri.c_str());

	if(not uri.userinfoPart.empty())
		memset(argv[optind], '#', strlen(argv[optind]));

	Bytes epd = FlashCryptoAdapter::makeEPD(fingerprint, uri.publicUri.c_str(), nullptr);
	if(epd.empty())
		return errormsg(argv[0], 1, "couldn't construct EPD");
	if(verbose)
		Hex::print("EPD", epd);

	FlashCryptoAdapter_OpenSSL crypto;
	if(not crypto.init(false, NULL))
		return errormsg(argv[0], 1, "can't init crypto");
	crypto.setHMACSendAlways(requireHMAC);
	crypto.setHMACRecvRequired(requireHMAC);
	crypto.setSSeqSendAlways(requireSSEQ);
	crypto.setSSeqRecvRequired(requireSSEQ);
	printf("my fingerprint: %s\n", Hex::encode(crypto.getFingerprint()).c_str());

	PreferredRunLoop rl;
	PosixPlatformAdapter platform(&rl);
	RTMFP rtmfp(&platform, &crypto);
	platform.setRtmfp(&rtmfp);

	rtmfp.setDefaultSessionKeepalivePeriod(30);
	rtmfp.setDefaultSessionRetransmitLimit(20);

	::signal(SIGINT, signal_handler);
	::signal(SIGTERM, signal_handler);
	rl.onEveryCycle = [&rtmfp] { if(interrupted) { interrupted = false; rtmfp.shutdown(true); printf("interrupted. shutting down.\n"); } };
	platform.onShutdownCompleteCallback = [&rl] { rl.stop(); };

	if(ipv4 and not addInterface(&platform, 0, AF_INET))
		return 1;
	if(ipv6 and not addInterface(&platform, 0, AF_INET6))
		return 1;

	auto tcconn = share_ref(new RunLoopRTMFPTCConnection(&rl, verbose), false);
	tcconn->init(&rtmfp, epd);
	tcconn->onTransportOpen = [tcconn, uri, hashAuthToken, requireHashAuthToken, &crypto, streamName] {
		printf("transport open\n");
		printf("  far address: %s\n", tcconn->sessionOpt()->getFarAddress().toPresentation().c_str());
		printf("  fingerprint: %s\n", Hex::encode(tcconn->getServerFingerprint()).c_str());
		printf("   near nonce: %s\n", Hex::encode(tcconn->sessionOpt()->getNearNonce()).c_str());
		printf("    far nonce: %s\n", Hex::encode(tcconn->sessionOpt()->getFarNonce()).c_str());
		printf("\n");

		tcconn->sessionOpt()->setSessionTrafficClass(tos);
		tcconn->sessionOpt()->setSessionCongestionDelay(delaycc_delay);
		tcconn->sessionOpt()->setSessionFIHelloMode(FI_SEND_RHELLO);

		auto connectArgs = collect<std::shared_ptr<AMF0>>(AMF0::String, uri.userinfoPart.empty() ? std::vector<std::string>() : uri.split(uri.userinfo, ':'));
		std::shared_ptr<AMF0> authToken = connectArgs.empty() ? nullptr : connectArgs.back();
		if(authToken and hashAuthToken)
			connectArgs.back() = AMF0::String(hexHMACSHA256(&crypto, tcconn->sessionOpt()->getFarNonce(), authToken->stringValue()));

		tcconn->connect(
			[tcconn, authToken, requireHashAuthToken, &crypto, streamName] (bool success, std::shared_ptr<AMF0> result) {
				printf("onConnect %s %s\n\n", success ? "success" : "failure", result ? result->repr().c_str() : "nullptr");
				if(not success)
					return;

				if(authToken and requireHashAuthToken)
				{
					auto serverAuthToken = result->getValueAtKey("authToken");
					if( (not serverAuthToken->isString())
					 or (hexHMACSHA256(&crypto, tcconn->sessionOpt()->getNearNonce(), authToken->stringValue()) != serverAuthToken->stringValue())
					)
					{
						printf("!!! server didn't authenticate. closing...\n\n");
						tcconn->close();
						return;
					}
				}

				tcconn->command("setPeerInfo", { AMF0::Null() });

				// Adobe Media Server rejects connections if you send a createStream before connect is complete.
				// This could be pipelined with connect for tcserver, rather than here in the connect Handler.
				auto stream = tcconn->createStream();
				stream->onOpen = [] { printf("stream onOpen\n\n"); };
				stream->onStatus = [] (std::shared_ptr<AMF0> info) { printf("stream onStatus: %s\n\n", info->repr().c_str()); };
				stream->onData = [] (uint32_t timestamp, const std::string &command, const Args &args) {
					printf("stream onData ts: %u command: %s\n", (unsigned)timestamp, command.c_str());
					for(auto it = args.begin(); it != args.end(); it++)
						printf("  %s\n", (*it)->repr().c_str());
					printf("\n");
				};
				stream->onVideo = [] (uint32_t timestamp, const uint8_t *bytes, size_t len) {
					printf("stream onVideo ts: %u len: %zu\n", (unsigned)timestamp, len);
				};
				stream->onAudio = [] (uint32_t timestamp, const uint8_t *bytes, size_t len) {
					printf("stream onAudio ts: %u len: %zu\n", (unsigned)timestamp, len);
				};

				stream->play(streamName);
			}
			, uri.publicUri
			, AMF0::Object()
				->putValueAtKey(AMF0::Number(0xffff), "videoCodecs") // wildcard
				->putValueAtKey(AMF0::Number(0xffff), "audioCodecs") // wildcard
			, connectArgs
		);
	};

	tcconn->onClose = [&rtmfp] { printf("connection onClosed\n"); rtmfp.shutdown(true); };
	tcconn->onStatus = [] (std::shared_ptr<AMF0> info) { printf("connection onStatus: %s\n\n", info->repr().c_str()); };
	tcconn->onCommand = [] (const std::string &command, const Args &args) {
		printf("connection onCommand command: %s\n\n", command.c_str());
		for(auto it = args.begin(); it != args.end(); it++)
			printf("  %s\n", (*it)->repr().c_str());
	};

	int lookupError = 0;
	tcconn->addCandidateAddresses(Address::lookup(uri.host.c_str(), uri.effectivePort.c_str(), &lookupError));
	if(lookupError)
		return errormsg(argv[0], 1, "couldn't look up host: ", gai_strerror(lookupError));

	rl.run();

	printf("end.\n");
	return 0;
}
