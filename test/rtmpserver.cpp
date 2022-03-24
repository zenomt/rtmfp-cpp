#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "rtmfp/SelectRunLoop.hpp"
#include "rtmfp/TCMessage.hpp"
#include "rtmfp/AMF.hpp"
#include "rtmfp/Address.hpp"

#include "PosixStreamPlatformAdapter.hpp"

using namespace com::zenomt;
using namespace com::zenomt::rtmp;

using Args = std::vector<std::shared_ptr<AMF0>>;
using Bytes = std::vector<uint8_t>;

namespace {

int verbose = 0;
int port = 1935;
bool simpleMode = false;

class Client : public Object {
public:
	Client(RunLoop *rl);
	~Client();

	void close();

	static std::shared_ptr<Client> newClient(RunLoop *rl, int fd);

	void onMessage(uint32_t streamID, uint8_t messageType, uint32_t timestamp, const uint8_t *payload, size_t len);

protected:
	void onCommandMessage(uint32_t streamID, uint8_t messageType, const uint8_t *payload, size_t len);
	void onConnectCommand(const Args &args);
	void onCreateStreamCommand(const Args &args);
	void onPublishCommand(uint32_t streamID, const Args &args);

	PosixRTMPPlatformAdapter m_adapter;
	std::shared_ptr<RTMP> m_rtmp;
	uint32_t m_nextStreamID;
};

Client::Client(RunLoop *rl) : m_adapter(rl), m_nextStreamID(1)
{}

Client::~Client()
{
	close();
}

void Client::close()
{
	if(m_rtmp)
		m_rtmp->close();
	m_adapter.close();
}

std::shared_ptr<Client> Client::newClient(RunLoop *rl, int fd)
{
	auto client = share_ref(new Client(rl), false);
	if(not client->m_adapter.setSocketFd(fd))
	{
		client.reset();
		::close(fd); // just in case
		return client;
	}
	client->m_rtmp = share_ref(new RTMP(&client->m_adapter), false);
	if(not client->m_rtmp->init(true))
	{
		client.reset();
		return client;
	}

	client->m_rtmp->onmessage = [client] (uint32_t streamID, uint8_t messageType, uint32_t timestamp, const uint8_t *payload, size_t len) {
		client->onMessage(streamID, messageType, timestamp, payload, len);
	};

	client->m_rtmp->onerror = [client] {
		printf("protocol error %p\n", (void *)client.get());
		client->close();
	};

	client->m_rtmp->onopen = [] { printf("onopen!\n"); };

	if(simpleMode)
	{
		client->m_rtmp->setSimpleMode(true);
		client->m_rtmp->setChunkSize(1<<24);
	}

	return client;
}

void Client::onMessage(uint32_t streamID, uint8_t messageType, uint32_t timestamp, const uint8_t *payload, size_t len)
{
	if(verbose)
	{
		printf("streamID,%u,type,%d,timestamp,%u,len,%lu,time,%.3f,", streamID, messageType, timestamp, (unsigned long)len, (double)m_rtmp->getInstanceAge());
		if((TCMSG_VIDEO == messageType) and len)
			printf("%s", (0x10 == (payload[0] & 0xf0)) ? "keyframe" : "");
		if(0 == len)
			printf("silence");
		printf("\n");
		fflush(stdout);
	}
	switch(messageType)
	{
	case TCMSG_COMMAND:
	case TCMSG_COMMAND_EX:
		onCommandMessage(streamID, messageType, payload, len);
		break;

	default:
		break;
	}
}

void Client::onCommandMessage(uint32_t streamID, uint8_t messageType, const uint8_t *payload, size_t len)
{
	const uint8_t *cursor = payload;
	const uint8_t *limit = cursor + len;

	if(0 == len)
		return;
	if((TCMSG_COMMAND_EX == messageType) and (0 != *cursor++)) // COMMAND_EX has a format id, and only format id=0 is defined/allowed
		return;

	Args args;
	if(not AMF0::decode(cursor, limit, args))
	{
		if(verbose)
			printf("couldn't decode command arguments\n");
		close();
		return;
	}
	if(verbose)
	{
		printf("client %p received command\n", (void *)this);
		for(auto it = args.begin(); it != args.end(); it++)
			printf("  %s\n", (*it)->repr().c_str());
	}

	if( (args.size() < 3)
	 or (not args[0]->isString()) // command name
	 or (not args[1]->isNumber()) // transaction ID
	)
	{
		if(verbose)
			printf("invaild command format\n");
		close();
		return;
	}

	if((0 == streamID) and (0 == strcmp("connect", args[0]->stringValue())))
		onConnectCommand(args);
	else if((0 == streamID) and (0 == strcmp("createStream", args[0]->stringValue())))
		onCreateStreamCommand(args);
	else if((0 != streamID) and (0 == strcmp("publish", args[0]->stringValue())))
		onPublishCommand(streamID, args);
	else
	{
		// ...
	}
}

void Client::onConnectCommand(const Args &args)
{
	auto objectEncoding = args[2]->getValueAtKey("objectEncoding");
	if(not objectEncoding->isNumber())
		objectEncoding = AMF0::Number(0);

	m_rtmp->write(PRI_ROUTINE, 0, TCMSG_COMMAND, 0, Message::command("_result", args[1]->doubleValue(), nullptr,
		AMF0::Object()
			->putValueAtKey(AMF0::String("status"), "level")
			->putValueAtKey(AMF0::String("NetConnection.Connect.Success"), "code")
			->putValueAtKey(AMF0::String("you connected!"), "description")
			->putValueAtKey(objectEncoding, "objectEncoding")));
}

void Client::onCreateStreamCommand(const Args &args)
{
	m_rtmp->write(PRI_ROUTINE, 0, TCMSG_COMMAND, 0, Message::command("_result", args[1]->doubleValue(), nullptr, AMF0::Number(m_nextStreamID++)));
}

void Client::onPublishCommand(uint32_t streamID, const Args &args)
{
	m_rtmp->write(PRI_ROUTINE, streamID, TCMSG_COMMAND, 0, Message::command("onStatus", 0, nullptr,
		AMF0::Object()
			->putValueAtKey(AMF0::String("status"), "level")
			->putValueAtKey(AMF0::String("NetStream.Publish.Start"), "code")
			->putValueAtKey(AMF0::String("publishing"), "description")));
}

int usage(const char *prog, const char *msg, int rv)
{
	if(msg)
		printf("%s\n", msg);
	printf("usage: %s [options]\n", prog);
	printf("  -p port   -- listen on port (default %d)\n", port);
	printf("  -s        -- set simple mode for compatibility with bad RTMPs\n");
	printf("  -4        -- listen on IPv4 (default IPv6)\n");
	printf("  -v        -- increase verbose output\n");
	printf("  -h        -- show this help\n");

	return rv;
}

}

int main(int argc, char **argv)
{
	int family = AF_INET6;
	int ch;

	while((ch = getopt(argc, argv, "vhs4p:")) != -1)
	{
		switch(ch)
		{
		case 'v':
			verbose++;
			break;
		case '4':
			family = AF_INET;
			break;
		case 's':
			simpleMode = true;
			break;
		case 'p':
			port = atoi(optarg);
			break;

		case 'h':
		default:
			return usage(argv[0], NULL, 'h' != ch);
		}
	}

	int fd = socket(family, SOCK_STREAM, IPPROTO_TCP);
	if(fd < 0)
	{
		perror("socket");
		return 1;
	}
	{
		int val = 1;
		if(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val)))
			::perror("SO_REUSEADDR");
	}

	rtmfp::Address addr;
	addr.setFamily(family);
	addr.setPort(port);
	if(bind(fd, addr.getSockaddr(), addr.getSockaddrLen()))
	{
		perror("bind");
		return 1;
	}

	if(listen(fd, 5))
	{
		perror("listen");
		return 1;
	}

	SelectRunLoop rl;

	rl.registerDescriptor(fd, rl.READABLE, [] (RunLoop *sender, int fd, RunLoop::Condition cond) {
		rtmfp::Address::in_sockaddr boundAddr;
		socklen_t addrLen = sizeof(boundAddr);
		int newFd = accept(fd, &boundAddr.s, &addrLen);
		if(newFd < 0)
		{
			perror("accept");
			return;
		}

		printf("accepted from %s\n", rtmfp::Address(&boundAddr.s).toPresentation().c_str());
		Client::newClient(sender, newFd);
	});

	rl.run();

	return 0;
}
