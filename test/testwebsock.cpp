
#include "rtmfp/RunLoops.hpp"
#include "rtmfp/Address.hpp"
#include "rtmfp/Hex.hpp"

#include "SimpleWebSocket.hpp"
#include "PosixStreamPlatformAdapter.hpp"
#include "RTWebSocket.hpp"
#include "SimpleWebSocketMessagePlatformAdapter.hpp"

extern "C" {
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>
}

using namespace com::zenomt;
using namespace com::zenomt::rtws;
using namespace com::zenomt::websock;
using Address = com::zenomt::rtmfp::Address;

namespace {

PreferredRunLoop rl;

class TrackRTWebSocket : public RTWebSocket {
public:
	using RTWebSocket::RTWebSocket;

	~TrackRTWebSocket()
	{
		printf("~TrackRTWebSocket\n");
	}
};

class Client : public Object {
public:
	static void newClient(int fd, const Address &addr)
	{
		auto client = share_ref(new Client(), false);
		if(not client->m_platformStream->setSocketFd(fd))
		{
			::close(fd);
			return;
		}

		client->m_farAddress = addr;
		client->m_websock = share_ref(new SimpleWebSocket_OpenSSL(client->m_platformStream), false);
		client->m_wsMessageAdapter->init(client->m_websock);
		client->m_wsMessageAdapter->onOpen = [client] { client->onWebsockOpen(); };
		client->m_rtws = share_ref(new TrackRTWebSocket(client->m_wsMessageAdapter), false);
		client->m_rtws->onError = [client] { printf("RTWebSocket onError\n"); };
	}

	Client()
	{
		m_platformStream = share_ref(new PosixStreamPlatformAdapter(&rl), false);
		m_wsMessageAdapter = share_ref(new SimpleWebSocketMessagePlatformAdapter(m_platformStream), false);
	}

	~Client() { printf("~Client\n"); }

	void onWebsockOpen()
	{
		printf("onWebsocketOpen\n");
		m_rtws->init();
		m_rtws->onRecvFlow = [this] (std::shared_ptr<RecvFlow> flow) { onRecvFlow(flow); };
	}

	void onRecvFlow(std::shared_ptr<RecvFlow> flow)
	{
		Bytes metadata = flow->getMetadata();
		Hex::print("onRecvFlow! metadata", metadata);
		flow->accept();

		// auto sendFlow = flow->openReturnFlow(metadata);
		auto sendFlow = m_rtws->openFlow("return", 6);
		if(sendFlow)
		{
			if((metadata.size() > 3) and (0 == memcmp(metadata.data(), "imm", 3)))
				sendFlow->setPriority(PRI_IMMEDIATE);
			sendFlow->onException = [] (uintmax_t reason, const std::string &description) { printf("onException reason %lu \"%s\"\n", (unsigned long)reason, description.c_str()); };
		}
		else
			printf("couldn't open SendFlow\n");

		flow->onMessage = [this, flow, sendFlow] (const uint8_t *bytes, size_t len, uintmax_t messageNumber) {
			printf("onMessage #%lu ", (unsigned long)messageNumber);
			if(len < 1000)
				Hex::print(nullptr, bytes, len);
			else
				printf("(%lu)\n", (unsigned long)len);
			if(sendFlow)
			{
				auto receipt = sendFlow->write(bytes, len);
				if(receipt)
				{
					receipt->onFinished = [this] (bool abn) {
						printf("sent%s rtt:%f\n", abn ? " abandoned" : "", (double)m_rtws->getRTT());
					};
					printf("got a receipt\n");
				}
				else
					printf("no receipt\n");
			}
			else
				printf("no return flow\n");

			if(sendFlow and (sendFlow->getPriority() < PRI_IMMEDIATE))
			{
				flow->setPaused(true);
				printf("pause\n");
				rl.scheduleRel(Timer::makeAction([flow] { flow->setPaused(false); printf("unpause\n"); }), 2);
			}
		};
		flow->onComplete = [flow, sendFlow] { Hex::print("onComplete", flow->getMetadata()); sendFlow->close(); };
	}

protected:
	std::shared_ptr<PosixStreamPlatformAdapter> m_platformStream;
	std::shared_ptr<SimpleWebSocketMessagePlatformAdapter> m_wsMessageAdapter;
	std::shared_ptr<SimpleWebSocket> m_websock;
	std::shared_ptr<RTWebSocket> m_rtws;
	
	Address m_farAddress;
};

}

int main(int argc, char **argv)
{
	if(argc < 2)
		return 1;

	Address bindaddr;
	if(not bindaddr.setFromPresentation(argv[1]))
		return 1;

	int fd = socket(bindaddr.getFamily(), SOCK_STREAM, IPPROTO_TCP);
	if(fd < 0)
	{
		::perror("socket");
		return 1;
	}
	{
		int val = 1;
		if(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val)))
			::perror("SO_REUSEADDR");
		setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &val, sizeof(val));
	}
	if(bind(fd, bindaddr.getSockaddr(), bindaddr.getSockaddrLen()))
	{
		::perror("bind");
		return 1;
	}
	if(listen(fd, 5))
	{
		::perror("listen");
		return 1;
	}

	rl.registerDescriptor(fd, RunLoop::READABLE, [] (RunLoop *sender, int fd, RunLoop::Condition cond) {
		Address::in_sockaddr boundAddr_u;
		socklen_t addrLen = sizeof(Address::in_sockaddr);
		int newFd = accept(fd, &boundAddr_u.s, &addrLen);
		if(newFd < 0)
		{
			::perror("accept");
			return;
		}

		Address boundAddr(&boundAddr_u.s);
		printf("accept from %s\n", boundAddr.toPresentation().c_str());
		Client::newClient(newFd, boundAddr);
	});

	rl.run();

	return 0;
}
