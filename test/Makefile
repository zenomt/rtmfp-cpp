OPENSSL_INCLUDEDIR = -I/usr/local/openssl/include
OPENSSL_LIBDIR = -L/usr/local/openssl/lib

# CXXFLAGS = -Wall -pedantic -std=c++11 -g -I../include
# CXXFLAGS = -Os -Wall -pedantic -std=c++11 -fno-exceptions -I../include
CXXFLAGS = -Os -Wall -pedantic -std=c++11 -I../include

LIBRARY = ../librtmfp.a
RTMP = RTMP.o PosixStreamPlatformAdapter.o
RTWS = RTWebSocket.o SimpleWebSocketMessagePlatformAdapter.o SimpleWebSocket.o

ifndef WITHOUT_OPENSSL
FC_OPENSSL_EXAMPLES = fcclient echoserver redirector rtclient static-redirector tcrelay tcserver
RTWS += SimpleWebSocket_OpenSSL.o
RTWS_EXAMPLES = testwebsock
endif

TESTS = tis testperform testchecksums testlist testvlu testaddress testhex testamf testtcmsg testflowsync testreorder testmedia
EXAMPLES = server testclient t2 rtmpserver $(FC_OPENSSL_EXAMPLES) $(RTWS_EXAMPLES)

default: all
test-all: all
all: tests examples
tests: $(TESTS)
examples: $(EXAMPLES)

$(LIBRARY):
	@cd .. && $(MAKE)

tis: tis.o $(LIBRARY)
	rm -f $@
	$(CXX) -o $@ $+

testperform: testperform.o $(LIBRARY)
	rm -f $@
	$(CXX) -o $@ $+ -lpthread

testchecksums: testchecksums.o $(LIBRARY)
	rm -f $@
	$(CXX) -o $@ $+

testlist: testlist.o $(LIBRARY)
	rm -f $@
	$(CXX) -o $@ $+

testvlu: testvlu.o $(LIBRARY)
	rm -f $@
	$(CXX) -o $@ $+

testaddress: testaddress.o $(LIBRARY)
	rm -f $@
	$(CXX) -o $@ $+

testtcmsg: testtcmsg.o $(LIBRARY)
	rm -f $@
	$(CXX) -o $@ $+

testamf: testamf.o $(LIBRARY)
	rm -f $@
	$(CXX) -o $@ $+

testhex: testhex.o $(LIBRARY)
	rm -f $@
	$(CXX) -o $@ $+

testflowsync: testflowsync.o $(LIBRARY)
	rm -f $@
	$(CXX) -o $@ $+

testreorder: testreorder.o $(LIBRARY)
	rm -f $@
	$(CXX) -o $@ $+

testmedia: testmedia.o $(LIBRARY)
	rm -f $@
	$(CXX) -o $@ $+

testclient.o: addrlist.hpp
testclient: testclient.o $(LIBRARY)
	rm -f $@
	$(CXX) -o $@ $+

server: server.o $(LIBRARY)
	rm -f $@
	$(CXX) -o $@ $+

t2.o: addrlist.hpp
t2: t2.o $(LIBRARY)
	rm -f $@
	$(CXX) -o $@ $+

fcclient.o: addrlist.hpp
fcclient: fcclient.o $(LIBRARY)
	rm -f $@
	$(CXX) -o $@ $+ $(OPENSSL_LIBDIR) -lcrypto

echoserver.o: redirectorspec.hpp
echoserver: echoserver.o $(LIBRARY)
	rm -f $@
	$(CXX) -o $@ $+ $(OPENSSL_LIBDIR) -lcrypto -lpthread

rtclient.o: addrlist.hpp
rtclient: rtclient.o $(LIBRARY)
	rm -f $@
	$(CXX) -o $@ $+ $(OPENSSL_LIBDIR) -lcrypto

static-redirector: static-redirector.o $(LIBRARY)
	rm -f $@
	$(CXX) -o $@ $+ $(OPENSSL_LIBDIR) -lcrypto -lpthread

rtmpserver: rtmpserver.o $(RTMP) $(LIBRARY)
	rm -f $@
	$(CXX) -o $@ $+

tcrelay: tcrelay.o $(RTMP) $(LIBRARY)
	rm -f $@
	$(CXX) -o $@ $+ $(OPENSSL_LIBDIR) -lcrypto -lpthread

tcserver: tcserver.o $(RTMP) $(LIBRARY)
	rm -f $@
	$(CXX) -o $@ $+ $(OPENSSL_LIBDIR) -lcrypto -lpthread

redirector: redirector.o $(LIBRARY)
	rm -f $@
	$(CXX) -o $@ $+ $(OPENSSL_LIBDIR) -lcrypto -lpthread

testwebsock: testwebsock.o PosixStreamPlatformAdapter.o $(RTWS) $(LIBRARY)
	rm -f $@
	$(CXX) -o $@ $+ $(OPENSSL_LIBDIR) -lcrypto -lpthread

SimpleWebSocket_OpenSSL.o: CPPFLAGS += $(OPENSSL_INCLUDEDIR)

# make ci: build all, but only run the automated tests.
ci: all
	./tis
	./testperform
	./testchecksums
	./testlist
	./testvlu
	./testaddress
	./testhex
	./testamf
	./testtcmsg
	./testflowsync
	./testreorder
	./testmedia

clean:
	rm -f *.o $(TESTS) $(EXAMPLES)
