OPENSSL_LIBDIR = -L/usr/local/openssl/lib

# CXXFLAGS = -Wall -pedantic -std=c++11 -g -I../include
# CXXFLAGS = -Os -Wall -pedantic -std=c++11 -fno-exceptions -I../include
CXXFLAGS = -Os -Wall -pedantic -std=c++11 -I../include

LIBRARY = ../librtmfp.a

ifndef WITHOUT_OPENSSL
FC_OPENSSL_SAMPLES = fcclient fcechoserver
endif

default: all
all: tests server testclient t2 $(FC_OPENSSL_SAMPLES)
tests: tis testperform testchecksums testlist testvlu testaddress testplatform testhex

$(LIBRARY):
	@cd .. && $(MAKE)

tis: tis.o $(LIBRARY)
	$(CXX) -o $@ $+

testperform: testperform.o $(LIBRARY)
	$(CXX) -o $@ $+ -lpthread

testchecksums: testchecksums.o $(LIBRARY)
	$(CXX) -o $@ $+

testlist: testlist.o $(LIBRARY)
	$(CXX) -o $@ $+

testvlu: testvlu.o $(LIBRARY)
	$(CXX) -o $@ $+

testaddress: testaddress.o $(LIBRARY)
	$(CXX) -o $@ $+

testplatform: testplatform.o $(LIBRARY)
	$(CXX) -o $@ $+ -lpthread

testhex: testhex.o $(LIBRARY)
	$(CXX) -o $@ $+

testclient.o: testclient.cpp addrlist.hpp
testclient: testclient.o $(LIBRARY)
	$(CXX) -o $@ $+

server: server.o $(LIBRARY)
	$(CXX) -o $@ $+

t2.o: t2.cpp addrlist.hpp
t2: t2.o $(LIBRARY)
	$(CXX) -o $@ $+

fcclient: fcclient.o $(LIBRARY)
	$(CXX) -o $@ $+ $(OPENSSL_LIBDIR) -lcrypto

fcechoserver: fcechoserver.o $(LIBRARY)
	$(CXX) -o $@ $+ $(OPENSSL_LIBDIR) -lcrypto -lpthread

ci: tests
	./tis
	./testperform
	./testchecksums
	./testlist
	./testvlu
	./testaddress
	./testhex

clean:
	rm -f *.o tis testperform testchecksums testlist testvlu testaddress testplatform testclient server t2 testhex fcclient fcechoserver
