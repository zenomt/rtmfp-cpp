# CXXFLAGS = -Wall -pedantic -std=c++11 -g -I../include
# CXXFLAGS = -Os -Wall -pedantic -std=c++11 -fno-exceptions -I../include
CXXFLAGS = -Os -Wall -pedantic -std=c++11 -I../include

LIBRARY = ../librtmfp.a

default: all
all: tests server testclient t2
tests: tis testperform testchecksums testlist testvlu testaddress testplatform

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

testclient.o: testclient.cpp addrlist.hpp
testclient: testclient.o $(LIBRARY)
	$(CXX) -o $@ $+

server: server.o $(LIBRARY)
	$(CXX) -o $@ $+

t2.o: t2.cpp addrlist.hpp
t2: t2.o $(LIBRARY)
	$(CXX) -o $@ $+


ci: tests
	./tis
	./testperform
	./testchecksums
	./testlist
	./testvlu
	./testaddress

clean:
	rm -f *.o tis testperform testchecksums testlist testvlu testaddress testplatform testclient server t2
