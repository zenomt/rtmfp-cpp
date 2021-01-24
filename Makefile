AR = ar
RANLIB = ranlib

# CXXFLAGS = -g -Wall -pedantic -std=c++11
# CXXFLAGS = -Os -Wall -pedantic -std=c++11 -fno-exceptions
CXXFLAGS = -Os -Wall -pedantic -std=c++11

UTILS = src/Checksums.o src/Hex.o src/IndexSet.o src/Object.o src/Timer.o

PROTOCOL = src/Address.o src/Flow.o src/Interface.o src/PacketAssembler.o \
	src/RecvFlow.o src/RTMFP.o src/SendFlow.o src/Session.o src/VLU.o src/WriteReceipt.o

SAMPLES = src/Performer.o src/PerformerPosixPlatformAdapter.o src/PlainCryptoAdapter.o \
	src/PosixPlatformAdapter.o src/RunLoop.o src/SelectRunLoop.o

LIBOBJS = $(UTILS) $(PROTOCOL) $(SAMPLES)

default: librtmfp.a

all: default tests

librtmfp.a: $(LIBOBJS)
	rm -f $@
	$(AR) -r $@ $+
	$(RANLIB) $@

tests ci: default
	@cd test && $(MAKE) $@

clean:
	rm -f $(LIBOBJS) librtmfp.a
	@cd test && $(MAKE) clean
