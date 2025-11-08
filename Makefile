AR = ar
RANLIB = ranlib

OPENSSL_DIR = /usr/local/openssl
OPENSSL_INCLUDEDIR = -I$(OPENSSL_DIR)/include
OPENSSL_LIBDIR = -L$(OPENSSL_DIR)/lib

# CXXFLAGS = -g -Wall -pedantic -std=c++11
# CXXFLAGS = -Os -Wall -pedantic -std=c++11 -fno-exceptions
CXXFLAGS = -Os -Wall -pedantic -std=c++11

UTILS = src/Checksums.o src/Hex.o src/IndexSet.o src/Object.o src/RateTracker.o src/Timer.o

PROTOCOL = src/Address.o src/Flow.o src/Interface.o src/PacketAssembler.o \
	src/RecvFlow.o src/RTMFP.o src/SendFlow.o src/Session.o src/VLU.o src/WriteReceipt.o

SAMPLES = src/AMF.o src/EPollRunLoop.o src/FlashCryptoAdapter.o src/FlowSyncManager.o src/Media.o src/Performer.o \
	src/PerformerPosixPlatformAdapter.o src/PlainCryptoAdapter.o src/PosixPlatformAdapter.o src/RedirectorClient.o \
	src/ReorderBuffer.o src/RunLoop.o src/SelectRunLoop.o src/TCConnection.o src/TCMessage.o src/URIParse.o

ifndef WITHOUT_OPENSSL
SAMPLES_OPENSSL = src/FlashCryptoAdapter_OpenSSL.o
$(SAMPLES_OPENSSL): CPPFLAGS += $(OPENSSL_INCLUDEDIR)
endif

LIBOBJS = $(UTILS) $(PROTOCOL) $(SAMPLES) $(SAMPLES_OPENSSL)

default: librtmfp.a

all: default test-all

librtmfp.a: $(LIBOBJS)
	rm -f $@
	$(AR) -r $@ $+
	$(RANLIB) $@

tests ci test-all examples: default
	@cd test && $(MAKE) $@

clean:
	rm -f $(LIBOBJS) librtmfp.a
	@cd test && $(MAKE) clean
