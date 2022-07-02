cmake_minimum_required(VERSION 3.0)

project(rtmfp-cpp)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)

add_library(rtmfp STATIC
	src/Address.cpp
	src/AMF.cpp
	src/Checksums.cpp
	src/EPollRunLoop.cpp
	src/FlashCryptoAdapter.cpp
	src/FlashCryptoAdapter_OpenSSL.cpp
	src/Flow.cpp
	src/FlowSyncManager.cpp
	src/Hex.cpp
	src/IndexSet.cpp
	src/Interface.cpp
	src/Media.cpp
	src/Object.cpp
	src/PacketAssembler.cpp
	src/Performer.cpp
	src/PerformerPosixPlatformAdapter.cpp
	src/PlainCryptoAdapter.cpp
	src/PosixPlatformAdapter.cpp
	src/RecvFlow.cpp
	src/RedirectorClient.cpp
	src/ReorderBuffer.cpp
	src/RTMFP.cpp
	src/RunLoop.cpp
	src/SelectRunLoop.cpp
	src/SendFlow.cpp
	src/Session.cpp
	src/TCMessage.cpp
	src/Timer.cpp
	src/VLU.cpp
	src/WriteReceipt.cpp
)

target_compile_options(rtmfp PRIVATE -Os)
target_include_directories(rtmfp INTERFACE
	$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
	$<INSTALL_INTERFACE:include>)
target_link_libraries(rtmfp PRIVATE crypto)

install (TARGETS rtmfp
	EXPORT rtmfp-targets
	LIBRARY DESTINATION lib
	INCLUDES DESTINATION include
)
install (DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/include/" DESTINATION include)
install (EXPORT rtmfp-targets
	FILE rtmfp-targets.cmake
	NAMESPACE rtmfp::
	DESTINATION lib/cmake/rtmfp
)
