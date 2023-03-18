cmake_minimum_required(VERSION 3.4)

project(rtmfp-cpp VERSION 1.4.1)

find_package(OpenSSL)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)

add_library(rtmfp STATIC
	src/Address.cpp
	src/AMF.cpp
	src/Checksums.cpp
	src/FlashCryptoAdapter.cpp
	src/Flow.cpp
	src/FlowSyncManager.cpp
	src/Hex.cpp
	src/IndexSet.cpp
	src/Interface.cpp
	src/Media.cpp
	src/Object.cpp
	src/PacketAssembler.cpp
	src/PlainCryptoAdapter.cpp
	src/RateTracker.cpp
	src/RecvFlow.cpp
	src/RedirectorClient.cpp
	src/ReorderBuffer.cpp
	src/RTMFP.cpp
	src/RunLoop.cpp
	src/SendFlow.cpp
	src/Session.cpp
	src/TCConnection.cpp
	src/TCMessage.cpp
	src/Timer.cpp
	src/URIParse.cpp
	src/VLU.cpp
	src/WriteReceipt.cpp
)

if(OpenSSL_FOUND)
	target_sources(rtmfp PRIVATE src/FlashCryptoAdapter_OpenSSL.cpp)
endif()

if(NOT WIN32)
	target_sources(rtmfp PRIVATE
		src/EPollRunLoop.cpp
		src/Performer.cpp
		src/PerformerPosixPlatformAdapter.cpp
		src/PosixPlatformAdapter.cpp
		src/SelectRunLoop.cpp
	)
endif()

target_compile_options(rtmfp PRIVATE -Os)

if(WIN32)
	target_compile_options(rtmfp PRIVATE /permissive-)
	target_compile_definitions(rtmfp PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
endif()

target_include_directories(rtmfp INTERFACE
	$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
	$<INSTALL_INTERFACE:include>)

if(OpenSSL_FOUND)
	target_link_libraries(rtmfp PRIVATE OpenSSL::Crypto)
endif()

if(WIN32)
	target_link_libraries(rtmfp PRIVATE ws2_32)
endif()

export (TARGETS rtmfp NAMESPACE rtmfp:: FILE rtmfp-targets.cmake)

install (TARGETS rtmfp
	EXPORT rtmfp-targets
	LIBRARY DESTINATION lib
	INCLUDES DESTINATION include
)
install (DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/include/" DESTINATION include)
install (EXPORT rtmfp-targets
	NAMESPACE rtmfp::
	DESTINATION lib/cmake/rtmfp
)

include (CMakePackageConfigHelpers)
write_basic_package_version_file (rtmfp-config-version.cmake COMPATIBILITY SameMajorVersion)
configure_package_config_file (src/config.cmake.in rtmfp-config.cmake
	INSTALL_DESTINATION lib/cmake/rtmfp
)
install (FILES
	"${CMAKE_CURRENT_BINARY_DIR}/rtmfp-config.cmake"
	"${CMAKE_CURRENT_BINARY_DIR}/rtmfp-config-version.cmake"
	DESTINATION lib/cmake/rtmfp
)
