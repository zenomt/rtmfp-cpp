#include <cassert>
#include "rtmfp/FlowSyncManager.hpp"

using namespace com::zenomt::rtmfp;
using namespace com::zenomt::rtmp;

int main(int argc, char **argv)
{
	std::shared_ptr<FlowSyncManager> manager = share_ref(new FlowSyncManager(), false);
	std::shared_ptr<RecvFlow> noflow;

	Bytes message = manager->makeSyncMessage(3);
	uint32_t syncID = 0;
	size_t count = 0;

	assert(manager->parse(message.data(), message.size(), syncID, count));
	assert(0 == syncID);
	assert(3 == count);
	message[0] = 0;
	assert(0 == manager->parse(message.data(), message.size(), syncID, count));

	message = manager->makeSyncMessage(2);
	assert(manager->parse(message.data(), message.size(), syncID, count));
	assert(1 == syncID);
	assert(2 == count);

	assert(not manager->sync(0, 2, noflow));
	assert(manager->sync(0, 2, noflow));

	assert(not manager->sync(8, 3, noflow));
	assert(not manager->sync(8, 3, noflow));
	assert(manager->sync(8, 3, noflow));

	assert(not manager->sync(10, 5, noflow));
	assert(manager->sync(10, 1, noflow));

	return 0;
}
