// Copyright © 2021 Michael Thornburgh
// SPDX-License-Identifier: MIT

#include "../include/rtmfp/TCMessage.hpp"
#include "../include/rtmfp/VLU.hpp"

namespace com { namespace zenomt { namespace rtmfp {

size_t TCMetadata::parse(const uint8_t *metadata, const uint8_t *limit, uint32_t *outStreamID, ReceiveOrder *outRxOrder)
{
	if( (limit - metadata < 4) // 'T' 'C' flags vlu
	 or (metadata[0] != 'T')
	 or (metadata[1] != 'C')
	 or (not (metadata[2] & TCMETADATA_FLAG_SID))
	)
		return 0;

	uintmax_t streamID;
	size_t rv = VLU::parse(metadata + 3, limit, &streamID);
	if(0 == rv)
		return 0;

	if(streamID > UINT32_MAX)
		return 0; // impossible RTMP stream ID

	if(outStreamID)
		*outStreamID = streamID;

	if(outRxOrder)
		*outRxOrder = ((metadata[2] & TCMETADATA_FLAG_RXI_MASK) == TCMETADATA_RXI_NETWORK) ? RO_NETWORK : RO_SEQUENCE;

	return 3 // 'T', 'C', flags
	     + rv; // length of streamID
}

size_t TCMetadata::parse(const Bytes &metadata, uint32_t *outStreamID, ReceiveOrder *outRxOrder)
{
	return parse(metadata.data(), metadata.data() + metadata.size(), outStreamID, outRxOrder);
}

Bytes TCMetadata::encode(uint32_t streamID, ReceiveOrder rxOrder)
{
	Bytes rv;

	rv.push_back('T');
	rv.push_back('C');
	rv.push_back(TCMETADATA_FLAG_SID | ((RO_NETWORK == rxOrder) ? TCMETADATA_RXI_NETWORK : TCMETADATA_RXI_SEQUENCE));
	VLU::append(streamID, rv);

	return rv;
}


} } } // namespace com::zenomt::rtmfp
