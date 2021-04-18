#pragma once

// Copyright © 2021 Michael Thornburgh
// SPDX-License-Identifier: MIT

namespace com { namespace zenomt { namespace rtmfp {

struct SendFlow::SendFrag : public Object {
	SendFlow *m_owner; // weak ref
	uintmax_t m_sequence_number;
	uint8_t   m_fra;
	bool      m_sent_abandoned;
	size_t    m_nak_count;
	bool      m_in_flight;
	bool      m_ever_sent;
	size_t    m_transmit_size;
	uintmax_t m_tsn;
	long      m_session_outstanding_name;
	Bytes     m_data;
	std::shared_ptr<IssuerWriteReceipt> m_receipt;

	SendFrag(SendFlow *owner, const uint8_t *data, size_t len, uintmax_t sequenceNumber, uint8_t fra, const std::shared_ptr<IssuerWriteReceipt> &receipt);

	static size_t size_queue(const std::shared_ptr<SendFrag>& value);
	static size_t size_outstanding(const std::shared_ptr<SendFrag>& value);
};

} } } // namespace com::zenomt::rtmfp
