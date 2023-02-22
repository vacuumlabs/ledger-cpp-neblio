#include "error.h"
#include "ledger.h"
#include "utils.h"

namespace ledger
{
	Ledger::Ledger() : transport_(std::make_unique<Transport>(Transport::TransportType::HID))
	{
	}

	Ledger::~Ledger()
	{
		transport_->close();
	}

	Error Ledger::open()
	{
		return transport_->open();
	}

	std::tuple<ledger::Error, std::vector<uint8_t>> Ledger::get_public_key(uint32_t account, bool confirm)
	{
		auto payload = std::vector<uint8_t>();
		payload.push_back(3);

		// m/44'/146'/0' derivation path
		payload.push_back(0x80);
		payload.push_back(0x00);
		payload.push_back(0x00);
		payload.push_back(0x2C); // 44

		payload.push_back(0x80);
		payload.push_back(0x00);
		payload.push_back(0x00);
		payload.push_back(0x92); // 146

		payload.push_back(0x80);
		payload.push_back(0x00);
		payload.push_back(0x00);
		payload.push_back(0x00); // 0

		auto [err, buffer] = transport_->exchange(APDU::CLA, APDU::INS_GET_PUBLIC_KEY, confirm, 0x00, payload);
		if (err != Error::SUCCESS)
			return {err, {}};
		return {err, std::vector<uint8_t>(buffer.begin() + 1, buffer.end())};
	}

	std::tuple<Error, std::vector<uint8_t>> Ledger::sign(uint32_t account, const std::vector<uint8_t> &msg)
	{
		auto payload = utils::int_to_bytes(account, 4);
		payload.insert(payload.end(), msg.begin(), msg.end());
		auto [err, buffer] = transport_->exchange(APDU::CLA, APDU::INS_SIGN, 0x00, 0x00, payload);
		if (err != Error::SUCCESS)
			return {err, {}};
		return {err, std::vector<uint8_t>(buffer.begin() + 1, buffer.end())};
	}

	void Ledger::close()
	{
		return transport_->close();
	}
}
