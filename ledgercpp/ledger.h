#pragma once

#include "transport.h"

namespace ledger
{
	struct TxInput
	{
		std::vector<uint8_t> prevout;
		std::vector<uint8_t> script;
		uint32_t sequence;
	};

	struct TxOutput
	{
		uint64_t amount;
		std::vector<uint8_t> script;
	};

	struct Tx
	{
		uint32_t version;
		uint32_t time;
		std::vector<TxInput> inputs;
		std::vector<TxOutput> outputs;
		uint32_t locktime;
	};

	class Ledger
	{
		enum APDU : uint8_t
		{
			CLA = 0xe0,
			INS_GET_APP_CONFIGURATION = 0x01,
			INS_GET_PUBLIC_KEY = 0x40,
			INS_SIGN = 0x03,
			INS_GET_TRUSTED_INPUT = 0x42,
		};

	public:
		Ledger();
		~Ledger();

		Error open();

		std::tuple<Error, std::vector<uint8_t>> get_public_key(uint32_t account, bool confirm = false);
		std::tuple<Error, std::vector<uint8_t>> sign(uint32_t account, const std::vector<uint8_t> &msg);
		void SignTransaction();

		void close();

		// private:
		std::unique_ptr<Transport> transport_;

		std::tuple<Error, std::vector<uint8_t>> ProcessScriptBlocks(const std::vector<uint8_t> &script, uint32_t sequence);
		std::tuple<Error, std::vector<uint8_t>> GetTrustedInputRaw(bool firstRound, uint32_t indexLookup, const std::vector<uint8_t> &data);
		std::tuple<Error, std::vector<uint8_t>> GetTrustedInput(uint32_t indexLookup, const std::vector<uint8_t> &transaction);

		std::tuple<uint32_t, uint8_t> GetVarint(const std::vector<uint8_t> &data, uint32_t offset);
		std::vector<uint8_t> CreateVarint(uint32_t value);
		Tx SplitTransaction(std::vector<uint8_t> transaction);
	};
}
