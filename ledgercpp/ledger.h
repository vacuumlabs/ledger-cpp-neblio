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

	struct ScriptWitness
	{
		std::vector<std::vector<uint8_t>> stack;
	};

	struct TxInWitness
	{
		ScriptWitness scriptWitness;
	};

	struct TxWitness
	{
		std::vector<TxInWitness> txInWitnesses;
	};

	struct Tx
	{
		uint32_t version;
		uint32_t time;
		std::vector<TxInput> inputs;
		std::vector<TxOutput> outputs;
		uint32_t locktime;
		TxWitness witness;
	};

	struct TrustedInput
	{
		std::vector<uint8_t> serialized;
		uint16_t random;
		std::vector<uint8_t> prevTxId;
		uint32_t outIndex;
		uint64_t amount;
		std::vector<uint8_t> hmac;
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
			INS_UNTRUSTED_HASH_TRANSACTION_INPUT_START = 0x44,
			INS_UNTRUSTED_HASH_TRANSACTION_INPUT_FINALIZE = 0x4A,
			INS_UNTRUSTED_HASH_SIGN = 0x48
		};

	public:
		Ledger();
		~Ledger();

		Error open();

		std::tuple<std::vector<uint8_t>, std::string, std::vector<uint8_t>> GetPublicKey(std::string path, bool confirm);
		std::tuple<Error, std::vector<uint8_t>> sign(uint32_t account, const std::vector<uint8_t> &msg);

		void close();

		// private:
		std::unique_ptr<Transport> transport_;

		std::tuple<Error, std::vector<uint8_t>> ProcessScriptBlocks(const std::vector<uint8_t> &script, uint32_t sequence);
		std::tuple<Error, std::vector<uint8_t>> GetTrustedInputRaw(bool firstRound, uint32_t indexLookup, const std::vector<uint8_t> &data);
		std::tuple<Error, std::vector<uint8_t>> _NOT_WORKING_GetTrustedInput_NOT_WORKING_(uint32_t indexLookup, const std::vector<uint8_t> &transaction);
		std::tuple<Error, std::vector<uint8_t>> GetTrustedInput(uint32_t indexLookup, const std::vector<uint8_t> &serializedTransaction);
		void UntrustedHashTxInputFinalize(Tx tx, std::string changePath);
		void UntrustedHashTxInputStart(Tx tx, std::vector<TrustedInput> trustedInputs, int inputIndex, std::vector<uint8_t> script, bool isNewTransaction);
		std::vector<std::tuple<int, std::vector<uint8_t>>> SignTransaction(std::string address, uint64_t amount, uint64_t fees, std::string changePath, std::vector<std::string> signPaths, std::vector<std::tuple<std::vector<uint8_t>, uint32_t>> rawUtxos, uint32_t locktime);
		std::tuple<Error, std::vector<uint8_t>> GetTrustedInput(uint32_t indexLookup, Tx tx);
		TrustedInput DeserializeTrustedInput(const std::vector<uint8_t> &serializedTrustedInput);

		std::tuple<uint32_t, uint8_t> GetVarint(const std::vector<uint8_t> &data, uint32_t offset);
		std::vector<uint8_t> CreateVarint(uint32_t value);
		Tx SplitTransaction(std::vector<uint8_t> transaction);
	};
}
