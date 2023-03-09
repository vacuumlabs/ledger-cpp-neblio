#pragma once

#include "bytes.h"
#include "transport.h"

namespace ledger
{
	struct TxInput
	{
		bytes prevout;
		bytes script;
		uint32_t sequence;
	};

	struct TxOutput
	{
		uint64_t amount;
		bytes script;
	};

	struct ScriptWitness
	{
		std::vector<bytes> stack;
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
		bytes serialized;
		uint16_t random;
		bytes prevTxId;
		uint32_t outIndex;
		uint64_t amount;
		bytes hmac;
	};

	struct Utxo
	{
		bytes raw;
		uint32_t index;
		Tx tx;
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

		std::tuple<bytes, std::string, bytes> GetPublicKey(const std::string &path, bool confirm);
		std::tuple<Error, bytes> sign(uint32_t account, const bytes &msg);

		void close();

		// private:
		std::unique_ptr<Transport> transport_;

		std::tuple<Error, bytes> ProcessScriptBlocks(const bytes &script, uint32_t sequence);
		std::tuple<Error, bytes> GetTrustedInputRaw(bool firstRound, uint32_t indexLookup, const bytes &data);
		std::tuple<Error, bytes> _NOT_WORKING_GetTrustedInput_NOT_WORKING_(uint32_t indexLookup, const bytes &transaction);
		std::tuple<Error, bytes> GetTrustedInput(uint32_t indexLookup, const bytes &serializedTransaction);
		void UntrustedHashTxInputFinalize(Tx tx, const std::string &changePath);
		void UntrustedHashTxInputStart(Tx tx, const std::vector<TrustedInput> &trustedInputs, int inputIndex, bytes script, bool isNewTransaction);
		std::vector<std::tuple<int, bytes>> SignTransaction(const std::string &address, uint64_t amount, uint64_t fees, const std::string &changePath, const std::vector<std::string> &signPaths, const std::vector<std::tuple<bytes, uint32_t>> &rawUtxos, uint32_t locktime);
		std::tuple<Error, bytes> GetTrustedInput(uint32_t indexLookup, Tx tx);
		TrustedInput DeserializeTrustedInput(const bytes &serializedTrustedInput);

		std::tuple<uint32_t, uint8_t> GetVarint(const bytes &data, uint32_t offset);
		bytes CreateVarint(uint32_t value);
		Tx SplitTransaction(const bytes &transaction);
	};
}
