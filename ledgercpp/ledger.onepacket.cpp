#include "ledger.h"
#include "error.h"
#include "utils.h"

#include <algorithm>

namespace ledger
{
	Ledger::Ledger() { this->transport_ = std::unique_ptr<Transport>(new Transport(Transport::TransportType::HID)); }

	Ledger::~Ledger() { transport_->close(); }

	Error Ledger::open() { return transport_->open(); }

	std::tuple<ledger::Error, std::vector<uint8_t>> Ledger::get_public_key(uint32_t account, bool confirm)
	{
		auto payload = std::vector<uint8_t>();
		// path length
		payload.push_back(5);
		// m/44'/146'/0'/0/0 derivation path
		utils::AppendVector(payload, utils::IntToBytes(utils::Harden(44), 4));
		utils::AppendVector(payload, utils::IntToBytes(utils::Harden(146), 4));
		utils::AppendVector(payload, utils::IntToBytes(utils::Harden(account), 4));
		utils::AppendVector(payload, utils::IntToBytes(0, 4));
		utils::AppendVector(payload, utils::IntToBytes(0, 4));

		auto result = transport_->exchange(APDU::CLA, APDU::INS_GET_PUBLIC_KEY, confirm, 0x00, payload);
		auto err = std::get<0>(result);
		auto buffer = std::get<1>(result);
		if (err != Error::SUCCESS)
			return {err, {}};
		return {err, std::vector<uint8_t>(buffer.begin() + 1, buffer.end())};
	}

	std::tuple<Error, std::vector<uint8_t>> Ledger::sign(uint32_t account, const std::vector<uint8_t> &msg)
	{
		auto payload = utils::IntToBytes(account, 4);
		payload.insert(payload.end(), msg.begin(), msg.end());
		auto result = transport_->exchange(APDU::CLA, APDU::INS_SIGN, 0x00, 0x00, payload);
		auto err = std::get<0>(result);
		auto buffer = std::get<1>(result);
		if (err != Error::SUCCESS)
			return {err, {}};
		return {err, std::vector<uint8_t>(buffer.begin() + 1, buffer.end())};
	}

	std::tuple<uint32_t, uint8_t> Ledger::GetVarint(const std::vector<uint8_t> &data, uint32_t offset)
	{
		if (data[offset] < 0xfd)
		{
			return {data[offset], 1};
		}

		if (data[offset] == 0xfd)
		{
			return {(data[offset + 2] << 8) + data[offset + 1], 3};
		}

		if (data[offset] == 0xfe)
		{
			return {
					(data[offset + 4] << 24) +
							(data[offset + 3] << 16) +
							(data[offset + 2] << 8) +
							data[offset + 1],
					5,
			};
		}
	}

	std::vector<uint8_t> Ledger::CreateVarint(uint32_t value)
	{
		std::vector<uint8_t> data;
		if (value < 0xfd)
		{
			data.push_back(value);
		}
		else if (value <= 0xffff)
		{
			data.push_back(0xfd);
			data.push_back(value & 0xff);
			data.push_back((value >> 8) & 0xff);
		}
		else
		{
			data.push_back(0xfd);
			data.push_back(value & 0xff);
			data.push_back((value >> 8) & 0xff);
			data.push_back((value >> 16) & 0xff);
			data.push_back((value >> 24) & 0xff);
		}

		return data;
	}

	Tx Ledger::SplitTransaction(std::vector<uint8_t> transaction)
	{
		Tx tx;
		tx.inputs = std::vector<TxInput>();
		tx.outputs = std::vector<TxOutput>();

		auto offset = 0;

		auto wtf = utils::Splice(transaction, offset, 1);
		tx.version = utils::BytesToInt(wtf);
		offset += 4;

		tx.time = utils::BytesToInt(utils::Splice(transaction, offset, 4));
		offset += 4;

		auto varint = GetVarint(transaction, offset);
		auto inputsCount = std::get<0>(varint);
		offset += std::get<1>(varint);

		for (auto i = 0; i < inputsCount; i++)
		{
			TxInput input;

			input.prevout = utils::Splice(transaction, offset, 36);
			offset += 36;

			varint = GetVarint(transaction, offset);
			offset += std::get<1>(varint);
			input.script = utils::Splice(transaction, offset, std::get<0>(varint));

			offset += std::get<0>(varint);
			input.sequence = utils::BytesToInt(utils::Splice(transaction, offset, 4));
			offset += 4;

			tx.inputs.push_back(input);
		}

		varint = GetVarint(transaction, offset);
		auto numberOutputs = std::get<0>(varint);
		offset += std::get<1>(varint);

		for (auto i = 0; i < numberOutputs; i++)
		{
			TxOutput output;

			output.amount = utils::BytesToUint64(utils::Splice(transaction, offset, 8));
			offset += 8;

			varint = GetVarint(transaction, offset);
			offset += std::get<1>(varint);

			output.script = utils::Splice(transaction, offset, std::get<0>(varint));
			offset += std::get<0>(varint);

			tx.outputs.push_back(output);
		}

		tx.locktime = utils::BytesToInt(utils::Splice(transaction, offset, 4));

		return tx;
	}

	std::tuple<Error, std::vector<uint8_t>> Ledger::GetTrustedInputRaw(bool firstRound, uint32_t indexLookup, const std::vector<uint8_t> &transactionData)
	{
		std::vector<uint8_t> data;
		if (firstRound)
		{
			std::vector<uint8_t> prefix;
			utils::AppendUint32(prefix, indexLookup);
			std::reverse(prefix.begin(), prefix.end());
			utils::AppendVector(data, prefix);
		}

		utils::AppendVector(data, transactionData);

		auto result = transport_->exchange(APDU::CLA, APDU::INS_GET_TRUSTED_INPUT, firstRound ? 0x00 : 0x80, 0x00, data);
		auto err = std::get<0>(result);
		auto buffer = std::get<1>(result);
		if (err != Error::SUCCESS)
			return {err, {}};

		return {err, std::vector<uint8_t>(buffer.begin(), buffer.end())};
	}

	std::tuple<Error, std::vector<uint8_t>> Ledger::ProcessScriptBlocks(const std::vector<uint8_t> &script, uint32_t sequence)
	{
		auto MAX_SCRIPT_BLOCK = 255;

		std::vector<std::vector<uint8_t>> scriptBlocks;
		auto offset = 0;

		while (offset != script.size())
		{
			auto blockSize = script.size() - offset > MAX_SCRIPT_BLOCK ? MAX_SCRIPT_BLOCK : script.size() - offset;

			if ((offset + blockSize) != script.size())
			{
				scriptBlocks.push_back(utils::Splice(script, offset, blockSize));
			}
			else
			{
				auto block = utils::Splice(script, offset, blockSize);
				// utils::AppendUint32(block, sequence);

				scriptBlocks.push_back(block);
			}

			offset += blockSize;
		}

		std::vector<uint8_t> finalResults;
		for (auto &scriptBlock : scriptBlocks)
		{
			auto result = GetTrustedInputRaw(false, 0, scriptBlock);
			if (std::get<0>(result) != Error::SUCCESS)
			{
				return {std::get<0>(result), {}};
			}
			finalResults = std::get<1>(result);
		}

		return {Error::SUCCESS, finalResults};
	}

	std::tuple<Error, std::vector<uint8_t>> Ledger::GetTrustedInput(uint32_t indexLookup, const std::vector<uint8_t> &transaction)
	{
		auto tx = SplitTransaction(transaction);

		std::vector<uint8_t> data;
		utils::AppendUint32(data, indexLookup);
		std::reverse(data.begin(), data.end());
		utils::AppendUint32(data, tx.version);
		utils::AppendUint32(data, tx.time);
		utils::AppendVector(data, CreateVarint(tx.inputs.size()));

		// auto result = GetTrustedInputRaw(true, indexLookup, data);
		// if (std::get<0>(result) != Error::SUCCESS)
		// {
		// 	return {std::get<0>(result), {}};
		// }

		for (auto input : tx.inputs)
		{
			// std::vector<uint8_t> data;
			utils::AppendVector(data, input.prevout);
			utils::AppendVector(data, CreateVarint(input.script.size()));

			// result = GetTrustedInputRaw(false, 0, data);
			// if (std::get<0>(result) != Error::SUCCESS)
			// {
			// 	return {std::get<0>(result), {}};
			// }

			// auto error = ProcessScriptBlocks(input.script, input.sequence);
			// if (error != Error::SUCCESS)
			// {
			// 	return {error, {}};
			// }
			utils::AppendVector(data, input.script);
			utils::AppendVector(data, utils::IntToBytes(input.sequence, 4));
		}

		// result = GetTrustedInputRaw(false, 0, CreateVarint(tx.outputs.size()));
		// if (std::get<0>(result) != Error::SUCCESS)
		// {
		// 	return {std::get<0>(result), {}};
		// }

		utils::AppendVector(data, CreateVarint(tx.outputs.size()));

		for (auto output : tx.outputs)
		{
			// std::vector<uint8_t> data;
			utils::AppendUint64(data, output.amount);
			utils::AppendVector(data, CreateVarint(output.script.size()));
			utils::AppendVector(data, output.script);

			// result = GetTrustedInputRaw(false, 0, data);
			// if (std::get<0>(result) != Error::SUCCESS)
			// {
			// 	return {std::get<0>(result), {}};
			// }
		}

		auto wtf = utils::IntToBytes(tx.locktime, 4);
		std::reverse(wtf.begin(), wtf.end());
		// return GetTrustedInputRaw(false, 0, wtf);
		utils::AppendVector(data, wtf);

		auto result = ProcessScriptBlocks(data, 0);
		if (std::get<0>(result) != Error::SUCCESS)
		{
			return {std::get<0>(result), {}};
		}

		return result;
	}

	void Ledger::SignTransaction()
	{
	}

	void Ledger::close() { return transport_->close(); }
} // namespace ledger
