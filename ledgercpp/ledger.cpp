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
		utils::append_vector(payload, utils::int_to_bytes(utils::hardened(44), 4));
		utils::append_vector(payload, utils::int_to_bytes(utils::hardened(146), 4));
		utils::append_vector(payload, utils::int_to_bytes(utils::hardened(account), 4));
		utils::append_vector(payload, utils::int_to_bytes(0, 4));
		utils::append_vector(payload, utils::int_to_bytes(0, 4));

		auto result = transport_->exchange(APDU::CLA, APDU::INS_GET_PUBLIC_KEY, confirm, 0x00, payload);
		auto err = std::get<0>(result);
		auto buffer = std::get<1>(result);
		if (err != Error::SUCCESS)
			return {err, {}};
		return {err, std::vector<uint8_t>(buffer.begin() + 1, buffer.end())};
	}

	std::tuple<Error, std::vector<uint8_t>> Ledger::sign(uint32_t account, const std::vector<uint8_t> &msg)
	{
		auto payload = utils::int_to_bytes(account, 4);
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

		auto wtf = utils::splice(transaction, offset, 1);
		tx.version = utils::bytes_to_int(wtf);
		offset += 4;

		// tx.time = utils::bytes_to_int(utils::splice(transaction, offset, 4));
		// offset += 4;

		// tx.time = utils::bytes_to_int(utils::splice(transaction, offset, 1));
		// offset += 1;

		auto varint = GetVarint(transaction, offset);
		auto inputsCount = std::get<0>(varint);
		offset += std::get<1>(varint);

		for (auto i = 0; i < inputsCount; i++)
		{
			TxInput input;

			input.prevout = utils::splice(transaction, offset, 36);
			offset += 36;

			varint = GetVarint(transaction, offset);
			offset += std::get<1>(varint);
			input.script = utils::splice(transaction, offset, std::get<0>(varint));

			offset += std::get<0>(varint);
			input.sequence = utils::bytes_to_int(utils::splice(transaction, offset, 4));
			offset += 4;

			tx.inputs.push_back(input);
		}

		varint = GetVarint(transaction, offset);
		auto numberOutputs = std::get<0>(varint);
		offset += std::get<1>(varint);

		for (auto i = 0; i < numberOutputs; i++)
		{
			TxOutput output;

			output.amount = utils::bytes_to_uint64(utils::splice(transaction, offset, 8));
			offset += 8;

			varint = GetVarint(transaction, offset);
			offset += std::get<1>(varint);

			output.script = utils::splice(transaction, offset, std::get<0>(varint));
			offset += std::get<0>(varint);

			tx.outputs.push_back(output);
		}

		tx.locktime = utils::bytes_to_int(utils::splice(transaction, offset, 4));

		return tx;
	}

	std::tuple<Error, std::vector<uint8_t>> Ledger::GetTrustedInputRaw(bool firstRound, uint32_t indexLookup, const std::vector<uint8_t> &transactionData)
	{
		// std::vector<uint8_t> data;
		// if (firstRound)
		// {
		// }

		auto result = transport_->exchange(APDU::CLA, APDU::INS_GET_TRUSTED_INPUT, firstRound ? 0x00 : 0x80, 0x00, transactionData);
		auto err = std::get<0>(result);
		auto buffer = std::get<1>(result);
		if (err != Error::SUCCESS)
			return {err, {}};

		return {err, std::vector<uint8_t>(buffer.begin(), buffer.end())};
	}

	std::tuple<Error, std::vector<uint8_t>> Ledger::ProcessScriptBlocks(const std::vector<uint8_t> &script, uint32_t sequence)
	{
		auto MAX_SCRIPT_BLOCK = 50;

		std::vector<std::vector<uint8_t>> scriptBlocks;
		auto offset = 0;

		while (offset != script.size())
		{
			auto blockSize = script.size() - offset > MAX_SCRIPT_BLOCK ? MAX_SCRIPT_BLOCK : script.size() - offset;

			if ((offset + blockSize) != script.size())
			{
				scriptBlocks.push_back(utils::splice(script, offset, blockSize));
			}
			else
			{
				auto block = utils::splice(script, offset, blockSize);
				utils::append_uint32(block, sequence);

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

	std::tuple<Error, std::vector<uint8_t>> Ledger::GetTrustedInputSinglePacket(uint32_t indexLookup, const std::vector<uint8_t> &transaction)
	{
		auto tx = SplitTransaction(transaction);

		std::vector<uint8_t> data;
		utils::append_uint32(data, indexLookup);
		utils::append_uint32(data, tx.version, true);
		// data.push_back(0);
		// data.push_back(1);
		// utils::append_uint32(data, tx.time);

		utils::append_vector(data, CreateVarint(tx.inputs.size()));

		for (auto input : tx.inputs)
		{
			utils::append_vector(data, input.prevout);
			utils::append_vector(data, CreateVarint(input.script.size()));
			utils::append_vector(data, input.script);
			utils::append_uint32(data, input.sequence);
		}

		utils::append_vector(data, CreateVarint(tx.outputs.size()));

		for (auto output : tx.outputs)
		{
			utils::append_uint64(data, output.amount);
			utils::append_vector(data, CreateVarint(output.script.size()));
			utils::append_vector(data, output.script);
		}

		utils::append_uint32(data, tx.locktime);

		auto MAX_CHUNK_SIZE = 255;
		std::vector<std::vector<uint8_t>> chunks;
		auto offset = 0;

		while (offset != data.size())
		{
			auto chunkSize = data.size() - offset > MAX_CHUNK_SIZE ? MAX_CHUNK_SIZE : data.size() - offset;
			chunks.push_back(utils::splice(data, offset, chunkSize));
			offset += chunkSize;
		}

		auto isFirst = true;
		std::vector<uint8_t> finalResults;
		for (auto &chunk : chunks)
		{
			auto result = GetTrustedInputRaw(isFirst, 0, chunk);
			if (std::get<0>(result) != Error::SUCCESS)
			{
				return {std::get<0>(result), {}};
			}

			isFirst = false;
			finalResults = std::get<1>(result);
		}

		return {Error::SUCCESS, finalResults};
	}

	std::tuple<Error, std::vector<uint8_t>> Ledger::GetTrustedInput(uint32_t indexLookup, const std::vector<uint8_t> &transaction)
	{
		auto tx = SplitTransaction(transaction);

		std::vector<uint8_t> data;
		utils::append_uint32(data, tx.version);
		utils::append_uint32(data, tx.time);
		utils::append_vector(data, CreateVarint(tx.inputs.size()));

		auto result = GetTrustedInputRaw(true, indexLookup, data);
		if (std::get<0>(result) != Error::SUCCESS)
		{
			return {std::get<0>(result), {}};
		}

		for (auto input : tx.inputs)
		{
			std::vector<uint8_t> inputData;
			utils::append_vector(inputData, input.prevout);
			utils::append_vector(inputData, CreateVarint(input.script.size()));

			result = GetTrustedInputRaw(false, 0, inputData);
			if (std::get<0>(result) != Error::SUCCESS)
			{
				return {std::get<0>(result), {}};
			}

			auto result = ProcessScriptBlocks(input.script, input.sequence);
			if (std::get<0>(result) != Error::SUCCESS)
			{
				return result;
			}
		}

		result = GetTrustedInputRaw(false, 0, CreateVarint(tx.outputs.size()));
		if (std::get<0>(result) != Error::SUCCESS)
		{
			return {std::get<0>(result), {}};
		}

		for (auto output : tx.outputs)
		{
			std::vector<uint8_t> outputData;
			utils::append_uint64(outputData, output.amount, false);
			utils::append_vector(outputData, CreateVarint(output.script.size()));
			utils::append_vector(outputData, output.script);

			result = GetTrustedInputRaw(false, 0, outputData);
			if (std::get<0>(result) != Error::SUCCESS)
			{
				return {std::get<0>(result), {}};
			}
		}

		auto locktimeBytes = utils::int_to_bytes(tx.locktime, 4);
		return GetTrustedInputRaw(false, 0, locktimeBytes);
	}

	void Ledger::SignTransaction()
	{
	}

	void Ledger::close() { return transport_->close(); }
} // namespace ledger
