#include "ledger.h"
#include "error.h"
#include "hash.h"
#include "utils.h"
#include "base58.h"
#include "bip32.h"

#include <algorithm>
#include <iostream>

namespace ledger
{
	Ledger::Ledger() { this->transport_ = std::unique_ptr<Transport>(new Transport(Transport::TransportType::HID)); }

	Ledger::~Ledger() { transport_->close(); }

	Error Ledger::open()
	{
		std::cout << "Opening Ledger connection." << std::endl;
		auto openError = transport_->open();
		if (openError != ledger::Error::SUCCESS)
		{
			throw ledger::error_message(openError);
		}
		std::cout << "Ledger connection opened." << std::endl;
	}

	std::tuple<bytes, std::string, bytes> Ledger::GetPublicKey(const std::string &path, bool confirm)
	{
		auto payload = bytes();

		auto pathBytes = bip32::ParseHDKeypath(path);
		payload.push_back(pathBytes.size() / 4);
		utils::AppendVector(payload, pathBytes);

		auto result = transport_->exchange(APDU::CLA, APDU::INS_GET_PUBLIC_KEY, confirm, 0x02, payload);
		auto err = std::get<0>(result);
		auto buffer = std::get<1>(result);
		if (err != Error::SUCCESS)
			throw error_message(err);

		auto offset = 1;
		auto pubKeyLen = (int)buffer[offset] * 16 + 1;
		auto pubKey = utils::Splice(buffer, offset, pubKeyLen);
		offset += pubKeyLen;

		auto addressLen = (int)buffer[offset];
		offset++;
		auto address = utils::Splice(buffer, offset, addressLen);
		offset += addressLen;

		auto chainCode = utils::Splice(buffer, offset, 32);
		offset += 32;

		if (offset != buffer.size())
			throw "Something went wrong";

		return {pubKey, std::string(address.begin(), address.end()), chainCode};
	}

	std::tuple<Error, bytes> Ledger::sign(uint32_t account, const bytes &msg)
	{
		auto payload = utils::IntToBytes(account, 4);
		payload.insert(payload.end(), msg.begin(), msg.end());
		auto result = transport_->exchange(APDU::CLA, APDU::INS_SIGN, 0x00, 0x00, payload);
		auto err = std::get<0>(result);
		auto buffer = std::get<1>(result);
		if (err != Error::SUCCESS)
			return {err, {}};
		return {err, bytes(buffer.begin() + 1, buffer.end())};
	}

	std::tuple<uint32_t, uint8_t> Ledger::GetVarint(const bytes &data, uint32_t offset)
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

	bytes Ledger::CreateVarint(uint32_t value)
	{
		bytes data;
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

	Tx Ledger::SplitTransaction(const bytes &transaction)
	{
		Tx tx;
		tx.inputs = std::vector<TxInput>();
		tx.outputs = std::vector<TxOutput>();

		auto offset = 0;

		tx.version = utils::BytesToInt(utils::Splice(transaction, offset, 4), true);
		offset += 4;

		tx.time = utils::BytesToInt(utils::Splice(transaction, offset, 4), true);
		offset += 4;

		auto varint = GetVarint(transaction, offset);
		auto inputsCount = std::get<0>(varint);
		offset += std::get<1>(varint);

		auto flags = 0;
		if (inputsCount == 0)
		{
			flags = utils::BytesToInt(utils::Splice(transaction, offset, 1));
			offset += 1;

			varint = GetVarint(transaction, offset);
			inputsCount = std::get<0>(varint);
			offset += std::get<1>(varint);
		}

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

			output.amount = utils::BytesToUint64(utils::Splice(transaction, offset, 8), true);
			offset += 8;

			varint = GetVarint(transaction, offset);
			offset += std::get<1>(varint);

			output.script = utils::Splice(transaction, offset, std::get<0>(varint));
			offset += std::get<0>(varint);

			tx.outputs.push_back(output);
		}

		if (flags != 0)
		{
			TxWitness txWitness;
			for (auto i = 0; i < inputsCount; i++)
			{
				auto numberOfWitnesses = GetVarint(transaction, offset);
				offset += std::get<1>(numberOfWitnesses);

				TxInWitness txInWitness;
				ScriptWitness scriptWitness;
				for (auto j = 0; j < std::get<0>(numberOfWitnesses); j++)
				{
					auto scriptWitnessSize = GetVarint(transaction, offset);
					offset += std::get<1>(scriptWitnessSize);
					scriptWitness.stack.push_back(bytes(transaction.begin() + offset, transaction.begin() + offset + std::get<0>(scriptWitnessSize)));
					offset += std::get<0>(scriptWitnessSize);
				}

				txInWitness.scriptWitness = scriptWitness;
				txWitness.txInWitnesses.push_back(txInWitness);
			}
		}

		tx.locktime = utils::BytesToInt(utils::Splice(transaction, offset, 4));

		return tx;
	}

	std::tuple<Error, bytes> Ledger::GetTrustedInputRaw(bool firstRound, uint32_t indexLookup, const bytes &transactionData)
	{
		auto result = transport_->exchange(APDU::CLA, APDU::INS_GET_TRUSTED_INPUT, firstRound ? 0x00 : 0x80, 0x00, transactionData);
		auto err = std::get<0>(result);
		auto buffer = std::get<1>(result);
		if (err != Error::SUCCESS)
			return {err, {}};

		return {err, bytes(buffer.begin(), buffer.end())};
	}

	std::tuple<Error, bytes> Ledger::GetTrustedInput(uint32_t indexLookup, Tx tx)
	{
		bytes serializedTransaction;
		utils::AppendUint32(serializedTransaction, tx.version, true);
		utils::AppendUint32(serializedTransaction, tx.time, true);

		utils::AppendVector(serializedTransaction, CreateVarint(tx.inputs.size()));
		for (auto input : tx.inputs)
		{
			utils::AppendVector(serializedTransaction, input.prevout);
			utils::AppendVector(serializedTransaction, CreateVarint(input.script.size()));
			utils::AppendVector(serializedTransaction, input.script);
			utils::AppendUint32(serializedTransaction, input.sequence);
		}

		utils::AppendVector(serializedTransaction, CreateVarint(tx.outputs.size()));
		for (auto output : tx.outputs)
		{
			utils::AppendUint64(serializedTransaction, output.amount, true);
			utils::AppendVector(serializedTransaction, CreateVarint(output.script.size()));
			utils::AppendVector(serializedTransaction, output.script);
		}

		utils::AppendUint32(serializedTransaction, tx.locktime);

		return GetTrustedInput(indexLookup, serializedTransaction);
	}

	TrustedInput Ledger::DeserializeTrustedInput(const bytes &serializedTrustedInput)
	{
		TrustedInput trustedInput;

		// TODO GK - direct assignment ok?
		utils::AppendVector(trustedInput.serialized, serializedTrustedInput);

		auto offset = 0;

		auto trustedInputMagic = serializedTrustedInput[offset];
		if (trustedInputMagic != 0x32)
			throw "Invalid trusted input magic";
		offset += 1;

		auto zeroByte = serializedTrustedInput[offset];
		if (zeroByte != 0x00)
			throw "Zero byte is not a zero byte";
		offset += 1;

		trustedInput.random = utils::BytesToInt(utils::Splice(serializedTrustedInput, offset, 2));
		offset += 2;

		trustedInput.prevTxId = utils::Splice(serializedTrustedInput, offset, 32);
		offset += 32;

		trustedInput.outIndex = utils::BytesToInt(utils::Splice(serializedTrustedInput, offset, 4), true);
		offset += 4;

		trustedInput.amount = utils::BytesToInt(utils::Splice(serializedTrustedInput, offset, 8), true);
		offset += 8;

		trustedInput.hmac = utils::Splice(serializedTrustedInput, offset, 8);
		offset += 8;

		if (offset != serializedTrustedInput.size())
			throw "Leftover bytes in trusted input";

		return trustedInput;
	}

	std::tuple<Error, bytes> Ledger::GetTrustedInput(uint32_t indexLookup, const bytes &serializedTransaction)
	{
		auto MAX_CHUNK_SIZE = 255;
		std::vector<bytes> chunks;
		auto offset = 0;

		bytes data;
		utils::AppendUint32(data, indexLookup);

		utils::AppendVector(data, serializedTransaction);

		while (offset != data.size())
		{
			auto chunkSize = data.size() - offset > MAX_CHUNK_SIZE ? MAX_CHUNK_SIZE : data.size() - offset;
			chunks.push_back(utils::Splice(data, offset, chunkSize));
			offset += chunkSize;
		}

		auto isFirst = true;
		bytes finalResults;
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

	void Ledger::UntrustedHashTxInputFinalize(Tx tx, const std::string &changePath)
	{
		auto ins = APDU::INS_UNTRUSTED_HASH_TRANSACTION_INPUT_FINALIZE;
		auto p2 = 0x00;

		auto p1 = 0xFF;
		if (changePath.length() > 0)
		{
			auto serializedChangePath = bip32::ParseHDKeypath(changePath);

			bytes changePathData;
			changePathData.push_back(serializedChangePath.size() / 4);
			utils::AppendVector(changePathData, serializedChangePath);

			auto result = transport_->exchange(APDU::CLA, ins, p1, p2, changePathData);
			auto err = std::get<0>(result);
			auto buffer = std::get<1>(result);
			if (err != Error::SUCCESS)
				throw err;
		}
		else
		{
			auto result = transport_->exchange(APDU::CLA, ins, p1, p2, {0x00});
			auto err = std::get<0>(result);
			auto buffer = std::get<1>(result);
			if (err != Error::SUCCESS)
				throw err;
		}

		p1 = 0x00;
		auto result = transport_->exchange(APDU::CLA, ins, p1, p2, CreateVarint(tx.outputs.size()));
		auto err = std::get<0>(result);
		auto buffer = std::get<1>(result);
		if (err != Error::SUCCESS)
			throw err;

		for (auto i = 0; i < tx.outputs.size(); i++)
		{
			p1 = i < tx.outputs.size() - 1 ? 0x00 : 0x80;

			auto output = tx.outputs[i];
			bytes outputData;
			utils::AppendUint64(outputData, output.amount, true);
			utils::AppendVector(outputData, CreateVarint(output.script.size()));
			utils::AppendVector(outputData, output.script);

			auto result = transport_->exchange(APDU::CLA, ins, p1, p2, outputData);
			auto err = std::get<0>(result);
			auto buffer = std::get<1>(result);
			if (err != Error::SUCCESS)
				throw err;
		}
	}

	void Ledger::UntrustedHashTxInputStart(Tx tx, const std::vector<TrustedInput> &trustedInputs, int inputIndex, bytes script, bool isNewTransaction)
	{
		auto ins = APDU::INS_UNTRUSTED_HASH_TRANSACTION_INPUT_START;
		auto p1 = 0x00;
		auto p2 = isNewTransaction ? 0x02 : 0x80;

		bytes data;
		utils::AppendUint32(data, tx.version, true);
		utils::AppendUint32(data, tx.time, true);
		utils::AppendVector(data, CreateVarint(trustedInputs.size()));

		auto result = transport_->exchange(APDU::CLA, ins, p1, p2, data);
		auto err = std::get<0>(result);
		auto buffer = std::get<1>(result);
		if (err != Error::SUCCESS)
			throw err;

		p1 = 0x80;
		for (auto i = 0; i < trustedInputs.size(); i++)
		{
			auto trustedInput = trustedInputs[i];
			auto _script = i == inputIndex ? script : bytes();

			bytes _data;
			_data.push_back(0x01);
			_data.push_back(trustedInput.serialized.size());
			utils::AppendVector(_data, trustedInput.serialized);
			utils::AppendVector(_data, CreateVarint(_script.size()));

			utils::PrintHex(trustedInput.serialized);
			utils::PrintHex(_data);

			auto result = transport_->exchange(APDU::CLA, ins, p1, p2, _data);
			auto err = std::get<0>(result);
			auto buffer = std::get<1>(result);
			if (err != Error::SUCCESS)
				throw err;

			bytes scriptData;
			utils::AppendVector(scriptData, _script);
			utils::AppendUint32(scriptData, 0xfffffffd, true);

			result = transport_->exchange(APDU::CLA, ins, p1, p2, scriptData);
			err = std::get<0>(result);
			buffer = std::get<1>(result);
			if (err != Error::SUCCESS)
				throw err;
		}
	}

	std::vector<std::tuple<int, bytes>> Ledger::SignTransaction(const std::string &address, uint64_t amount, uint64_t fees, const std::string &changePath, const std::vector<std::string> &signPaths, const std::vector<std::tuple<bytes, uint32_t>> &rawUtxos, uint32_t locktime)
	{
		Tx tx;
		tx.version = 2;
		tx.time = 0;
		tx.locktime = locktime;

		// build UTxOs and count amount available
		std::vector<Utxo> utxos;
		uint64_t amountAvailable = 0;
		for (const auto &rawUtxo : rawUtxos)
		{
			Utxo utxo;
			utxo.raw = std::get<0>(rawUtxo);
			utxo.index = std::get<1>(rawUtxo);

			auto utxoTx = SplitTransaction(utxo.raw);
			utxo.tx = utxoTx;

			utxos.push_back(utxo);

			auto amount = utxoTx.outputs[utxo.index].amount;
			amountAvailable += amount;
		}

		// get trusted inputs
		std::vector<TrustedInput> trustedInputs;
		for (auto i = 0; i < utxos.size(); i++)
		{
			const auto &utxo = utxos[i];

			const auto serializedTrustedInputResult = GetTrustedInput(utxo.index, utxo.tx);
			auto trustedInput = DeserializeTrustedInput(std::get<1>(serializedTrustedInputResult));

			TxInput txInput;
			txInput.prevout = trustedInput.prevTxId;

			auto publicKeyResult = GetPublicKey(signPaths[i], false);
			auto publicKey = utils::CompressPubKey(std::get<0>(publicKeyResult));

			auto pubKeyHash = Hash160(publicKey);
			bytes pubKeyHashVector(pubKeyHash.begin(), pubKeyHash.end());

			bytes finalScriptPubKey;
			finalScriptPubKey.push_back(0x76);
			finalScriptPubKey.push_back(0xa9);
			finalScriptPubKey.push_back(0x14);
			utils::AppendVector(finalScriptPubKey, pubKeyHashVector);
			finalScriptPubKey.push_back(0x88);
			finalScriptPubKey.push_back(0xac);

			txInput.script = finalScriptPubKey;
			txInput.sequence = 0xfffffffd;

			trustedInputs.push_back(trustedInput);
			tx.inputs.push_back(txInput);
		}

		// create change output
		if (amountAvailable - fees > amount)
		{
			auto publicKeyResult = GetPublicKey(changePath, false);
			auto publicKey = utils::CompressPubKey(std::get<0>(publicKeyResult));
			auto publicKeyHash = Hash160(publicKey);

			// TODO GK - other key structures?
			bytes changeScriptPublicKey;
			changeScriptPublicKey.push_back(0x76);
			changeScriptPublicKey.push_back(0xa9);
			changeScriptPublicKey.push_back(0x14);
			utils::AppendVector(changeScriptPublicKey, bytes(publicKeyHash.begin(), publicKeyHash.end()));
			changeScriptPublicKey.push_back(0x88);
			changeScriptPublicKey.push_back(0xac);

			TxOutput txChangeOutput;
			// TODO GK - fix amount
			txChangeOutput.amount = amount - fees;
			txChangeOutput.script = changeScriptPublicKey;
			tx.outputs.push_back(txChangeOutput);
		}

		// create output to address
		// TODO GK - other key structures?
		bytes scriptPublicKey;
		scriptPublicKey.push_back(0x76);
		scriptPublicKey.push_back(0xa9);
		scriptPublicKey.push_back(0x14);
		auto addressDecoded = Base58Decode(address);
		utils::AppendVector(scriptPublicKey, bytes(addressDecoded.begin() + 1, addressDecoded.end() - 4));
		scriptPublicKey.push_back(0x88);
		scriptPublicKey.push_back(0xac);

		TxOutput txOutput;
		txOutput.amount = amount;
		txOutput.script = scriptPublicKey;
		tx.outputs.push_back(txOutput);

		for (auto i = 0; i < tx.inputs.size(); i++)
		{
			UntrustedHashTxInputStart(tx, trustedInputs, i, tx.inputs[i].script, i == 0);
		}

		UntrustedHashTxInputFinalize(tx, changePath);

		std::vector<std::tuple<int, bytes>> signatures;
		for (auto i = 0; i < tx.inputs.size(); i++)
		{
			UntrustedHashTxInputStart(tx, {trustedInputs[i]}, 0, tx.inputs[i].script, false);

			auto amount = tx.outputs[i].amount;

			auto ins = INS_UNTRUSTED_HASH_SIGN;
			auto p1 = 0x00;
			auto p2 = 0x00;

			auto serializedChangePath = bip32::ParseHDKeypath(signPaths[i]);

			bytes data;
			data.push_back(serializedChangePath.size() / 4);
			utils::AppendVector(data, serializedChangePath);
			data.push_back(0x00);
			utils::AppendUint32(data, locktime);
			data.push_back(0x01);

			auto result = transport_->exchange(APDU::CLA, ins, p1, p2, data);
			auto err = std::get<0>(result);
			auto buffer = std::get<1>(result);
			if (err != Error::SUCCESS)
				throw err;

			utils::PrintHex(buffer);

			if (buffer[0] & 0x01)
			{
				bytes data;
				data.push_back(0x30);
				utils::AppendVector(data, bytes(buffer.begin() + 1, buffer.end()));
				signatures.push_back({{1}, data});
			}
			else
			{
				signatures.push_back({{0}, buffer});
			}
		}

		return signatures;
	}

	void Ledger::close() { return transport_->close(); }
} // namespace ledger
