#include "utils.h"

#include <algorithm>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>

namespace ledger::utils
{
	std::string BytesToHex(std::vector<uint8_t> vec)
	{
		std::stringstream ss;
		for (int i = 0; i < vec.size(); i++)
		{
			ss << std::hex << std::setfill('0') << std::setw(2) << (int)vec[i];
		}

		return ss.str();
	}

	void PrintHex(std::vector<uint8_t> vec)
	{
		for (int i = 0; i < vec.size(); i++)
		{
			std::cout << std::hex << std::setfill('0') << std::setw(2) << (int)vec[i];
		}

		std::cout << std::dec << std::endl;
	}

	std::vector<uint8_t> HexToBytes(const std::string &data)
	{
		std::stringstream ss;
		ss << data;

		std::vector<uint8_t> resBytes;
		size_t count = 0;
		const auto len = data.size();
		while (ss.good() && count < len)
		{
			unsigned short num;
			char hexNum[2];
			ss.read(hexNum, 2);
			sscanf(hexNum, "%2hX", &num);
			resBytes.push_back(num);
			count += 2;
		}
		return resBytes;
	}

	uint64_t BytesToUint64(const std::vector<uint8_t> &bytes)
	{
		uint64_t value = 0;
		for (const uint8_t &byte : bytes)
		{
			value = (value << 8) + byte;
		}
		return value;
	}

	int BytesToInt(const std::vector<uint8_t> &bytes, bool littleEndian)
	{
		auto bytesToConvert = bytes;
		if (littleEndian)
		{
			bytesToConvert = std::vector<uint8_t>(bytesToConvert.rbegin(), bytesToConvert.rend());
		}

		int value = 0;
		for (const uint8_t &byte : bytesToConvert)
		{
			value = (value << 8) + byte;
		}
		return value;
	}

	std::vector<uint8_t> IntToBytes(uint32_t n, uint32_t length, bool littleEndian)
	{
		std::vector<uint8_t> bytes;
		bytes.reserve(length);
		for (auto i = 0; i < length; i++)
		{
			bytes.emplace_back((n >> 8 * (length - 1 - i)) & 0xFF);
		}

		if (littleEndian)
		{
			std::reverse(bytes.begin(), bytes.end());
		}

		return bytes;
	}

	void AppendUint32(std::vector<uint8_t> &vector, uint32_t n, bool littleEndian)
	{
		AppendVector(vector, IntToBytes(n, 4, littleEndian));
	}

	std::vector<uint8_t> Uint64ToBytes(uint64_t n, uint32_t length, bool littleEndian)
	{
		std::vector<uint8_t> bytes;
		bytes.reserve(length);
		for (auto i = 0; i < length; i++)
		{
			bytes.emplace_back((n >> 8 * (length - 1 - i)) & 0xFF);
		}

		if (littleEndian)
		{
			std::reverse(bytes.begin(), bytes.end());
		}

		return bytes;
	}

	void AppendUint64(std::vector<uint8_t> &vector, uint64_t n, bool littleEndian)
	{
		AppendVector(vector, Uint64ToBytes(n, 8, littleEndian));
	}

	std::vector<uint8_t> Splice(std::vector<uint8_t> vec, int start, int length)
	{
		std::vector<uint8_t> result(length);
		copy(vec.begin() + start, vec.begin() + start + length, result.begin());

		return result;
	}

	std::vector<uint8_t> CompressPubKey(std::vector<uint8_t> pubKey)
	{
		if (pubKey.size() != 65)
		{
			throw std::runtime_error("Invalid public key length");
		}

		if (pubKey[0] != 0x04)
		{
			throw std::runtime_error("Invalid public key format");
		}

		std::vector<uint8_t> compressedPubKey(33);
		compressedPubKey[0] = pubKey[64] & 1 ? 0x03 : 0x02;
		copy(pubKey.begin() + 1, pubKey.begin() + 33, compressedPubKey.begin() + 1);

		return compressedPubKey;
	}
} // namespace ledger::utils
