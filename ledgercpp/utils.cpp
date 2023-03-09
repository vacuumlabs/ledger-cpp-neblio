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

	uint32_t Harden(uint32_t n)
	{
		return n | 0x80000000;
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

	// copied from https://github.com/bitcoin/bitcoin/blob/master/src/util/bip32.cpp#L13
	// and adjusted for uint8_t instead of uint32_t vector
	std::vector<uint8_t> ParseHDKeypath(const std::string &keypath_str)
	{
		std::vector<uint8_t> keypath;
		std::stringstream ss(keypath_str);
		std::string item;
		bool first = true;
		while (std::getline(ss, item, '/'))
		{
			if (item.compare("m") == 0)
			{
				if (first)
				{
					first = false;
					continue;
				}
				throw std::runtime_error("Invalid keypath");
			}
			// Finds whether it is hardened
			uint32_t path = 0;
			size_t pos = item.find("'");
			if (pos != std::string::npos)
			{
				// The hardened tick can only be in the last index of the string
				if (pos != item.size() - 1)
				{
					throw std::runtime_error("Invalid keypath");
				}
				path |= 0x80000000;
				item = item.substr(0, item.size() - 1); // Drop the last character which is the hardened tick
			}

			// Ensure this is only numbers
			if (item.find_first_not_of("0123456789") != std::string::npos)
			{
				throw std::runtime_error("Invalid keypath");
			}

			utils::AppendUint32(keypath, std::stoul(item) | path);

			first = false;
		}
		return keypath;
	}
} // namespace ledger::utils
