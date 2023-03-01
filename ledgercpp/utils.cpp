#include "utils.h"

#include <algorithm>
#include <iostream>
#include <iomanip>

namespace ledger::utils
{
	void printHex(std::vector<uint8_t> vec)
	{
		for (int i = 0; i < vec.size(); i++)
		{
			std::cout << std::hex << std::setfill('0') << std::setw(2) << (int)vec[i];
		}

		std::cout << std::dec << std::endl;
	}

	uint64_t bytes_to_uint64(const std::vector<uint8_t> &bytes)
	{
		uint64_t value = 0;
		for (const uint8_t &byte : bytes)
		{
			value = (value << 8) + byte;
		}
		return value;
	}

	int bytes_to_int(const std::vector<uint8_t> &bytes)
	{
		int value = 0;
		for (const uint8_t &byte : bytes)
		{
			value = (value << 8) + byte;
		}
		return value;
	}

	std::vector<uint8_t> int_to_bytes(uint32_t n, uint32_t length, bool littleEndian)
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

	void append_uint32(std::vector<uint8_t> &vector, uint32_t n, bool littleEndian)
	{
		append_vector(vector, int_to_bytes(n, 4, littleEndian));
	}

	std::vector<uint8_t> uint64_to_bytes(uint64_t n, uint32_t length, bool littleEndian)
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

	void append_uint64(std::vector<uint8_t> &vector, uint64_t n, bool littleEndian)
	{
		append_vector(vector, uint64_to_bytes(n, 8, littleEndian));
	}

	uint32_t hardened(uint32_t n)
	{
		return n | 0x80000000;
	}

	std::vector<uint8_t> splice(std::vector<uint8_t> vec, int start, int length)
	{
		std::vector<uint8_t> result(length);
		copy(vec.begin() + start, vec.begin() + start + length, result.begin());

		return result;
	}
} // namespace ledger::utils
