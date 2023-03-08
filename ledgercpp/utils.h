#ifndef _LEDGER_UTILS
#define _LEDGER_UTILS 1

#include <cstdint>
#include <vector>
#include <string>

namespace ledger::utils
{
	std::string BytesToHex(std::vector<uint8_t> vec);

	void printHex(std::vector<uint8_t> vec);
	std::vector<uint8_t> HexToBytes(const std::string &data);
	uint64_t bytes_to_uint64(const std::vector<uint8_t> &bytes);
	int bytes_to_int(const std::vector<uint8_t> &bytes, bool littleEndian = false);
	std::vector<uint8_t> int_to_bytes(unsigned int n, unsigned int length, bool littleEndian = false);
	std::vector<uint8_t> uint64_to_bytes(uint64_t n, unsigned int length, bool littleEndian = false);
	template <typename T>
	void append_vector(std::vector<T> &destination, std::vector<T> source)
	{
		destination.insert(destination.end(), source.begin(), source.end());
	}
	void append_uint32(std::vector<uint8_t> &vector, uint32_t n, bool littleEndian = false);
	void append_uint64(std::vector<uint8_t> &vector, uint64_t n, bool littleEndian = false);
	uint32_t hardened(uint32_t n);
	std::vector<uint8_t> splice(std::vector<uint8_t> vec, int start, int length);
	std::vector<uint8_t> compressPubKey(std::vector<uint8_t> pubKey);
	bool ParseHDKeypath(const std::string &keypath_str, std::vector<uint8_t> &keypath);
} // namespace ledger::utils

#endif
