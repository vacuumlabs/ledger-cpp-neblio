#ifndef _LEDGER_UTILS
#define _LEDGER_UTILS 1

#include <cstdint>
#include <vector>
#include <string>

namespace ledger::utils
{
	std::string BytesToHex(std::vector<uint8_t> vec);

	void PrintHex(std::vector<uint8_t> vec);
	std::vector<uint8_t> HexToBytes(const std::string &data);
	uint64_t BytesToUint64(const std::vector<uint8_t> &bytes);
	int BytesToInt(const std::vector<uint8_t> &bytes, bool littleEndian = false);
	std::vector<uint8_t> IntToBytes(unsigned int n, unsigned int length, bool littleEndian = false);
	std::vector<uint8_t> Uint64ToBytes(uint64_t n, unsigned int length, bool littleEndian = false);
	template <typename T>
	void AppendVector(std::vector<T> &destination, std::vector<T> source)
	{
		destination.insert(destination.end(), source.begin(), source.end());
	}
	void AppendUint32(std::vector<uint8_t> &vector, uint32_t n, bool littleEndian = false);
	void AppendUint64(std::vector<uint8_t> &vector, uint64_t n, bool littleEndian = false);
	uint32_t Harden(uint32_t n);
	std::vector<uint8_t> Splice(std::vector<uint8_t> vec, int start, int length);
	std::vector<uint8_t> CompressPubKey(std::vector<uint8_t> pubKey);
	std::vector<uint8_t> ParseHDKeypath(const std::string &keypath_str);
} // namespace ledger::utils

#endif
