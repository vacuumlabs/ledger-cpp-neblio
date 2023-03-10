#ifndef _LEDGER_UTILS
#define _LEDGER_UTILS 1

#include "bytes.h"

#include <cstdint>
#include <vector>
#include <string>

namespace ledger::utils
{
	std::tuple<uint32_t, uint8_t> DeserializeVarint(const bytes &data, uint32_t offset);
	bytes CreateVarint(uint32_t value);
	std::string BytesToHex(const bytes &vec);
	void PrintHex(const bytes &vec);
	bytes HexToBytes(const std::string &data);
	uint64_t BytesToUint64(const bytes &bytes, bool littleEndian = false);
	int BytesToInt(const bytes &bytes, bool littleEndian = false);
	bytes IntToBytes(unsigned int n, unsigned int length, bool littleEndian = false);
	bytes Uint64ToBytes(uint64_t n, unsigned int length, bool littleEndian = false);
	template <typename T>
	void AppendVector(std::vector<T> &destination, const std::vector<T> &source)
	{
		destination.insert(destination.end(), source.begin(), source.end());
	}
	void AppendUint32(bytes &vector, uint32_t n, bool littleEndian = false);
	void AppendUint64(bytes &vector, uint64_t n, bool littleEndian = false);
	bytes Splice(const bytes &vec, int start, int length);
	bytes CompressPubKey(const bytes &pubKey);
} // namespace ledger::utils

#endif
