#ifndef __LEDGER_BIP32
#define __LEDGER_BIP32 1

#include <cstdint>
#include <vector>
#include <string>

namespace ledger::bip32
{
    uint32_t Harden(uint32_t n);
    std::vector<uint8_t> ParseHDKeypath(const std::string &keypath_str);
}

#endif