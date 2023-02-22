#include "ledger.h"
#include "error.h"

#include <iostream>
#include <iomanip>

std::vector<uint8_t> splice(std::vector<uint8_t> vec, int start, int length)
{
  std::vector<uint8_t> result(length);
  copy(vec.begin() + start, vec.begin() + start + length, result.begin());

  return result;
}

void printHex(std::vector<uint8_t> vec)
{
  for (int i = 0; i < vec.size(); i++)
  {
    std::cout << std::hex << std::setfill('0') << std::setw(2) << (int)vec[i] << " ";
  }

  std::cout << std::dec << std::endl;
}

int main()
{
  std::cout << "Opening Ledger connection" << std::endl;

  auto ledger = ledger::Ledger();
  auto openError = ledger.open();
  if (openError != ledger::Error::SUCCESS)
  {
    std::cout << ledger::error_message(openError) << std::endl;
    return -1;
  }

  std::cout << "Getting public key - please confirm action on Ledger" << std::endl;

  auto result = ledger.get_public_key(0, true);
  auto resultError = std::get<0>(result);
  if (resultError != ledger::Error::SUCCESS)
  {
    std::cout << "get key error: " << ledger::error_message(std::get<0>(result)) << std::endl;
    return -1;
  }

  auto resultData = std::get<1>(result);
  std::cout << "Raw result data: ";
  printHex(resultData);

  auto pubKeyLen = (int)resultData[0] * 16;
  auto pubKey = splice(resultData, 0, pubKeyLen + 1);
  std::cout << "Public key: ";
  printHex(pubKey);

  auto addressLen = (int)resultData[1 + pubKeyLen];
  auto address = splice(resultData, pubKeyLen + 2, addressLen);
  std::cout << "Address: " << std::string(address.begin(), address.end()) << std::endl;

  auto chainCode = splice(resultData, pubKeyLen + 1 + addressLen + 1, 32);
  std::cout << "Chain code: ";
  printHex(chainCode);

  return 0;
}
