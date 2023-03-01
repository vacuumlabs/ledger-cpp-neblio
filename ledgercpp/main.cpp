#include "ledger.h"
#include "error.h"
#include "utils.h"

#include <string.h>

#include <iostream>
#include <iomanip>
#include <sstream>

using namespace ledger;

void printHex(std::vector<uint8_t> vec)
{
  for (int i = 0; i < vec.size(); i++)
  {
    std::cout << std::hex << std::setfill('0') << std::setw(2) << (int)vec[i] << " ";
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

int getPublicKey()
{
  std::cout << "Opening Ledger connection" << std::endl;

  ledger::Ledger ledger;
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
  auto pubKey = utils::splice(resultData, 0, pubKeyLen + 1);
  std::cout << "Public key: ";
  printHex(pubKey);

  auto addressLen = (int)resultData[1 + pubKeyLen];
  auto address = utils::splice(resultData, pubKeyLen + 2, addressLen);
  std::cout << "Address: " << std::string(address.begin(), address.end()) << std::endl;

  auto chainCode = utils::splice(resultData, pubKeyLen + 1 + addressLen + 1, 32);
  std::cout << "Chain code: ";
  printHex(chainCode);
}

int signTx()
{
  std::cout << "Opening Ledger connection" << std::endl;

  ledger::Ledger ledger;
  auto openError = ledger.open();
  if (openError != ledger::Error::SUCCESS)
  {
    std::cout << ledger::error_message(openError) << std::endl;
    return -1;
  }

  // neblio tx from neblio rpc
  std::string txHex = "01000000b59cfc6301cec8e9fad831395e6d626837a478e4d082ba9c4e6f5c6e6047725de7df2e1b57000000006b483045022100959ea739d1cbc75ab8d32ff8d6f9a559c6644ef149b7f7f03107c0e08b2662f4022059f8f0da281c21edbe2da8c46552fd2099ede592fed1f5f06e7b2cb5ec78830d0121029d178514d15a2223c48adf548ae65dcbfdfc271054e1ce893aab0306123003c5ffffffff0200e1f505000000001976a914b5a94913cb123972678f8ab2727cb810add78afb88ace0a0f78a2e0000001976a9140109ec1c263c6ef86c20e45d0ae214334dff6b7e88ac00000000";
  // btc tx from ledger-app tests
  // std::string txHex = "02000000015122c2cde6823e55754175b92c9c57a0a8e1ac83c38e1787fd3a1ff3348e9513010000006b483045022100e55b3ca788721aae8def2eadff710e524ffe8c9dec1764fdaa89584f9726e196022012a30fbcf9e1a24df31a1010356b794ab8de438b4250684757ed5772402540f4012102ee8608207e21028426f69e76447d7e3d5e077049f5e683c3136c2314762a4718fdffffff0178410f00000000001976a91413d7d58166946c3ec022934066d8c0d111d1bb4188ac1a041d00";
  auto transaction = HexToBytes(txHex);

  auto result = ledger.GetTrustedInput(0, transaction);
  auto resultError = std::get<0>(result);
  if (resultError != ledger::Error::SUCCESS)
  {
    std::cout << "get trusted input error: " << ledger::error_message(std::get<0>(result)) << std::endl;
    return -1;
  }

  auto trustedInput = std::get<1>(result);
  printHex(trustedInput);
}

int main(int argc, char *argv[])
{
  auto action = "sign-tx";
  if (argc >= 2)
  {
    if (strcmp(argv[1], "sign-tx") == 0)
    {
      action = "sign-tx";
    }
  }

  if (action == "pub-key")
  {
    getPublicKey();
  }
  else
  {
    signTx();
  }
}
