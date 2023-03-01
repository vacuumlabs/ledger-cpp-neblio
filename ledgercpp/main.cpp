#include "ledger.h"
#include "error.h"
#include "utils.h"

#include <string.h>

#include <iostream>
#include <iomanip>
#include <sstream>

using namespace ledger;

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
  utils::printHex(resultData);

  auto pubKeyLen = (int)resultData[0] * 16;
  auto pubKey = utils::splice(resultData, 0, pubKeyLen + 1);
  std::cout << "Public key: ";
  utils::printHex(pubKey);

  auto addressLen = (int)resultData[1 + pubKeyLen];
  auto address = utils::splice(resultData, pubKeyLen + 2, addressLen);
  std::cout << "Address: " << std::string(address.begin(), address.end()) << std::endl;

  auto chainCode = utils::splice(resultData, pubKeyLen + 1 + addressLen + 1, 32);
  std::cout << "Chain code: ";
  utils::printHex(chainCode);
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
  // std::string txHex = "01000000b59cfc6301cec8e9fad831395e6d626837a478e4d082ba9c4e6f5c6e6047725de7df2e1b57000000006b483045022100959ea739d1cbc75ab8d32ff8d6f9a559c6644ef149b7f7f03107c0e08b2662f4022059f8f0da281c21edbe2da8c46552fd2099ede592fed1f5f06e7b2cb5ec78830d0121029d178514d15a2223c48adf548ae65dcbfdfc271054e1ce893aab0306123003c5ffffffff0200e1f505000000001976a914b5a94913cb123972678f8ab2727cb810add78afb88ace0a0f78a2e0000001976a9140109ec1c263c6ef86c20e45d0ae214334dff6b7e88ac00000000";
  // btc tx from ledger-app tests (json)
  // std::string txHex = "02000000015122c2cde6823e55754175b92c9c57a0a8e1ac83c38e1787fd3a1ff3348e9513010000006b483045022100e55b3ca788721aae8def2eadff710e524ffe8c9dec1764fdaa89584f9726e196022012a30fbcf9e1a24df31a1010356b794ab8de438b4250684757ed5772402540f4012102ee8608207e21028426f69e76447d7e3d5e077049f5e683c3136c2314762a4718fdffffff0178410f00000000001976a91413d7d58166946c3ec022934066d8c0d111d1bb4188ac1a041d00";
  // another from ledger-app tests (getTrustedInputs)
  std::string txHex = "020000000240d1ae8a596b34f48b303e853c56f8f6f54c483babc16978eb182e2154d5f2ab000000006b483045022100ca145f0694ffaedd333d3724ce3f4e44aabc0ed5128113660d11f917b3c5205302207bec7c66328bace92bd525f385a9aa1261b83e0f92310ea1850488b40bd25a5d0121032006c64cdd0485e068c1e22ba0fa267ca02ca0c2b34cdc6dd08cba23796b6ee7fdffffff40d1ae8a596b34f48b303e853c56f8f6f54c483babc16978eb182e2154d5f2ab010000006a47304402202a5d54a1635a7a0ae22cef76d8144ca2a1c3c035c87e7cd0280ab43d3451090602200c7e07e384b3620ccd2f97b5c08f5893357c653edc2b8570f099d9ff34a0285c012102d82f3fa29d38297db8e1879010c27f27533439c868b1cc6af27dd3d33b243decfdffffff01d7ee7c01000000001976a9140ea263ff8b0da6e8d187de76f6a362beadab781188ace3691900";
  auto transaction = HexToBytes(txHex);

  auto result = ledger.GetTrustedInputSinglePacket(0, transaction);
  auto resultError = std::get<0>(result);
  if (resultError != ledger::Error::SUCCESS)
  {
    std::cout << "get trusted input error: " << ledger::error_message(std::get<0>(result)) << std::endl;
    return -1;
  }

  auto trustedInput = std::get<1>(result);
  utils::printHex(trustedInput);
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
