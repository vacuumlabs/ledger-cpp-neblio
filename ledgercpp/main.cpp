#include "ledger.h"
#include "error.h"
#include "utils.h"

#include <string.h>

#include <iostream>
#include <iomanip>

using namespace ledger;

std::string NEBLIO_TX_FROM_RPC = "01000000b59cfc6301cec8e9fad831395e6d626837a478e4d082ba9c4e6f5c6e6047725de7df2e1b57000000006b483045022100959ea739d1cbc75ab8d32ff8d6f9a559c6644ef149b7f7f03107c0e08b2662f4022059f8f0da281c21edbe2da8c46552fd2099ede592fed1f5f06e7b2cb5ec78830d0121029d178514d15a2223c48adf548ae65dcbfdfc271054e1ce893aab0306123003c5ffffffff0200e1f505000000001976a914b5a94913cb123972678f8ab2727cb810add78afb88ace0a0f78a2e0000001976a9140109ec1c263c6ef86c20e45d0ae214334dff6b7e88ac00000000";
std::string BTC_TX_FROM_JSON = "02000000015122c2cde6823e55754175b92c9c57a0a8e1ac83c38e1787fd3a1ff3348e9513010000006b483045022100e55b3ca788721aae8def2eadff710e524ffe8c9dec1764fdaa89584f9726e196022012a30fbcf9e1a24df31a1010356b794ab8de438b4250684757ed5772402540f4012102ee8608207e21028426f69e76447d7e3d5e077049f5e683c3136c2314762a4718fdffffff0178410f00000000001976a91413d7d58166946c3ec022934066d8c0d111d1bb4188ac1a041d00";
std::string BTC_TX_FROM_TRUSTED_INPUTS = "020000000240d1ae8a596b34f48b303e853c56f8f6f54c483babc16978eb182e2154d5f2ab000000006b483045022100ca145f0694ffaedd333d3724ce3f4e44aabc0ed5128113660d11f917b3c5205302207bec7c66328bace92bd525f385a9aa1261b83e0f92310ea1850488b40bd25a5d0121032006c64cdd0485e068c1e22ba0fa267ca02ca0c2b34cdc6dd08cba23796b6ee7fdffffff40d1ae8a596b34f48b303e853c56f8f6f54c483babc16978eb182e2154d5f2ab010000006a47304402202a5d54a1635a7a0ae22cef76d8144ca2a1c3c035c87e7cd0280ab43d3451090602200c7e07e384b3620ccd2f97b5c08f5893357c653edc2b8570f099d9ff34a0285c012102d82f3fa29d38297db8e1879010c27f27533439c868b1cc6af27dd3d33b243decfdffffff01d7ee7c01000000001976a9140ea263ff8b0da6e8d187de76f6a362beadab781188ace3691900";
std::string TX_FROM_TESTS = "0200000000000000015122c2cde6823e55754175b92c9c57a0a8e1ac83c38e1787fd3a1ff3348e9513010000006b483045022100e55b3ca788721aae8def2eadff710e524ffe8c9dec1764fdaa89584f9726e196022012a30fbcf9e1a24df31a1010356b794ab8de438b4250684757ed5772402540f4012102ee8608207e21028426f69e76447d7e3d5e077049f5e683c3136c2314762a4718fdffffff0178410f00000000001976a91413d7d58166946c3ec022934066d8c0d111d1bb4188ac1a041d00";
std::string UTXO_TX_FROM_TESTS = "0200000000000000000101ec230e53095256052a2428270eec0498944b10f6f1c578f431c23d0098b4ae5a0100000017160014281539820e2de973ae41ba6004b431c921c4d86dfeffffff02727275000000000017a914c8b906af298c70e603a28c3efc2fae19e6ab280f8740420f00000000001976a914cbae5b50cf939e6f531b8a6b7abd788fe14b029788ac02473044022037ecb4248361aafd4f8c11e705f0fa7a5fbdcd595172fcd5643f3b11beff5d400220020c6d326f6c37d63cecadaf4eb335faedf7c44e05f5ef1d2b68140b023bd13d012103dac82fc0acfcfc36348d4a48a46f01cea77f2b9ece3f8c3b4c99d0b0b2f995d284f21c00";

int getPublicKey()
{
  ledger::Ledger ledger;
  ledger.open();

  std::cout << "Getting public key - please confirm action on Ledger" << std::endl;

  auto result = ledger.GetPublicKey("m/44'/146'/0'", true);
  auto pubKey = std::get<0>(result);
  auto addressVec = std::get<1>(result);
  auto chainCode = std::get<2>(result);

  std::cout << "Public key: ";
  utils::PrintHex(pubKey);

  auto address = std::string(addressVec.begin(), addressVec.end());
  std::cout << "Address: " << address << std::endl;

  std::cout << "Chain code: ";
  utils::PrintHex(chainCode);

  return 0;
}

void signTransaction()
{
  ledger::Ledger ledger;
  ledger.open();

  auto serializedTransaction = utils::HexToBytes(UTXO_TX_FROM_TESTS);
  auto txstr = utils::BytesToHex(serializedTransaction);

  auto result = ledger.SignTransaction("mhKsh7EzJo1gSU1vrpyejS1qsJAuKyaWWg", 999800, 200, "", {"m/84'/1'/0'/0/0"}, {{serializedTransaction, 1}}, 1901594);

  if (utils::BytesToHex(std::get<1>(result[0])) != "3044022100ca7c026ef193d0e0091c4f7855f883689fca843c974b9a2a4c7285af1e24683b021f28f6c0b5f8899389b473669a1d92dc950af57cb4d1013b510b9b7d1617bb2401")
  {
    std::cout << "Different results received";
  }
  else
  {
    std::cout << "Same results received";
  }
}

int main(int argc, char *argv[])
{
  // getPublicKey();
  signTransaction();
}
