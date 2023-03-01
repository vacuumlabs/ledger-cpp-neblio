## GetTrustedInput expected APDUs and results

### Tx from tests with bitcoin app

First APDU: e0420000ff00000000020000000240d1ae8a596b34f48b303e853c56f8f6f54c483babc16978eb182e2154d5f2ab000000006b483045022100ca145f0694ffaedd333d3724ce3f4e44aabc0ed5128113660d11f917b3c5205302207bec7c66328bace92bd525f385a9aa1261b83e0f92310ea1850488b40bd25a5d0121032006c64cdd0485e068c1e22ba0fa267ca02ca0c2b34cdc6dd08cba23796b6ee7fdffffff40d1ae8a596b34f48b303e853c56f8f6f54c483babc16978eb182e2154d5f2ab010000006a47304402202a5d54a1635a7a0ae22cef76d8144ca2a1c3c035c87e7cd0280ab43d3451090602200c7e07e384b3620ccd2f97b5c08f5893357c653edc2b

Second APDU: e0428000588570f099d9ff34a0285c012102d82f3fa29d38297db8e1879010c27f27533439c868b1cc6af27dd3d33b243decfdffffff01d7ee7c01000000001976a9140ea263ff8b0da6e8d187de76f6a362beadab781188ace3691900

_Some of the trusted input data are random so they aren't exactly the same._
Results APDU (trusted input): 32009e057f5f46c09775091481d6a4eaf005ab4ed4acf614ec22e14c59a91c6bbc4c797700000000d7ee7c0100000000ac19fa3d448e388f

### Tx from Neblio RPC with Neblio app

APDU: e0420000ea0000000001000000b59cfc6301cec8e9fad831395e6d626837a478e4d082ba9c4e6f5c6e6047725de7df2e1b57000000006b483045022100959ea739d1cbc75ab8d32ff8d6f9a559c6644ef149b7f7f03107c0e08b2662f4022059f8f0da281c21edbe2da8c46552fd2099ede592fed1f5f06e7b2cb5ec78830d0121029d178514d15a2223c48adf548ae65dcbfdfc271054e1ce893aab0306123003c5ffffffff0200e1f505000000001976a914b5a94913cb123972678f8ab2727cb810add78afb88ace0a0f78a2e0000001976a9140109ec1c263c6ef86c20e45d0ae214334dff6b7e88ac00000000

Result: 3200db247c015417018415ec40f70b30f8f838d72c9aa90d50e27e0c7ec59d69341d34c00000000000e1f5050000000029274039fbf86471