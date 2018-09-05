des.nim
=======

[![Build Status](https://travis-ci.org/LucaWolf/des.nim.svg?branch=master)](https://travis-ci.org/LucaWolf/des.nim)

About
-----
This is a Nim port of a C-based DES implementation. It implements single, double and triple DES operations with support for basic data padding. 
DUKPT simple key management (PEK is cached, not holding the future keys array) with encrypt/decrypt and MAC operations also supported.

Examples
--------
Refer to the `test` folder for how to DES crypt/decrypt and DUKPT current key(s) derivation.

Notes
-----
- only the mostly used CBC and ECB modes are implemented. Nowadays, ECB is only useful as an internal helper routine, do not encode your data that way.
- pay attention to resetting the IV when starting a different logical operation (IV is cached to allow manual chaining)
- all operations are based on complete input data. For streams, your may want to enhance or build atop the existing implementation. The last processed block may require special handling (see MAC X9.19)

Future
------
None. All desired operations are now supported. (low priority: perhaps incrementing the internal KSN field and deriving the keys based on it)

Credits
-------
Thanks to the libtomcrypt authors on whose work this library is based.
