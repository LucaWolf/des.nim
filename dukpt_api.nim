import strutils, sequtils
import des_api
# TODO unify into a dukpt API

type
    dukptCipherObj = object
        pek: seq[byte]
        # TODO future keys array to discard pek
        key: seq[byte] # current key for the desired operation (speed)
        crypter: desCipher
        ksn: seq[byte] # current KSN; future increment API

    dukptCipher* = ref dukptCipherObj 
    
# TODO design: hide all ops under dukptCipher or export the internal crypter object
# and use it directly?

proc restrict*(cipher: dukptCipher, useSingleDes: bool = true) =
    cipher.crypter.restrict()