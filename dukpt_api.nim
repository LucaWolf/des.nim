import strutils, sequtils
import des_api, dukpt_const, dukpt_ipek, dukpt_pek
export des_api, dukpt_const, dukpt_ipek, dukpt_pek

# TODO unify into a dukpt API

type
    dukptCipherObj = object
        pek: dukptKey
        # TODO future keys array to discard pek
        key: dukptKey # current key for the desired operation (speed)
        crypter: desCipher
        ksn: dukptKsn # current KSN; future increment API

    dukptCipher* = ref dukptCipherObj 
    
# TODO design: hide all ops under dukptCipher or export the internal crypter object
# and use it directly?

proc restrict*(cipher: dukptCipher, useSingleDes: bool = true) =
    cipher.crypter.restrict()

proc newDukptCipher*(bdk, ksn: openArray[byte]): dukptCipher =

    if bdk.len != 2 * desBlockSize:
        raise newException(RangeError, "BDK not desBlockSize multiple:" & $bdk.len)

    if ksn.len != 10:
        raise newException(RangeError, "KSN wrong size:" & $ksn.len)


    new(result)
    
    result.pek = createPEK(createIPEK(bdk, ksn), ksn)

    c.isSetup = true
    c.useSingleDes = false

    return c, nil
