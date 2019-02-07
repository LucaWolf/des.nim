import strutils, sequtils
import des_api, dukpt_const
export dukpt_const

#----
proc pekBlackBox(currKey: var dukptKey, currKSN: dukptKsn) =

    var
        keyLeft, keyRight: desKey # copies
        msg, ksnLSB: desKey
        nextKeyLeft: desKey
        nextKeyRight: desKey
        cipher: desCipher
        
    copyTo(currKey, keyLeft)
    copyLastTo(currKey, desBlockSize, keyRight)
    copyLastTo(currKSN, desBlockSize, ksnLSB)
    

    # ===============================================
    # LSB of new key is:
    # - XOR right key with current KSN iteration,
    # - encrypt with left key
    # - XOR with right key
    # ===============================================
    msg = keyRight
    applyWith(msg, ksnLSB,`xor`)
    cipher = newDesCipher(keyLeft)
    cipher.encrypt(msg, nextKeyRight)
    applyWith(nextKeyRight, keyRight, `xor`)
    copyTo(nextKeyRight, currKey, desBlockSize) #apply back to currKey[desBlockSize .. ^1]

    # ===============================================
    # MSB of new key is as above but the input key is
    # C0C0C0C000000000 masked
    # ===============================================
    applyWith(keyLeft, ipekMask,`xor`)
    applyWith(keyRight, ipekMask,`xor`)

    msg = keyRight
    applyWith(msg, ksnLSB,`xor`)
    cipher = newDesCipher(keyLeft)
    cipher.encrypt(msg, nextKeyLeft)
    applyWith(nextKeyLeft, keyRight, `xor`) 
    copyTo(nextKeyLeft, currKey) #apply back to currKey[0..desBlockSize.pred]

#----
proc createPEK*(ipek, ksn: openArray[byte]): dukptKey =
    var
        ksnAccumulator: dukptKsn

    copyTo(ksn, ksnAccumulator)
    applyWith(ksnAccumulator, ksnCounterMask, `and`)

    copyTo(ipek, result)

    # ===============================================
    # k(n+1) derived from k(n) and ksn(n)
    # where ksn(n) is ksn(n-1) with next MSB (in bits[21->0]) set
    # ksn(0) is zero-ed counter KSN
    # Ex: KSN = 9876543210E0000B, B = 1011 = (1000 | 0010 | 0001)
    #  ksn(0) = 9876543210E00000,
    #  ksn(1) = 9876543210E00008 (8 = 1000)
    #  ksn(2) = 9876543210E0000A (A = 8|0010),
    #  ksn(3) = 9876543210E0000B (B = A|0001),
    # ===============================================

    for n in (8*ksnSize) ..> ^ksnCounterBits:
        if testBit(ksn, n):
            setBit(ksnAccumulator, n)
            result.pekBlackBox(ksnAccumulator)


# -------------
proc createIPEK(bdk, ksn: openArray[byte]): dukptKey =
    var
        ipek_l: array[desBlockSize, byte]
        ipek_r: array[desBlockSize, byte]
        ksnAccumulator: dukptKsn

    copyTo(ksn, ksnAccumulator)
    applyWith(ksnAccumulator, ksnCounterMask, `and`)
    
    # left register IPEK
    var tripleDes = newDesCipher(bdk)
    tripleDes.encrypt(ksnAccumulator, ipek_l, modeCBC)

    # prepare the key for the right register IPEK
    var keyMasked = mapWith(bdk, ipekMask, `xor`)

    tripleDes = newDesCipher(keyMasked)
    tripleDes.encrypt(ksnAccumulator, ipek_r, modeCBC)

    copyTo(ipek_l, result, 0)
    copyTo(ipek_r, result, desBlockSize)

#--------------

type
    dukptCipherObj = object
        pek: dukptKey
        # TODO future keys array to discard pek
        crypter*: desCipher # TODO make it public and implement MAC, encrypt, decrypt operations
        ksn: dukptKsn # current KSN; future increment API

    dukptCipher* = ref dukptCipherObj 
    
#---
proc restrict*(cipher: dukptCipher, useSingleDes: bool = true) =
    ## Enforces single DES key operations
    ## Most useful for particular MAC and other encryption types
    cipher.crypter.restrict(true)

#---
proc selectKey*(cipher: var dukptCipher, variant: keyVariant) =
    var maskKey = cipher.pek

    case variant
    of kvData:
        applyWith(maskKey, dataMask, `xor`)
        var c = newDesCipher(maskKey)
        c.encrypt(maskKey, maskKey, modeECB)
    of kvDataSimple:
        applyWith(maskKey, dataMask, `xor`)
    of kvPin:
        applyWith(maskKey, pinMask, `xor`)
    of kvMacReq:
        applyWith(maskKey, mReqMask, `xor`)
    of kvMacReply:
        applyWith(maskKey, mRspMask, `xor`)

    cipher.crypter = newDesCipher(maskKey)


#---
proc newDukptCipher*(key, ksn: openArray[byte], isBDK: bool = true): dukptCipher =

    doAssert(key.len == 2 * desBlockSize, "DUKPT Key not desBlockSize multiple:" & $key.len)
    doAssert(ksn.len == ksnSize, "KSN wrong size:" & $ksn.len)
        
    new(result)
    
    if isBDK:
        result.pek = createPEK(createIPEK(key, ksn), ksn) # derive IPEK from BDK=key
    else:
        result.pek = createPEK(key, ksn) # IPEK=key as provided
    result.selectKey(kvData)

#--- dot call on generic templates is sensitive to nesting and scope / type evaluation; 
# prefer standard call fct(param1, param2, ...)
template encrypt*(cipher: dukptCipher; src, dst: typed; mode: blockMode = modeCBC) =
    encrypt(cipher.crypter, src, dst, mode)

template decrypt*(cipher: dukptCipher; src, dst: typed; mode: blockMode = modeCBC) =
    decrypt(cipher.crypter, src, dst, mode)

#---
template mac*(cipher: dukptCipher; src, dst: typed; version: macVersion; pad: blockPadding; enforceFullBlockPadding: bool = false) =
    mac(cipher.crypter, src, dst, version, pad, enforceFullBlockPadding)


#---
proc setIV*(cipher: dukptCipher, initVector: openArray[byte]) =
    cipher.crypter.setIV(initVector)

proc setIV*(cipher: dukptCipher, initVector: uint64)=
    cipher.crypter.setIV(initVector)
