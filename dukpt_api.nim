import strutils, sequtils
import des_api, dukpt_const
export dukpt_const

#----
proc pekBlackBox(currKey: var dukptKey, currKSN: dukptKsn) =

    var
        keyLeft, keyRight: desKey # copies
        msg, ksnLSB: desKey
        nextKeyLeft = currKey.toBinBuffer()[0..<desBlockSize] # direct output
        nextKeyRight = currKey.toBinBuffer()[desBlockSize .. ^1]
        cipher: desCipher
        
    copyMem(addr keyLeft[0],  addr currKey[0],            desBlockSize)
    copyMem(addr keyRight[0], addr currKey[desBlockSize], desBlockSize)
    copyMem(addr ksnLSB[0], unsafeaddr currKSN[2], desBlockSize)

    # ===============================================
    # LSB of new key is:
    # - XOR right key with current KSN iteration,
    # - encrypt with left key
    # - XOR with right key
    # ===============================================
    msg = keyRight
    msg.applyWith(ksnLSB,`xor`)
    cipher = newDesCipher(keyLeft)
    cipher.encrypt(msg, nextKeyRight)
    nextKeyRight.applyWith(keyRight, `xor`)

    # ===============================================
    # MSB of new key is as above but the input key is
    # C0C0C0C000000000 masked
    # ===============================================
    keyLeft.applyWith(ipekMask,`xor`)
    keyRight.applyWith(ipekMask,`xor`)

    msg = keyRight
    msg.applyWith(ksnLSB,`xor`)
    cipher = newDesCipher(keyLeft)
    cipher.encrypt(msg, nextKeyLeft)
    nextKeyLeft.applyWith(keyRight, `xor`)

#----
proc createPEK*(ipek, ksn: openArray[byte]): dukptKey =
    var
        ksnAccumulator: dukptKsn

    copyMem(addr ksnAccumulator[0], unsafeAddr ksn[0], ksnSize)
    ksnAccumulator.applyWith(ksnCounterMask, `and`)

    copyMem(addr result[0], unsafeAddr ipek[0], 2*desBlockSize)

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

    for n in (8*ksnSize - counter_bits) .. <(8*ksnSize):
        if testBit(ksn, n):
            setBit(ksnAccumulator, n)
            result.pekBlackBox(ksnAccumulator)


# -------------
proc createIPEK(bdk, ksn: openArray[byte]): dukptKey =
    var
        ipek_l: array[desBlockSize, byte]
        ipek_r: array[desBlockSize, byte]
        ksnAccumulator: dukptKsn

    copyMem(addr ksnAccumulator[0], unsafeAddr ksn[0], ksnSize)
    ksnAccumulator.applyWith(ksnCounterMask, `and`)
    
    # left register IPEK
    var tripleDes = newDesCipher(bdk)
    tripleDes.encrypt(ksnAccumulator, ipek_l, modeCBC)

    # prepare the key for the right register IPEK
    var keyMasked = mapWith(bdk, ipekMask, `xor`)

    tripleDes = newDesCipher(keyMasked)
    tripleDes.encrypt(ksnAccumulator, ipek_r, modeCBC)

    copyMem(addr result[0],            addr ipek_l[0], desBlockSize)
    copyMem(addr result[desBlockSize], addr ipek_r[0], desBlockSize)

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
    var maskKey: dukptKey

    copyMem(addr maskKey[0], addr cipher.pek[0], maskKey.len)

    case variant
    of kvData:
        maskKey.applyWith(dataMask, `xor`)
        var c = newDesCipher(maskKey)
        c.encrypt(maskKey, maskKey, modeECB)
    of kvDataSimple:
        maskKey.applyWith(dataMask, `xor`)
    of kvPin:
        maskKey.applyWith(pinMask, `xor`)
    of kvMacReq:
        maskKey.applyWith(mReqMask, `xor`)
    of kvMacReply:
        maskKey.applyWith(mRspMask, `xor`)

    cipher.crypter = newDesCipher(maskKey)


#---
proc newDukptCipher*(bdk, ksn: openArray[byte]): dukptCipher =

    if bdk.len != 2 * desBlockSize:
        raise newException(RangeError, "BDK not desBlockSize multiple:" & $bdk.len)

    if ksn.len != ksnSize:
        raise newException(RangeError, "KSN wrong size:" & $ksn.len)
        
    new(result)
    
    result.pek = createPEK(createIPEK(bdk, ksn), ksn)
    result.selectKey(kvData)
    
#---
template encrypt*(cipher: dukptCipher; src, dst: typed; mode: blockMode = modeCBC) =
    cipher.crypter.encrypt(src, dst, mode)

template decrypt*(cipher: dukptCipher; src, dst: typed; mode: blockMode = modeCBC) =
    cipher.crypter.decrypt(src, dst, mode)

#---
template mac*(cipher: dukptCipher; src, dst: typed; version: macVersion; pad: blockPadding; enforceFullBlockPadding: bool = false) =
    cipher.crypter.mac(src, dst, version, pad, enforceFullBlockPadding)


#---
proc setIV*(cipher: dukptCipher, initVector: openArray[byte]) =
    cipher.crypter.setIV(initVector)

proc setIV*(cipher: dukptCipher, initVector: uint64)=
    cipher.crypter.setIV(initVector)
