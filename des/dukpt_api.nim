import des_api, dukpt_const
export dukpt_const

#----
proc pekBlackBox(currKey: var dukptKey, currKSN: dukptKsn) =

    var cipher: desCipher
    var keyLeft = currKey[0 ..> desBlockSize]
    var keyRight = currKey[desBlockSize ..> desBlockSize]
    var ksnLSB = currKSN[^desBlockSize .. ^1]

    # ===============================================
    # LSB of new key is:
    # - XOR right key with current KSN iteration,
    # - encrypt with left key
    # - XOR with right key
    # ===============================================
    var msg = keyRight
    applyWith(msg, ksnLSB,`xor`)
    cipher = newDesCipher(keyLeft)
    cipher.encrypt(msg, msg) # in place encrypt safe
    applyWith(msg, keyRight, `xor`)    
    currKey[^desBlockSize .. ^1] = msg # apply back to currKey[desBlockSize .. ^1]

    # ===============================================
    # MSB of new key is as above but the input key is
    # C0C0C0C000000000 masked
    # ===============================================
    applyWith(keyLeft, ipekMask,`xor`)
    applyWith(keyRight, ipekMask,`xor`)

    msg = keyRight
    applyWith(msg, ksnLSB,`xor`)
    cipher = newDesCipher(keyLeft)
    cipher.encrypt(msg, msg) # in place encrypt safe
    applyWith(msg, keyRight, `xor`) 
    currKey[0 ..> desBlockSize] = msg # apply back to currKey[0..desBlockSize.pred]

#----
proc createPEK*(ipek: dukptKey, ksn: dukptKsn): dukptKey =
    
    var ksnAccumulator = ksn

    applyWith(ksnAccumulator, ksnCounterMask, `and`)
    result = ipek

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

    for n in countdown(20,0):
        if testBit(ksn, n):
            setBit(ksnAccumulator, n)
            result.pekBlackBox(ksnAccumulator)


# -------------
proc createIPEK(bdk: dukptKey, ksn: dukptKsn): dukptKey =
    var
        ipek_l: array[desBlockSize, byte]
        ipek_r: array[desBlockSize, byte]
        ksnAccumulator = ksn
        keyMasked = bdk

    applyWith(ksnAccumulator, ksnCounterMask, `and`)
    
    # left register IPEK
    var cipher = newDesCipher(bdk)
    encrypt(cipher, ksnAccumulator, ipek_l, modeCBC)

    # prepare the key for the right register IPEK
    applyWith(keyMasked, ipekMask, `xor`)

    cipher = newDesCipher(keyMasked)
    encrypt(cipher, ksnAccumulator, ipek_r, modeCBC)

    result[0 ..> desBlockSize] = ipek_l
    result[desBlockSize ..> desBlockSize] = ipek_r


#-------------- public API --------------
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

    doAssert(key.len == 2 * desBlockSize, "DUKPT Key not 2DES:" & $key.len)
    doAssert(ksn.len == ksnSize, "KSN wrong size:" & $ksn.len)

    # need converting frm the openaray input into array
    var
       dkey: dukptKey
       dksn: dukptKsn

    key.copyTo(dkey)
    ksn.copyTo(dksn)
        
    new(result)
    
    if isBDK:
        result.pek = createPEK(createIPEK(dkey, dksn), dksn) # derive IPEK from BDK=key
    else:
        result.pek = createPEK(dkey, dksn) # IPEK=key as provided
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
