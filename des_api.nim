import bin, des_const, des_type
export bin, des_const, des_type

include des_core
    
#---
proc lastBlock*(src, dst: binBuffer; pad: blockPadding; extraBlock: bool): bool =
    ## Formats the *dst* as the paddded last chunk of *src* if deemed too short. 
    ## The *extraBlock* could enforce a full desBlockSize padding but only when the input
    ## is already multiple of desBlocksize bytes.
    ##
    ## A blank sequence and false is returned if padding is not required
    if (dst.len != desBlockSize):
        raise newException(RangeError, "Lastblock too short")

    var n = src.len and <desBlockSize # i.e. mod 8
    var padLen = desBlockSize - n

    if padLen == desBlockSize and extraBlock == false:
        padLen = 0

    if padLen != 0:
        if padLen != 8:
            copyMem(addr dst[0], addr src[len(src) - n], desBlockSize)
        
        result = true
        # fill in the rest of bytes to the desired scheme
        case pad
            of padPKCS5:
                for i in (desBlockSize - padLen) .. <desBlockSize:
                    dst[i] = padLen.byte
            of padX923:
                dst[^1] = padLen.byte
            of padISO7816:
                dst[^padLen] = 0x80'u8
            else:
                discard # leave zeros as if padZero
    else:
        result = false

proc lastBlock*(src, dst: var openArray[byte]; pad: blockPadding; extraBlock: bool): bool =
    var
        refSrc = src.toBinBuffer()
        refDst = dst.toBinBuffer()
    
    result = lastBlock(refSrc, refDst, pad, extraBlock)

proc lastBlock*(src: var openArray[byte]; dst: binBuffer; pad: blockPadding; extraBlock: bool): bool =
    var
        refSrc = src.toBinBuffer()
    
    result = lastBlock(refSrc, dst, pad, extraBlock)

proc lastBlock*(src: binBuffer; dst: var openArray[byte]; pad: blockPadding; extraBlock: bool): bool =
    var
        refDst = dst.toBinBuffer()
    
    result = lastBlock(src, refDst, pad, extraBlock)


#---------
proc newDesCipher*(initialKey: openArray[byte]): desCipher = 
    ## Creates a cipher for triple des operations.
    ## The length of *initialKey* must be exact one, double or triple of desKey
    var
        k1, k2, k3: desKey

    case initialKey.len
    of desBlockSize:
        copyMem(addr k1[0], unsafeAddr initialKey[0], desBlockSize)
    of 2 * desBlockSize:
        copyMem(addr k1[0], unsafeAddr initialKey[0], desBlockSize)
        copyMem(addr k2[0], unsafeAddr initialKey[desBlockSize], desBlockSize)
    of 3 * desBlockSize:
        copyMem(addr k1[0], unsafeAddr initialKey[0], desBlockSize)
        copyMem(addr k2[0], unsafeAddr initialKey[desBlockSize], desBlockSize)
        copyMem(addr k3[0], unsafeAddr initialKey[2*desBlockSize], desBlockSize)
    else:
        raise newException(RangeError, "Key not desBlockSize multiple:" & $initialKey.len)
    
    new(result)
    result.iv[0] = 0'u32
    result.iv[1] = 0'u32
    result.restricted = true
    result.keyIsSingle = true

    # enc keys
    initKeys(k1, opEncrypt, result.keyEnc[0])
    initKeys(k1, opDecrypt, result.keyDec[2]) # dec keys are used in reversed order
    
    if initialKey.len > desBlockSize:
        initKeys(k2, opDecrypt, result.keyEnc[1])
        initKeys(k2, opEncrypt, result.keyDec[1])
        result.restricted = false
        result.keyIsSingle = false

    if initialKey.len > 2*desBlockSize:
        initKeys(k3, opEncrypt, result.keyEnc[2])
        initKeys(k3, opDecrypt, result.keyDec[0])
    else: # this also covers single DES decryption
        result.keyEnc[2] = result.keyEnc[0]
        result.keyDec[0] = result.keyDec[2]
            
    # NOTE: weak keys is the responsability of and should be tested by the API user

#---------
proc setIV*(cipher: desCipher, initVector: openArray[byte]) =
    ## Sets the initialisation vector to the *initVector* input (which must be 
    ## exact *desBlockSize* in length).
    
    if initVector.len != desBlockSize:
        raise newException(RangeError, "IV not block")

    discard initVector.toBinBuffer().loadHigh(cipher.iv[0], 0)
    discard initVector.toBinBuffer().loadHigh(cipher.iv[1], 4)

#---------
proc setIV*(cipher: desCipher, initVector: uint64) =
    ## Sets the initialisation vector to the *initVector* input (which is treated
    ## as big endian format). Use this to quickly reset the IV for a new session
    ## of the same cipher object.
    ##
    ## Example:
    ##
    ## .. code-block::
    ##      des.setIV(0'u64)
    
    cipher.iv[0] = (initVector shr 32'u8).uint32
    cipher.iv[1] = (initVector and 0xFF_FF_FF_FF'u32).uint32

proc restrict*(cipher: desCipher, useSingleDes: bool = true) =
    # only applicable to des2 and des3
    if cipher.keyIsSingle == false:
        cipher.restricted = useSingleDes

#---------
proc encrypt*(cipher: desCipher; src, dst: binBuffer; mode: blockMode = modeCBC) =
    ## Encrypts the *src* input data in the *mode* chaining mode: currently only ECB and CBC
    ## are supported. The input is only processed for `n` bytes as multiple of *desBlockSize*. 
    ## The rest is ignored but you could use the *lastBlock* to hadle the input remainder.
    ## The *dst* output sequence must have at least `n` bytes (processed length of input)
    ## Last block not processed: you may want to preserve the IV when manually chaining !!!
    ##
    ## Example:
    ##
    ## .. code-block::
    ##      des.encrypt(dataClear, dataEnc, modeECB)
    ##      var dataLast = dataClear.lastBlock(padISO7816, true)
    ##      if dataLast != nil:
    ##          des.encrypt(dataLast, lastEnc, modeECB)
    var
        refSrc = src
        refDst = dst

    if refDst.len < (refSrc.len div desBlockSize) * desBlockSize:
        raise newException(RangeError, "Output too short")
    
    # this excludes the last incomplete chunk if any
    while refSrc.len >= desBlockSize:
        cipher.cryptBlock( refSrc[0 .. <desBlockSize], refDst[0 .. <desBlockSize], mode, opEncrypt)
        refSrc = refSrc[desBlockSize .. <refSrc.len]
        refDst = refDst[desBlockSize .. <refDst.len]

proc encrypt*(cipher: desCipher; src, dst: openArray[byte]; mode: blockMode = modeCBC) =    
    var
        refSrc = src.toBinBuffer()
        refDst = dst.toBinBuffer()

    encrypt(cipher, refSrc, refDst, mode)
   
proc encrypt*(cipher: desCipher; src: openArray[byte]; dst: binBuffer; mode: blockMode = modeCBC) =    
    var
        refSrc = src.toBinBuffer()

    encrypt(cipher, refSrc, dst, mode)

proc encrypt*(cipher: desCipher; src: binBuffer; dst: openArray[byte]; mode: blockMode = modeCBC) =    
    var
        refDst = dst.toBinBuffer()

    encrypt(cipher, src, refDst, mode)

#---------
proc decrypt*(cipher: desCipher; src, dst: binBuffer, mode: blockMode = modeCBC) =
    ## Decrypts the input data in the *mode* chaining mode: currently only ECB and CBC
    ## are supported. The *src* input must have the length as multiple of *desBlockSize* bytes
    ## The *dst* output sequence must have at least the same length as the input.
    ## Last block not processed: you may want to preserve the IV when manually chaining !!!
    var
        refSrc = src
        refDst = dst

    if (src.len and <desBlockSize) != 0: # mod 8
        raise newException(RangeError, "Input incomplete block")
    if refDst.len < refSrc.len:
        raise newException(RangeError, "Output too short")
    
    # this excludes the last incomplete chunk if any
    while refSrc.len >= desBlockSize:
        cipher.cryptBlock(refSrc[0 .. <desBlockSize], refDst[0 .. <desBlockSize], mode, opDecrypt)
        # TODO instead of allocating a new slice, perhaps implement a `view` shift?
        refSrc = refSrc[desBlockSize .. <refSrc.len]
        refDst = refDst[desBlockSize .. <refDst.len]

proc decrypt*(cipher: desCipher; src, dst: openArray[byte]; mode: blockMode = modeCBC) =    
    var
        refSrc = src.toBinBuffer()
        refDst = dst.toBinBuffer()

    decrypt(cipher, refSrc, refDst, mode)

proc decrypt*(cipher: desCipher; src: openArray[byte]; dst: binBuffer; mode: blockMode = modeCBC) =    
    var
        refSrc = src.toBinBuffer()

    decrypt(cipher, refSrc, dst, mode)

proc decrypt*(cipher: desCipher; src: binBuffer; dst: openArray[byte]; mode: blockMode = modeCBC) =    
    var
        refDst = dst.toBinBuffer()

    decrypt(cipher, src, refDst, mode)


#------- MAC is always CBC
proc mac*(cipher: desCipher; src, dst: binBuffer; version: macVersion; pad: blockPadding, enforceFullBlockPadding: bool = false) =
    ## MAC according to the padding and the X9 *version*. Input *src* can be
    ## an incomplete block (non multiple of 8 bytes), in which case the padding scheme applies
    ## Enforcing a full block padding (if input not complete) is also possible via *enforceFullBlockPadding*
    ## Output is placed in the provided *dst* which must be of desBlockSize capacity
    ##
    ##Do not use for data straeams; implement a similar routine if desired
    
    # input could have an incomplete block as we use the padding param,
    # test only only the output
    if (dst.len != desBlockSize):
        raise newException(RangeError, "MAC holder too short")
    
    var
        refSrc = src
        dataLast: desBlock
        hasPadding = src.lastBlock(dataLast, pad, enforceFullBlockPadding)
        endSize: int = desBlocksize

    if version == macX9_19:
        cipher.restrict(true)
        if  hasPadding == false:
            endSize = 2*desBlocksize

    while refSrc.len >= endSize:
        cipher.cryptBlock(refSrc[0 .. <desBlockSize], dst, modeCBC, opEncrypt)
        # TODO instead of allocating a new slice, perhaps implement a `view` shift?
        refSrc = refSrc[desBlockSize .. <refSrc.len]
    
    # last block and future operations reset to full key
    cipher.restrict(false)
    
    if hasPadding:
        cipher.cryptBlock(dataLast.toBinBuffer(), dst, modeCBC, opEncrypt)
    else:
        if version == macX9_19:
            # full blocks and last one needs 3DES
            cipher.cryptBlock(refSrc[0 .. <desBlockSize], dst, modeCBC, opEncrypt)
            

proc mac*(cipher: desCipher; src, dst: openArray[byte]; version: macVersion; pad: blockPadding; enforceFullBlockPadding: bool = false) = 
    var
        refSrc = src.toBinBuffer()
        refDst = dst.toBinBuffer()

    mac(cipher, refSrc, refDst, version, pad, enforceFullBlockPadding)
   
proc mac*(cipher: desCipher; src: openArray[byte]; dst: binBuffer; version: macVersion; pad: blockPadding, enforceFullBlockPadding: bool = false) =
    var
        refSrc = src.toBinBuffer()

    mac(cipher, refSrc, dst, version, pad, enforceFullBlockPadding)

proc mac*(cipher: desCipher; src: binBuffer; dst: openArray[byte]; version: macVersion; pad: blockPadding, enforceFullBlockPadding: bool = false) =
    var
        refDst = dst.toBinBuffer()

    mac(cipher, src, refDst, version, pad, enforceFullBlockPadding)


    
    
    
