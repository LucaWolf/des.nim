import sequtils
import bin, des_const, des_type
export bin, des_const, des_type

include des_core
    
proc lastBlock*(src: string; dst: var desBlock; pad: blockPadding; extraBlock: bool): bool =

    var n = src.len and <desBlockSize # i.e. mod 8
    var padLen = desBlockSize - n

    if padLen == desBlockSize and extraBlock == false:
        padLen = 0

    if padLen != 0:
        result = true
        dst.applyWith(dst, `xor`) # content reset
        
        if padLen != 8:
            dst[0..<n] = map(src[^n..^1], proc(c: char): byte = ord(c))

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

#---
proc lastBlock*(src: openArray[byte]; dst: var desBlock; pad: blockPadding; extraBlock: bool): bool =
    ## Formats the *dst* as the paddded last chunk of *src* if deemed too short. 
    ## The *extraBlock* could enforce a full desBlockSize padding but only when the input
    ## is already multiple of desBlocksize bytes.
    ##
    ## A blank sequence and false is returned if padding is not required

    var n = src.len and <desBlockSize # i.e. mod 8
    var padLen = desBlockSize - n

    if padLen == desBlockSize and extraBlock == false:
        padLen = 0

    if padLen != 0:
        result = true
        dst.applyWith(dst, `xor`) # content reset
        
        if padLen != 8:
            src.copyLastTo(n, dst)
        
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

#---------
proc newDesCipher*(initialKey: openArray[byte]): desCipher = 
    ## Creates a cipher for triple des operations.
    ## The length of *initialKey* must be exact one, double or triple of desKey
    var
        k1, k2, k3: desKey

    case initialKey.len
    of desBlockSize:
        initialKey.copyTo(k1)
    of 2 * desBlockSize:
        initialKey.copyTo(k1)
        initialKey.copyTo(desBlockSize .. 2*desBlockSize, k2)
    of 3 * desBlockSize:
        initialKey.copyTo(k1)
        initialKey.copyTo(desBlockSize .. 2*desBlockSize, k2)
        initialKey.copyTo(2*desBlockSize .. 3*desBlockSize, k3)
    else:
        doAssert(false, "Key not desBlockSize multiple:" & $initialKey.len)
    
    new(result)
    result.iv = 0
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
    
    doAssert(initVector.len == desBlockSize, "IV not block")

    cipher.iv = load64BE(initVector)
    

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
    
    cipher.iv = initVector.int64

proc restrict*(cipher: desCipher, useSingleDes: bool = true) =
    # only applicable to des2 and des3
    if cipher.keyIsSingle == false:
        cipher.restricted = useSingleDes

#---------
proc encrypt*(cipher: desCipher; src:openArray[byte]; dst: var openArray[byte]; mode: blockMode = modeCBC) =
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
    ##      var padBlock = dataClear.lastBlock(padISO7816, true)
    ##      if padBlock != nil:
    ##          des.encrypt(padBlock, lastEnc, modeECB)
    var
        pos = 0
        n = src.len div desBlocksize
        v, d: int64

    doAssert(n*desBlockSize <= dst.len, "Encrypt holder too short")
    
    # this excludes the last incomplete chunk if any
    for i in 0 .. <n:
        v = load64BE(src, pos)
        d = cipher.cryptBlock(v, mode, opEncrypt)
        store64BE(d, dst, pos)
        inc(pos, desBlockSize)

proc encrypt*(cipher: desCipher; src: string; dst: var openArray[byte]; mode: blockMode = modeCBC) =
    var
        pos = 0
        n = src.len div desBlocksize
        v, d: int64

    doAssert(n*desBlockSize <= dst.len, "Encrypt holder too short")
    
    # this excludes the last incomplete chunk if any
    for i in 0 .. <n:
        v = load64BE(src, pos)
        d = cipher.cryptBlock(v, mode, opEncrypt)
        store64BE(d, dst, pos)
        inc(pos, desBlockSize)

#---------
proc decrypt*(cipher: desCipher; src: openArray[byte]; dst: var openArray[byte]; mode: blockMode = modeCBC) =
    ## Decrypts the input data in the *mode* chaining mode: currently only ECB and CBC
    ## are supported. The *src* input must have the length as multiple of *desBlockSize* bytes
    ## The *dst* output sequence must have at least the same length as the input.
    ## Last block not processed: you may want to preserve the IV when manually chaining !!!
    var
        pos = 0
        n = src.len div desBlocksize
        v, d: int64

    # mod 8 is: val and 0x07
    doAssert((src.len and <desBlockSize) == 0, "Input incomplete block")
    doAssert(src.len <= dst.len, "Decrypt holder too short")
    
    # this excludes the last incomplete chunk if any
    for i in 0 .. <n:
        v = load64BE(src, pos)
        d = cipher.cryptBlock(v, mode, opDecrypt)
        store64BE(d, dst, pos)
        inc(pos, desBlockSize)

proc decrypt*(cipher: desCipher; src: string; dst: var openArray[byte]; mode: blockMode = modeCBC) =
    var
        pos = 0
        n = src.len div desBlocksize
        v, d: int64

    # mod 8 is: val and 0x07
    doAssert((src.len and <desBlockSize) == 0, "Input incomplete block")
    doAssert(src.len <= dst.len, "Decrypt holder too short")
    
    # this excludes the last incomplete chunk if any
    for i in 0 .. <n:
        v = load64BE(src, pos)
        d = cipher.cryptBlock(v, mode, opDecrypt)
        store64BE(d, dst, pos)
        inc(pos, desBlockSize)


#------- MAC is always CBC
proc mac*(cipher: desCipher; src :openArray[byte]; dst: var desBlock; version: macVersion; pad: blockPadding, enforceFullBlockPadding: bool = false) =
    ## MAC according to the padding and the X9 *version*. Input *src* can be
    ## an incomplete block (non multiple of 8 bytes), in which case the padding scheme applies
    ## Enforcing a full block padding (if input not complete) is also possible via *enforceFullBlockPadding*
    ## Output is placed in the provided *dst* which must be of desBlockSize capacity
    ##
    ## Do not use for data streams; implement a similar routine if desired
    
    # input could have an incomplete block as we use the padding param,
    # test only only the output
    doAssert(desBlockSize <= dst.len, "MAC holder too short")
    
    var
        n = src.len div desBlocksize
        padBlock: desBlock
        pos = 0
        s, d: int64

    let hasPadding = src.lastBlock(padBlock, pad, enforceFullBlockPadding)
    
    if version == macX9_19:
        cipher.restrict(true)
        if  hasPadding == false:
            dec(n)

    for i in 0 .. <n:
        s = load64BE(src, pos)
        d = cipher.cryptBlock(s, modeCBC, opEncrypt)
        inc(pos, desBlockSize)
    
    # last block and future operations reset to full key
    cipher.restrict(false)
    
    if hasPadding:
        s = load64BE(padBlock, 0)
        d = cipher.cryptBlock(s, modeCBC, opEncrypt)
    else:
        if version == macX9_19:
            # full blocks and last one needs 3DES
            pos = src.len - desBlocksize
            s = load64BE(src, pos)
            d = cipher.cryptBlock(s, modeCBC, opEncrypt)
    
    store64BE(d, dst)

proc mac*(cipher: desCipher; src :string; dst: var desBlock; version: macVersion; pad: blockPadding, enforceFullBlockPadding: bool = false) =
    doAssert(desBlockSize <= dst.len, "MAC holder too short")
    
    var
        n = src.len div desBlocksize
        padBlock: desBlock
        pos = 0
        s, d: int64

    let hasPadding = src.lastBlock(padBlock, pad, enforceFullBlockPadding)
    
    if version == macX9_19:
        cipher.restrict(true)
        if  hasPadding == false:
            dec(n)

    for i in 0 .. <n:
        s = load64BE(src, pos)
        d = cipher.cryptBlock(s, modeCBC, opEncrypt)
        inc(pos, desBlockSize)
    
    # last block and future operations reset to full key
    cipher.restrict(false)
    
    if hasPadding:
        s = load64BE(padBlock, 0)
        d = cipher.cryptBlock(s, modeCBC, opEncrypt)
    else:
        if version == macX9_19:
            # full blocks and last one needs 3DES
            pos = src.len - desBlocksize
            s = load64BE(src, pos)
            d = cipher.cryptBlock(s, modeCBC, opEncrypt)
    
    store64BE(d, dst)
