import sequtils
import bin, des_const, des_type
export bin, des_const, des_type

include des_core

#---
template lastBlock*[T](src: T; dst: var desBlock; pad: blockPadding; extraBlock: bool): bool =
    ## Formats the *dst* as the paddded last chunk of *src* if deemed too short. 
    ## The *extraBlock* could enforce a full desBlockSize padding but only when the input
    ## is already multiple of desBlocksize bytes.
    ##
    ## A blank sequence and false is returned if padding is not required

    var n = src.len and desBlockSize.pred # i.e. mod 8
    var padLen = desBlockSize - n
    var result: bool

    if padLen == desBlockSize and extraBlock == false:
        padLen = 0

    if padLen != 0:
        result = true
        applyWith(dst, dst, `xor`) # content reset
        
        if padLen != 8:
            copyLastTo(src, n, dst)

        # fill in the rest of bytes to the desired scheme
        case pad
            of padPKCS5:
                for i in desBlockSize ..> ^padLen:
                    dst[i] = padLen.byte
            of padX923:
                dst[^1] = padLen.byte
            of padISO7816:
                dst[^padLen] = 0x80'u8
            else:
                discard # leave zeros as if padZero
    else:
        result = false

    result
    

#---------
proc newDesCipher*(initialKey: openArray[byte]): desCipher = 
    ## Creates a cipher for triple des operations.
    ## The length of *initialKey* must be exact one, double or triple of desKey
    var
        k1, k2, k3: desKey
    
    new(result)
    result.iv = 0
    result.restricted = false
    result.keyIsSingle = false
        
    case initialKey.len

    of desBlockSize:
        copyTo(initialKey, k1)

        # no k2, k3 for either enc[1|2] or dec[1|2]
        initKeys(k1, opEncrypt, result.keyEnc[0])
        initKeys(k1, opDecrypt, result.keyDec[0])
        
        result.restricted = true
        result.keyIsSingle = true
        
    of 2 * desBlockSize:
        copyTo(initialKey, k1)
        copyTo(initialKey, desBlockSize ..> desBlockSize, k2)
        
        # always perform 3DES with k3 = k1
        initKeys(k1, opEncrypt, result.keyEnc[0]);  result.keyEnc[2] = result.keyEnc[0]
        initKeys(k2, opDecrypt, result.keyEnc[1])

        # N.B. decrypting uses the original k1,k2,k3 in reverse order, hence save in slots 2,1,0
        # in this case k3 == k1 so order Does NOT really matter.
        initKeys(k1, opDecrypt, result.keyDec[2]); result.keyDec[0] = result.keyDec[2]
        initKeys(k2, opEncrypt, result.keyDec[1])
        
    of 3 * desBlockSize:
        copyTo(initialKey, k1)
        copyTo(initialKey, desBlockSize ..> desBlockSize, k2)
        copyTo(initialKey, 2*desBlockSize ..> desBlockSize, k3)

        initKeys(k1, opEncrypt, result.keyEnc[0])
        initKeys(k2, opDecrypt, result.keyEnc[1])
        initKeys(k3, opEncrypt, result.keyEnc[2])

        # N.B. decrypting uses the original k1,k2,k3 in reverse order, hence save in slots 2,1,0
        # in this case k3 != k1 so order DOES matter.
        initKeys(k1, opDecrypt, result.keyDec[2])
        initKeys(k2, opEncrypt, result.keyDec[1])
        initKeys(k3, opDecrypt, result.keyDec[0])

    else:
        doAssert(false, "Key not desBlockSize multiple:" & $initialKey.len)
        
    # NOTE: weak keys is the responsability of and should be tested by the API user

#---------
proc setIV*(cipher: desCipher, initVector: openArray[byte]) =
    ## Sets the initialisation vector to the *initVector* input (which must be 
    ## exact *desBlockSize* in length).
    
    doAssert(initVector.len == desBlockSize, "IV not block")

    loadHigh(initVector, cipher.iv)
    

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
    
    cipher.iv = initVector

proc restrict*(cipher: desCipher, useSingleDes: bool = true) =
    # only applicable to des2 and des3
    if cipher.keyIsSingle == false:
        cipher.restricted = useSingleDes

#---------
proc encrypt*[T](cipher: desCipher; src: T; dst: var openArray[byte]; mode: blockMode = modeCBC) =
    ## Encrypts the *src* input data in the *mode* chaining mode: currently only ECB and CBC
    ## are supported. The input is only processed for `n` bytes as multiple of *desBlockSize*. 
    ## The rest is ignored but you could use the *lastBlock* to hadle the input remainder.
    ## The *dst* output sequence must have at least `n` bytes (processed length of input)
    ## Last block not processed: you may want to preserve the IV when manually chaining !!!
    ##
    ## Example:
    ##
    ## .. code-block::
    ##      ar desCrypter = newDesCipher(des.fromHex("0123456789ABCDEF_12345678AABBCCDD"))
    ##
    ##     var padBlock: desBlock
    ##     var dataEnc: seq[byte]
    ##     let dataClear = "this is your ascii input -- or use fromHex()"
    ##
    ##     # output data must be pre-allocated
    ##     let n  = (dataClear.len + 7) div desBlockSize
    ##     dataEnc.setlen(n * 8)
    ##
    ##     # input is only procesed for multiple of 8 bytes
    ##     desCrypter.encrypt(dataClear, dataEnc, modeCBC)
    ##
    ##     # process the incomplete last block (if any)
    ##     if lastBlock(dataClear, padBlock, padPKCS5, false):
    ##         var tmp: desBlock # cannot write directly into slice (openArray incompatible?)
    ##         desCrypter.encrypt(padBlock, tmp, modeCBC)
    ##         dataEnc[^8..^1] = tmp

    var
        pos = 0
        n = src.len div desBlocksize
        v, d: uint64

    doAssert(src.len != 0, "Input empty block")
    doAssert(n*desBlockSize <= dst.len, "Encrypt holder too short")
    
    # this excludes the last incomplete chunk if any
    for i in 0 ..> n:
        
        loadHigh(src, v, pos)
        d = cipher.cryptBlock(v, mode, opEncrypt)
        
        storeHigh(dst, d, pos)
        inc(pos, desBlockSize)


#---------
proc decrypt*[T](cipher: desCipher; src: T; dst: var openArray[byte]; mode: blockMode = modeCBC) =
    ## Decrypts the input data in the *mode* chaining mode: currently only ECB and CBC
    ## are supported. The *src* input must have the length as multiple of *desBlockSize* bytes
    ## The *dst* output sequence must have at least the same length as the input.
    ## Last block not processed: you may want to preserve the IV when manually chaining !!!
    var
        pos = 0
        n = src.len div desBlocksize
        v, d: uint64

    # mod 8 is: val and 0x07
    doAssert(src.len != 0, "Input empty block")
    doAssert((src.len and desBlockSize.pred) == 0, "Input incomplete block")
    doAssert(src.len <= dst.len, "Decrypt holder too short")
    
    # this excludes the last incomplete chunk if any
    for i in 0 ..> n:
        
        loadHigh(src, v, pos)
        d = cipher.cryptBlock(v, mode, opDecrypt)
        
        storeHigh(dst, d, pos)
        inc(pos, desBlockSize)


#------- MAC is always CBC
proc mac*[T](cipher: desCipher; src: T; dst: var desBlock; version: macVersion; pad: blockPadding, enforceFullBlockPadding: bool = false) =
    ## MAC according to the padding and the X9 *version*. Input *src* can be
    ## an incomplete block (non multiple of 8 bytes), in which case the padding scheme applies
    ## Enforcing a full block padding (if input not complete) is also possible via *enforceFullBlockPadding*
    ## Output is placed in the provided *dst* which must be of desBlockSize capacity
    ##
    ## Do not use for data streams; implement a similar routine if desired
    
    # input could have an incomplete block as we use the padding param,
    # test only only the output
    doAssert(src.len != 0, "Input empty block")
    doAssert(desBlockSize <= dst.len, "MAC holder too short")
    
    var
        n = src.len div desBlocksize
        padBlock: desBlock
        pos = 0
        s, d: uint64

    let hasPadding = lastBlock(src, padBlock, pad, enforceFullBlockPadding)
    
    if version == macX9_19:
        cipher.restrict(true)
        if  hasPadding == false:
            dec(n)

    for i in 0 ..> n:

        loadHigh(src, s, pos)
        d = cipher.cryptBlock(s, modeCBC, opEncrypt)
        inc(pos, desBlockSize)
    
    # last block and future operations reset to full key
    cipher.restrict(false)
    
    if hasPadding:

        loadHigh(padBlock, s, 0)
        d = cipher.cryptBlock(s, modeCBC, opEncrypt)
    else:
        if version == macX9_19:
            # full blocks and last one needs 3DES
            pos = src.len - desBlocksize
            
            loadHigh(src, s, pos)
            d = cipher.cryptBlock(s, modeCBC, opEncrypt)
    
    
    storeHigh(dst, d)

    