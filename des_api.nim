import bin, des_const, des_type
export bin, des_const, des_type

include des_core
    
proc lastBlock*(src: var seq[byte], pad: blockPadding, extraBlock: bool = false): seq[byte] =
    ## Creates a full block containing the paddded last of input data if *src* in deemed too short. 
    ## The *extraBlock* could enforce a full desBlockSize padding but only when the input
    ## is already multiple of desBlocksize bytes.
    ##
    ## A blank sequence is returned if padding is not required

    var padLen = desBlockSize - src.len mod desBlockSize

    if padLen == desBlockSize and extraBlock == false:
        padLen = 0

    if padLen != 0:
        result = newSeq[byte](desBlockSize) # zero filled by constructor
        if padLen != 8:
            # note slice of src would be nil and bin library is not so resilient..hence the validation
            copy(result.toBinBuffer(), src[^(desBlockSize - padLen)..^1].toBinBuffer()) # src cannot be openarray
        
        # fill in the rest of bytes to desired scheme
        case pad
            of padPKCS5:
                for i in desBlockSize - padLen..<desBlockSize:
                    result[i] = padLen.byte
            of padX923:
                result[^1] = padLen.byte
            of padISO7816:
                result[^padLen] = 0x80'u8
            else:
                discard # leave zeros as if padZero
    else:
        discard

#---------
proc newDesCipher*(initialKey: openArray[byte]): desCipher = 
    ## Creates a cipher for single des operations.
    ## The length of *initialKey* must be exact *desBlockSize* bytes

    if (initialKey.len != desBlockSize):
        raise newException(RangeError, "Key not desBlockSize")
    
    new(result)
    result.iv[0] = 0'u32
    result.iv[1] = 0'u32
    initKeys(initialKey, opEncrypt, result.keyEnc)
    initKeys(initialKey, opDecrypt, result.keyDec)
    
#---------
proc newDes3Cipher*(initialKey: seq[byte]): des3Cipher = 
    ## Creates a cipher for triple des operations.
    ## The length of *initialKey* must be exact twice or triple *desBlockSize* bytes

    
    if (initialKey.len != 2*desBlockSize) and (initialKey.len != 3*desBlockSize):
        raise newException(RangeError, "Key not desBlockSize multiple:" & $initialKey.len)
    
    new(result)
    result.iv[0] = 0'u32
    result.iv[1] = 0'u32
    
    # enc keys
    initKeys(initialKey[0 .. <desBlockSize], opEncrypt, result.keyEnc[0])
    initKeys(initialKey[desBlockSize .. <(2*desBlockSize)], opDecrypt, result.keyEnc[1])
    
    if initialKey.len == 2*desBlockSize:
        result.keyEnc[2] = result.keyEnc[0]
    else:
        initKeys(initialKey[(2*desBlockSize) .. <(3*desBlockSize)], opEncrypt, result.keyEnc[2])

    # dec keys are used in reversed order
    initKeys(initialKey[0 .. <desBlockSize], opDecrypt, result.keyDec[2])
    initKeys(initialKey[desBlockSize .. <(2*desBlockSize)], opEncrypt, result.keyDec[1])
    
    if initialKey.len == 2*desBlockSize:
        result.keyDec[0] = result.keyDec[2]
    else:
        initKeys(initialKey[(2*desBlockSize) .. <(3*desBlockSize)], opDecrypt, result.keyDec[0])
            
    # NOTE: weak keys is the responsability of and should be tested by the API user

#---------
proc setIV*[T: desCipher|des3Cipher](cipher: T, initVector: openArray[byte]) =
    ## Sets the initialisation vector to the *initVector* input (which must be 
    ## exact *desBlockSize* in length).
    
    if initVector.len != desBlockSize:
        raise newException(RangeError, "IV not block")

    discard initVector.toBinBuffer().loadHigh(cipher.iv[0], 0)
    discard initVector.toBinBuffer().loadHigh(cipher.iv[1], 4)

#---------
proc setIV*[T: desCipher|des3Cipher](cipher: T, initVector: uint64) =
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


#---------
proc encrypt*[T: desCipher|des3Cipher](cipher: T; src, dst: openArray[byte]; mode: blockMode = modeCBC) =
    ## Encrypts the *src* input data in the *mode* chaining mode: currently only ECB and CBC
    ## are supported. The input is only processed for `n` bytes as multiple of *desBlockSize*. 
    ## The rest is ignored but you could use the *lastBlock* to hadle the input remainder.
    ## The *dst* output sequence must have at least `n` bytes (processed length of input)
    ##
    ## Example:
    ##
    ## .. code-block::
    ##      des.encrypt(dataClear, dataEnc, modeECB)
    ##      var dataLast = dataClear.lastBlock(padISO7816, true)
    ##      if dataLast != nil:
    ##          des.encrypt(dataLast, lastEnc, modeECB)
    
    var
        refSrc = src.toBinBuffer()
        refDst = dst.toBinBuffer()
        
    if refDst.len < (refSrc.len div desBlockSize) * desBlockSize:
        raise newException(RangeError, "Output too short")
    
    # this excludes the last incomplete chunk if any
    while refSrc.len >= desBlockSize:
        cryptBlock(cipher, refSrc[0 .. <desBlockSize], refDst[0 .. <desBlockSize], mode, opEncrypt)
        # !!!STRANGE!!! [desBlockSize .. ^1] => why has this stopped working after introducing generics?
        refSrc = refSrc[desBlockSize .. <refSrc.len]
        refDst = refDst[desBlockSize .. <refDst.len]

#---------
proc decrypt*[T: desCipher|des3Cipher](cipher: T; src, dst: openArray[byte], mode: blockMode = modeCBC) =
    ## Decrypts the input data in the *mode* chaining mode: currently only ECB and CBC
    ## are supported. The *src* input must have the length as multiple of *desBlockSize* bytes
    ## The *dst* output sequence must have at least the same length as the input.
    
    var
        refSrc = src.toBinBuffer()
        refDst = dst.toBinBuffer()
        
    if (src.len mod 8) != 0:
        raise newException(RangeError, "Input incomplete block")
    if refDst.len < refSrc.len:
        raise newException(RangeError, "Output too short")
    
    # this excludes the last incomplete chunk if any
    while refSrc.len >= desBlockSize:
        cryptBlock(cipher, refSrc[0 .. <desBlockSize], refDst[0 .. <desBlockSize], mode, opDecrypt)
        # !!!STRANGE!!! [desBlockSize .. ^1] => why has this stopped working after introducing generics?
        refSrc = refSrc[desBlockSize .. <refSrc.len]
        refDst = refDst[desBlockSize .. <refDst.len]
    