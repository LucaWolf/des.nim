import bin, des_const, des_type
export bin, des_const, des_type

include des_core
    
proc lastBlock*(src: var seq[byte], pad: blockPadding, extraBlock: bool = false): seq[byte] =
    ## Creates a last block if src in deemed too short. The extraBlock could
    ## also enforce a full desBlockSize padding but only when the input
    ## is not already multiple of desBlocksize bytes.
    #
    ## Returns a desBlockSize byte padded sequence. A blank sequence is returned if
    ## padding is not required

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
proc newDesCipher*(keyUser: openArray[byte]): desCipher = 
    ## Creates a new single des cipher with the provided key. 
    ## Ther key must be exact *desBlockSize* in size

    if (keyUser.len != desBlockSize):
        return nil
    
    new(result)
    result.iv[0] = 0'u32
    result.iv[1] = 0'u32
    initKeys(keyUser, opEncrypt, result.keyEnc)
    initKeys(keyUser, opDecrypt, result.keyDec)
    
#---------
proc setIV*[T: desCipher|des3Cipher](cipher: T, initVector: openArray[byte]) =
    if initVector.len != desBlockSize:
        raise newException(RangeError, "IV not block")

    discard initVector.toBinBuffer().loadHigh(cipher.iv[0], 0)
    discard initVector.toBinBuffer().loadHigh(cipher.iv[1], 4)

#---------
proc setIV*[T: desCipher|des3Cipher](cipher: T, val: uint64) =
    cipher.iv[0] = (val shr 32'u8).uint32
    cipher.iv[1] = (val and 0xFF_FF_FF_FF'u32).uint32


#---------
proc encrypt*(cipher: desCipher, src, dst: openArray[byte], mode: blockMode = modeCBC) =
    ## Encrypts the input data in the *mode* chaining mode: currently only ECB and CBC
    ## are supported. The input is only processed for a multiple of *desBlockSize* bytes
    ## length `n`, the rest is ignored; use the *lastBlock* to hadle the input remainder.
    ## The output is placed in *dst* sequence that must have at least
    ## same length as `n` (processed length of input)
    ##
    ## Example:
    ## .. code-block:: Nim
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
        refSrc = refSrc[desBlockSize .. ^1]
        refDst = refDst[desBlockSize .. ^1]

#---------
proc decrypt*(cipher: desCipher, src, dst: openArray[byte], mode: blockMode = modeCBC) =
    ## Decrypts the input data in the *mode* chaining mode: currently only ECB and CBC
    ## are supported. The input must have the lenght as multiple of *desBlockSize* bytes
    ## The output is placed in *dst* sequence that must have at least
    ## same length as the input.
    
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
        refSrc = refSrc[desBlockSize .. ^1]
        refDst = refDst[desBlockSize .. ^1]
    