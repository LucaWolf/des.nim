import strutils, bin, des_const, des_type

#---------
proc cookey(raw: subkeys, key: var subkeys) = 
    
    for i in 0..15:
        var
            raw0 = raw[2*i]
            raw1 = raw[2*i + 1]
            k1 = addr key[2*i]
            k2 = addr key[2*i + 1]
            
        k1[] =           (raw0 and 0x00fc0000'u32) shl 6'u8
        k1[] =  k1[] or ((raw0 and 0x00000fc0'u32) shl 10'u8)
        k1[] =  k1[] or ((raw1 and 0x00fc0000'u32) shr 10'u8)
        k1[] =  k1[] or ((raw1 and 0x00000fc0'u32) shr 6'u8)        
        
        k2[] =          ((raw0 and 0x0003f000'u32) shl 12'u8)
        k2[] =  k2[] or ((raw0 and 0x0000003f'u32) shl 16'u8)
        k2[] =  k2[] or ((raw1 and 0x0003f000'u32) shr 4'u8)
        k2[] =  k2[] or  (raw1 and 0x0000003f'u32)
        

#---------
proc initKeys(keyin: openArray[byte], edf: blockOp, keyout: var subkeys) = 
    var
        s,m,n: int
        kn: subkeys
        pc1m, pcr: array[56, byte]
    
    for j in 0..<pc1m.len:
        s = pc1[j].int
        m =  s and 7
        pc1m[j] = if ((keyin[s shr 3] and maskbit[m]) == maskbit[m]): 1 else: 0

    for i in 0..15:
        m = if (edf == opDecrypt): (15 - i) shl 1  else: i shl 1
        
        n = m + 1
        kn[m] = 0
        kn[n] = 0
        
        for j in 0..27:
            s = j + totrot[i].int;
            pcr[j] = if (s < 28): pc1m[s] else: pc1m[s - 28]
        
        for j in 28..55:
            s = j + totrot[i].int;
            pcr[j] = if (s < 56): pc1m[s] else: pc1m[s - 28]
        
        for j in 0 .. <bigbyte.len:
            if (pcr[pc2[j].int] != 0'u8):
               kn[m] = kn[m] or bigbyte[j]
            
            if (pcr[pc2[j+24].int] != 0'u8):
               kn[n] = kn[n] or bigbyte[j]

    cookey(kn, keyout)
    
#---------    
proc desfunc(data: var openarray[uint32], key: var subkeys) =
    var
        work, right, left: uint32
        k1,k2,k3,k4: ptr uint32

    left = data[0]
    right = data[1]

    work = ((left shr 4)  xor right) and 0x0f0f0f0f'u32
    right = right xor work
    left = left xor (work shl 4)

    work = ((left shr 16) xor right) and 0x0000ffff'u32
    right = right xor work
    left = left xor (work shl 16)

    work = ((right shr 2)  xor left) and 0x33333333'u32
    left = left xor work
    right = right xor (work shl 2)

    work = ((right shr 8)  xor left) and 0x00ff00ff'u32
    left = left xor work
    right = right xor (work shl 8)

    right = rol(right, 1)
    work = (left xor right) and 0xaaaaaaaa'u32

    left = left xor work
    right = right xor work
    left = rol(left, 1)

    for cur_round in 0..7:
        k1 = addr key[4*cur_round]
        k2 = addr key[4*cur_round + 1]
        k3 = addr key[4*cur_round + 2]
        k4 = addr key[4*cur_round + 3]
        
        work  = ror(right, 4) xor k1[]
        left = left xor SP7[work  and 0x3f] xor
                SP5[(work shr  8) and 0x3f] xor
                SP3[(work shr 16) and 0x3f] xor
                SP1[(work shr 24) and 0x3f]
        
        work  = right xor k2[]
        left = left xor SP8[work  and 0x3f] xor
                SP6[(work shr  8) and 0x3f] xor
                SP4[(work shr 16) and 0x3f] xor
                SP2[(work shr 24) and 0x3f]

        work = ror(left, 4) xor k3[]
        right = right xor SP7[work and 0x3f] xor
                SP5[(work shr  8) and 0x3f]  xor
                SP3[(work shr 16) and 0x3f]  xor
                SP1[(work shr 24) and 0x3f]
        
        work  = left xor k4[]
        right = right xor SP8[work and 0x3f] xor
                SP6[(work shr  8) and 0x3f]  xor
                SP4[(work shr 16) and 0x3f]  xor
                SP2[(work shr 24) and 0x3f]

    right = ror(right, 1)
    work = (left xor right) and 0xaaaaaaaa'u32
    left = left xor work
    right = right xor work
    left = ror(left, 1)
    work = ((left shr 8) xor right) and 0x00ff00ff'u32
    right = right xor work
    left = left xor (work shl 8)
    #
    work = ((left shr 2) xor right) and 0x33333333'u32
    right = right xor work
    left = left xor (work shl 2)
    work = ((right shr 16) xor left) and 0x0000ffff'u32
    left = left xor work
    right = right xor (work shl 16)
    work = ((right shr 4) xor left) and 0x0f0f0f0f'u32
    left = left xor work
    right = right xor (work shl 4)

    data[0] = right
    data[1] = left

#--------- DES and DES3 objects -----
type
    desCipherObj = object
        keyEnc: array[3, subkeys]
        keyDec: array[3, subkeys]
        iv: array[2, uint32]
        restricted: bool # indicates use of 1st key only -- single DES mode
    desCipher* = ref desCipherObj


#---------
proc cryptBlock(cipher: desCipher, src, dst: binBuffer, mode: blockMode, operation: blockOp) =
    if (src.len != desBlockSize) or (dst.len != desBlockSize):
        raise newException(RangeError, "Not block")
    var
        work: array[2, uint32]
        tmp: array[2, uint32]
    
    discard src.loadHigh(work[0], 0)
    discard src.loadHigh(work[1], 4)

    # CBC only
    if mode == modeCBC:
        if operation == opEncrypt:
            # encryption XORs before crypt
            work[0] = work[0] xor cipher.iv[0]
            work[1] = work[1] xor cipher.iv[1]
        else:
            # decryption needs the previous encrypted block as iv
            tmp[0] = work[0]; tmp[1] = work[1]
    
    if operation == opEncrypt:
        desfunc(work, cipher.keyEnc[0])
        if cipher.restricted == false:
            desfunc(work, cipher.keyEnc[1]); # key created as opDecrypt
            desfunc(work, cipher.keyEnc[2]);
    else:
        desfunc(work, cipher.keyDec[0])
        if cipher.restricted == false:
            desfunc(work, cipher.keyDec[1]); # key created as opEncrypt
            desfunc(work, cipher.keyDec[2]);

    # CBC only
    if mode == modeCBC:
        if operation == opEncrypt:
            # encryption updates the iv to last output
            cipher.iv[0] = work[0]; cipher.iv[1] = work[1]
        else:
            # decryption XORs after crypt
            work[0] = work[0] xor cipher.iv[0]
            work[1] = work[1] xor cipher.iv[1] 
            # recover iv from the previous encrypted block
            cipher.iv[0] = tmp[0]; cipher.iv[1] = tmp[1]
        
    discard dst.storeHigh(work[0], 0)
    discard dst.storeHigh(work[1], 4)

