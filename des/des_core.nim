import strutils, bin, des_const, des_type

#--------- DES and DES3 objects -----
type        
    desCipherObj = object
        keyEnc: array[3, subkeys]
        keyDec: array[3, subkeys]
        iv: int64
        restricted: bool # enforces using of 1st key only -- single DES mode
        keyIsSingle: bool # tells if original key was single DES

    desCipher* = ref desCipherObj
#---------

#---------
proc cookey(raw: subkeys, key: var subkeys) = 
    
    for i in 0..15:
        var
            raw0 = raw[2*i]
            raw1 = raw[2*i + 1]
            # init
            k1 = key[2*i]
            k2 = key[2*i + 1]
            
        k1 =        (raw0 and 0x00fc0000) shl 6
        k1 = k1 or ((raw0 and 0x00000fc0) shl 10)
        k1 = k1 or ((raw1 and 0x00fc0000) shr 10)
        k1 = k1 or ((raw1 and 0x00000fc0) shr 6)        
        
        k2 =        ((raw0 and 0x0003f000) shl 12)
        k2 = k2 or ((raw0 and 0x0000003f) shl 16).toU32()
        k2 = k2 or ((raw1 and 0x0003f000) shr 4)
        k2 = k2 or  (raw1 and 0x0000003f)

        # write back
        key[2*i] = k1 
        key[2*i + 1] = k2
        

#---------
proc initKeys(keyin: openArray[byte], edf: blockOp, keyout: var subkeys) = 
    var
        s,m,n: int
        kn: subkeys
        pc1m, pcr: array[56, byte]
        mask: byte
    
    for j in 0 .. pc1m.len.pred:
        s = pc1[j]
        m =  s and 7
        mask = maskbit[m].byte
        pc1m[j] = if ((keyin[s shr 3] and mask) == mask): 1 else: 0

    for i in 0..15:
        m = if (edf == opDecrypt): (15 - i) shl 1  else: i shl 1
        
        n = m + 1
        kn[m] = 0
        kn[n] = 0
        
        for j in 0..27:
            s = j + totrot[i];
            pcr[j] = if (s < 28): pc1m[s] else: pc1m[s - 28]
        
        for j in 28..55:
            s = j + totrot[i];
            pcr[j] = if (s < 56): pc1m[s] else: pc1m[s - 28]
        
        for j in 0 .. bigbyte.len.pred:
            if (pcr[pc2[j]] != 0'u8):
               kn[m] = kn[m] or bigbyte[j]
            
            if (pcr[pc2[j+24]] != 0'u8):
               kn[n] = kn[n] or bigbyte[j]

    cookey(kn, keyout)
    
#---------    
proc desfunc(data: var int64, key: var subkeys) =
    var
        work, right, left: int32

    left = (data shr 32).toU32()
    right = data.toU32()

    work = ((left shr 4)  xor right) and 0x0f0f0f0f
    right = right xor work
    left = left xor (work shl 4)

    work = ((left shr 16) xor right) and 0x0000ffff
    right = right xor work
    left = left xor (work shl 16)

    work = ((right shr 2)  xor left) and 0x33333333
    left = left xor work
    right = right xor (work shl 2)

    work = ((right shr 8)  xor left) and 0x00ff00ff
    left = left xor work
    right = right xor (work shl 8)

    right = rol(right, 1)
    work = (left xor right) and 0xaaaaaaaa.toU32()

    left = left xor work
    right = right xor work
    left = rol(left, 1)

    for cur_round in 0..7:
        let k1 = key[4*cur_round]
        let k2 = key[4*cur_round + 1]
        let k3 = key[4*cur_round + 2]
        let k4 = key[4*cur_round + 3]
        
        work  = ror(right, 4) xor k1
        left = left xor (SP7[work  and 0x3f] xor
                SP5[(work shr  8) and 0x3f] xor
                SP3[(work shr 16) and 0x3f] xor
                SP1[(work shr 24) and 0x3f]).toU32()
        
        work  = right xor k2
        left = left xor (SP8[work  and 0x3f] xor
                SP6[(work shr  8) and 0x3f] xor
                SP4[(work shr 16) and 0x3f] xor
                SP2[(work shr 24) and 0x3f]).toU32()

        work = ror(left, 4) xor k3
        right = right xor (SP7[work and 0x3f] xor
                SP5[(work shr  8) and 0x3f]  xor
                SP3[(work shr 16) and 0x3f]  xor
                SP1[(work shr 24) and 0x3f]).toU32()
        
        work  = left xor k4
        right = right xor (SP8[work and 0x3f] xor
                SP6[(work shr  8) and 0x3f]  xor
                SP4[(work shr 16) and 0x3f]  xor
                SP2[(work shr 24) and 0x3f]).toU32()

    right = ror(right, 1)
    work = (left xor right) and 0xaaaaaaaa.toU32()
    left = left xor work
    right = right xor work
    left = ror(left, 1)
    work = ((left shr 8) xor right) and 0x00ff00ff
    right = right xor work
    left = left xor (work shl 8)

    #
    work = ((left shr 2) xor right) and 0x33333333
    right = right xor work
    left = left xor (work shl 2)
    work = ((right shr 16) xor left) and 0x0000ffff
    left = left xor work
    right = right xor (work shl 16)
    work = ((right shr 4) xor left) and 0x0f0f0f0f
    left = left xor work
    right = right xor (work shl 4)

    data = (right.ze64() shl 32) or left.ze64()


proc cryptBlock(cipher: desCipher; src: int64; mode: blockMode; operation: blockOp): int64 =

    var
        work = src
        tmp: int64
    
    # CBC only
    if mode == modeCBC:
        if operation == opEncrypt:
            # encryption XORs before crypt
            work = work xor cipher.iv 
        else:
            # decryption needs the previous encrypted block as iv
            tmp = work
    
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
            cipher.iv = work
        else:
            # decryption XORs after crypt
            work = work xor cipher.iv
            # recover iv from the previous encrypted block
            cipher.iv = tmp
        
    result = work

