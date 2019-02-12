import strutils, sequtils, bin, des_const, des_type

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
template cook1(raw0,raw1): untyped = 
    ((raw0 and 0x00fc0000) shl 6) or 
        ((raw0 and 0x00000fc0) shl 10) or
        ((raw1 and 0x00fc0000) shr 10) or
        ((raw1 and 0x00000fc0) shr 6)

template cook2(raw0,raw1): untyped =
    ((raw0 and 0x0003f000) shl 12) or
        ((raw0 and 0x0000003f) shl 16).toU32() or 
        ((raw1 and 0x0003f000) shr 4) or
        (raw1 and 0x0000003f)

template cookElem(i, raw, key): untyped =
    let raw0 = raw[2*i]
    let raw1 = raw[2*i+1]

    key[2*i] = cook1(raw0, raw1)
    key[2*i+1] = cook2(raw0, raw1)

proc cookey(raw: subkeys, key: var subkeys) =
    cookElem(0, raw, key); cookElem(1, raw, key); cookElem(2, raw, key); cookElem(3, raw, key);
    cookElem(4, raw, key); cookElem(5, raw, key); cookElem(6, raw, key); cookElem(7, raw, key);
    cookElem(8, raw, key); cookElem(9, raw, key); cookElem(10, raw, key); cookElem(11, raw, key);
    cookElem(12, raw, key); cookElem(13, raw, key); cookElem(14, raw, key); cookElem(15, raw, key);

#---------
const
    mm_dec = [15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0].mapIt(it shl 1)
    mm_enc = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15].mapIt(it shl 1)

proc initKeys(keyin: desKey, op: blockOp, keyout: var subkeys) = 
    var
        s,m,n: int
        kn: subkeys
        pc1m, pcr: array[0..55, byte]
        mask: byte 

    let mm = if op == opDecrypt: mm_dec else: mm_enc
        
    for i,s in pairs pc1:
        mask = maskbit[s and 7]
        # (a and mask) xor mask = a.not and mask; equals zero if a == mask
        pc1m[i] = not(keyin[s shr 3]) and mask

    for i,m in pairs mm:
        n = m + 1
        kn[m] = 0
        kn[n] = 0
        
        for j in 0 ..> 28:
            s = j + totrot[i];
            pcr[j] = if (s < 28): pc1m[s] else: pc1m[s - 28]
        
        for j in 28 ..> 28:
            s = j + totrot[i];
            pcr[j] = if (s < 56): pc1m[s] else: pc1m[s - 28]
        
        for j in 0 ..> bigbyte.len:
            if pcr[pc2[j + 00]] == 0'u8: kn[m] = kn[m] or bigbyte[j]            
            if pcr[pc2[j + 24]] == 0'u8: kn[n] = kn[n] or bigbyte[j]
        
    cookey(kn, keyout)
    

template desround(cur_round: int, right, left: var int32, key: subkeys): untyped = 
    var w1, w2: int32

    w1 = ror(right, 4) xor key[4*cur_round]
    w2 = right xor key[4*cur_round + 1]

    left = left xor (SP7[w1  and 0x3f] xor
            SP5[(w1 shr  8) and 0x3f] xor
            SP3[(w1 shr 16) and 0x3f] xor
            SP1[(w1 shr 24) and 0x3f]).toU32()
    
    left = left xor (SP8[w2  and 0x3f] xor
            SP6[(w2 shr  8) and 0x3f] xor
            SP4[(w2 shr 16) and 0x3f] xor
            SP2[(w2 shr 24) and 0x3f]).toU32()

    #
    w1 = ror(left, 4) xor key[4*cur_round + 2]
    w2  = left xor key[4*cur_round + 3]

    right = right xor (SP7[w1 and 0x3f] xor
            SP5[(w1 shr  8) and 0x3f]  xor
            SP3[(w1 shr 16) and 0x3f]  xor
            SP1[(w1 shr 24) and 0x3f]).toU32()
    
    
    right = right xor (SP8[w2 and 0x3f] xor
            SP6[(w2 shr  8) and 0x3f]  xor
            SP4[(w2 shr 16) and 0x3f]  xor
            SP2[(w2 shr 24) and 0x3f]).toU32()

    
#---------    
proc desfunc(data: var int64, key: subkeys) =
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

    desround(0, right, left, key)
    desround(1, right, left, key)
    desround(2, right, left, key)
    desround(3, right, left, key)
    desround(4, right, left, key)
    desround(5, right, left, key)
    desround(6, right, left, key)
    desround(7, right, left, key)

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

