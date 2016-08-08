import strutils, sequtils
import des_api
import dukpt_const

proc pekBlackBox(currKey: var seq[byte], currKSN: seq[byte]) =

    var
        keyLeft = currKey[0 .. <desBlockSize] # copies
        keyRight = currKey[desBlockSize .. ^1]
        nextKeyLeft = currKey.toBinBuffer()[0 .. <desBlockSize] # direct output
        nextKeyRight = currKey.toBinBuffer()[desBlockSize .. ^1]
        cipher: desCipher
        msg: seq[byte]
    
    # ===============================================
    # LSB of new key is:
    # - XOR right key with current KSN iteration,
    # - encrypt with left key
    # - XOR with right key
    # ===============================================
    msg = mapWith(keyRight, currKSN,`xor`)
    cipher = newDesCipher(keyLeft)
    cipher.encrypt(msg, nextKeyRight)
    nextKeyRight.applyWith(keyRight, `xor`)

    # ===============================================
    # MSB of new key is as above but the input key is
    # C0C0C0C000000000 masked
    # ===============================================
    keyLeft.applyWith(ipekMask,`xor`)
    keyRight.applyWith(ipekMask,`xor`)

    msg = mapWith(keyRight, currKSN,`xor`)
    cipher = newDesCipher(keyLeft)
    cipher.encrypt(msg, nextKeyLeft)
    nextKeyLeft.applyWith(keyRight, `xor`)


proc createPEK*(ipek, ksn: seq[byte]): seq[byte] =
    var
        ksn_lsb = ksn[2..^1]
        ksn_base = mapWith(ksn, ksnCounterMask, `and`)
        ksn_base_lsb = ksn_base[2..^1]

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

    for n in (8*desBlockSize - counter_bits) .. <(8*desBlockSize):
        if testBit(ksn_lsb, n):
            setBit(ksn_base_lsb, n)
            result.pekBlackBox(ksn_base_lsb)
            
