import strutils, sequtils
import des_api
import dukpt_const
import dukpt_pek

proc createIPEK*(bdk, ksn: openArray[byte]): dukptKey =
    var
        ipek_l: array[desBlockSize, byte]
        ipek_r: array[desBlockSize, byte]
        ksn_base = mapWith(ksn, ksnCounterMask, `and`)
        ksn_msb = ksn_base[0..<desBlockSize]

    # left register IPEK
    var tripleDes = newDesCipher(bdk)
    tripleDes.encrypt(ksn_msb, ipek_l, modeCBC)

    # prepare the key for the right register IPEK
    var keyMasked = mapWith(bdk, ipekMask, `xor`)

    tripleDes = newDesCipher(keyMasked)
    tripleDes.encrypt(ksn_msb, ipek_r, modeCBC)

    var i = 0
    for val in items(ipek_l):
        result[i] = val
        inc(i)
    for val in items(ipek_r):
        result[i] = val
        inc(i)