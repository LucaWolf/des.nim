import strutils, sequtils
import des_api
import dukpt_const
import dukpt_pek

proc createIPEK*(bdk, ksn: seq[byte]): seq[byte] =
    var
        ipek_l = newSeq[byte](desBlockSize)
        ipek_r = newSeq[byte](desBlockSize)
        ksn_base = mapWith(ksn, ksnCounterMask, `and`)
        ksn_msb = ksn_base[0..<desBlockSize]

    # left register IPEK
    var tripleDes = newDesCipher(bdk)
    tripleDes.encrypt(ksn_msb, ipek_l, modeCBC)

    # prepare the key for the right register IPEK
    var keyMasked = mapWith(bdk, ipekMask, `xor`)

    tripleDes = newDesCipher(keyMasked)
    tripleDes.encrypt(ksn_msb, ipek_r, modeCBC)

    result = concat(ipek_l, ipek_r)
