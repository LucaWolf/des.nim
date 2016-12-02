import strutils, sequtils
import ../des_api

proc toString(buff: seq[byte]): string =
    result = newString(buff.len)
    for i in 0 .. <buff.len():
        result[i] = buff[i].char()


when isMainModule:
    type
        blockFormat = enum
            fmt_hex, fmt_tex

        desVector = tuple[iv: uint64; key: seq[byte]; fmt: blockFormat; clear: string; cipher: string]

    # iv, key, clear, cipher,  
    var des_test: seq[desVector] = @[
        (0x00'u64, fromHex("0123456789abcdef"), fmt_hex, "1020304050607080A0B0C0D0E0F07788", "0bc1b8dab679cce0384e53c5688bc998"),
        (0x00'u64, fromHex("0123456789abcdef"), fmt_tex, "1020304050607080A0B0C0D0E0F07788", "e4d41c004feef3121340ef227d71d95b2ddd01d2b8c914d51d5fe73704725b1d"),
        (0x00'u64, fromHex("0123456789abcdef"), fmt_tex, "Sto bene, non ti preoccupare!\x00\x00\x00", "e7d913dc87cba7a2bd1429855df598161f7bf5d73c3b1e2a8258b07cf753de8c"),

        (0x00'u64, fromHex("81422418C00369A5"), fmt_hex, "8070605040302010FEDCBA0904030201", "6bfc9a1cf626bd5ff3e82c37fec77bc5"),
        (0x81244482C8D5F00F'u64, fromHex("81422418C00369A5"), fmt_hex, "8070605040302010FEDCBA0904030201", "a5f1e98e5d21917db50b297898c06946"),
        (0x00'u64, fromHex("81422418C00369A5"), fmt_hex, "FEDCBA09040302018070605040302010", "01b7a4918c08ba1e08f9ff43108dd0c1"),
        (0x81244482C8D5F00F'u64, fromHex("81422418C00369A5"), fmt_hex, "FEDCBA09040302018070605040302010", "c2d5f004cf17445700970e9e25287aaa"),

        (0x8181818181818181'u64, fromHex("7070707070707070"), fmt_hex, "8080808080808080", "27784764db81cfe1"),
        (0x8181818181818181'u64, fromHex("7070707070707070"), fmt_tex, "Lorem ipsum dolor sit amet, ex sanctus appellant", "beebda098b23162dcf7aa4d9e3fddbbb637726a13536d0224bcf60bd8c6869b4bc8f13755b72f27119d09d3fe93033d7"),
        (0x1818181818181818'u64, fromHex("0707070707070707"), fmt_hex, "0808080808080808", "947d60582689287d"),
        (0x1818181818181818'u64, fromHex("0707070707070707"), fmt_tex, "Lorem ipsum dolor sit amet, ex sanctus appellant", "4f5b254c963707d6b06a265fbc83e8b2c38c5760fd6c5e2fac4c173fe24f63d811a02a3b0462590903fa8c3542d1ee84"),
        ]
    var
        mode = modeCBC

    #---------------    
    echo "=== DES tests ==="
    for v in des_test:
        var length = (v.clear.len div desBlockSize) * desBlockSize
        
        if v.fmt == fmt_hex:
            length = length div 2

        var
            singleDes = newDesCipher(v.key)
            output = newSeq[byte](length)
            
    
        # ecrypt suite
        singleDes.setIV(v.iv)

        if v.fmt == fmt_hex:
            singleDes.encrypt(v.clear.fromHex(), output, mode)
        else:
            singleDes.encrypt(v.clear, output, mode)

        doAssert(output == v.cipher.fromHex(), "DES enc [$1] vs cipher [$2] " % [output.toHex(false), v.cipher])

        # decrypt suite
        singleDes.setIV(v.iv)

        singleDes.decrypt(v.cipher.fromHex(), output, mode)

        if v.fmt == fmt_hex:
            doAssert(output == v.clear.fromHex(), "DES dec [$1] vs clear [$2] " % [output.toHex(false), v.clear])
        else:
            let clear = output.toString()
            doAssert(clear == v.clear, "DES dec [$1] vs clear [$2] " % [clear, v.clear])
            

    echo "=== passed ==="

    
    


    
    
    