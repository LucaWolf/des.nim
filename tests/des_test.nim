import strutils, sequtils
import ../des_api

proc toString(buff: seq[byte]): string =
    result = newString(buff.len)
    for i in 0 .. <buff.len():
        result[i] = buff[i].char()


when isMainModule:
    type
        blockFormat = enum
            fmt_hex, fmt_text

        desVector = tuple[desc: string; iv: uint64; key: seq[byte]; fmt: blockFormat; clear: string; cipher: string]

    # iv, key, clear, cipher,  
    var des_test: seq[desVector] = @[
        ("T1", 0x00'u64, fromHex("0123456789abcdef"),
            fmt_hex, "1020304050607080A0B0C0D0E0F07788", "0bc1b8dab679cce0384e53c5688bc998"),
        
        ("T2", 0x00'u64, fromHex("0123456789abcdef"),
            fmt_text, "1020304050607080A0B0C0D0E0F07788", "e4d41c004feef3121340ef227d71d95b2ddd01d2b8c914d51d5fe73704725b1d"),
        
        ("T3", 0x00'u64, fromHex("0123456789abcdef"),
            fmt_text, "Sto bene, non ti preoccupare!\x00\x00\x00", "e7d913dc87cba7a2bd1429855df598161f7bf5d73c3b1e2a8258b07cf753de8c"),

        ("T4", 0x00'u64, fromHex("81422418C00369A5"),
            fmt_hex, "8070605040302010FEDCBA0904030201", "6bfc9a1cf626bd5ff3e82c37fec77bc5"),
        
        ("T5", 0x81244482C8D5F00F'u64, fromHex("81422418C00369A5"),
            fmt_hex, "8070605040302010FEDCBA0904030201", "a5f1e98e5d21917db50b297898c06946"),
        
        ("T6", 0x00'u64, fromHex("81422418C00369A5"),
            fmt_hex, "FEDCBA09040302018070605040302010", "01b7a4918c08ba1e08f9ff43108dd0c1"),
        
        ("T7", 0x81244482C8D5F00F'u64, fromHex("81422418C00369A5"),
            fmt_hex, "FEDCBA09040302018070605040302010", "c2d5f004cf17445700970e9e25287aaa"),

        ("T8", 0x8181818181818181'u64, fromHex("7070707070707070"),
            fmt_hex, "8080808080808080", "27784764db81cfe1"),
        
        ("T9", 0x8181818181818181'u64, fromHex("7070707070707070"),
            fmt_text, "Lorem ipsum dolor sit amet, ex sanctus appellant", "beebda098b23162dcf7aa4d9e3fddbbb637726a13536d0224bcf60bd8c6869b4bc8f13755b72f27119d09d3fe93033d7"),
        
        ("T10", 0x1818181818181818'u64, fromHex("0707070707070707"),
            fmt_hex, "0808080808080808", "947d60582689287D"),
        
        ("T11", 0x1818181818181818'u64, fromHex("0707070707070707"),
            fmt_text, "Lorem ipsum dolor sit amet, ex sanctus appellant", "4f5b254c963707d6b06a265fbc83e8b2c38c5760fd6c5e2fac4c173fe24f63d811a02a3b0462590903fa8c3542d1ee84"),
        
        # 2DES key suite
        ("T12", 0x9b1c1d0e77021df6'u64, fromHex("80808080010101014040404002020202"),
            fmt_hex, "FEFEFEFE01020408", "cf2c5238010822f1"),
        
        ("T13", 0xe5d21917db50b297'u64, fromHex("80808080010101014040404002020202"),
            fmt_hex, "df38d82ffeaf8675f8442da1f8fab047eaa6adbeee69cc6f4296f717cafd9d01", "b59520682eac25f2ae07819bc0bee7f746338b8f941f6e875502cdeea963c126"),
        
        ("T14", 0x5502cdeea963c126'u64, fromHex("b59520682eac25f2ae07819bc0bee7f7"),
            fmt_hex, "95673856465fe1efb3644910d6fba3c4cbd0b630ece156f8ce1f433d6af7149d", "b0437abe0e06206f435b3ac3e9ddac624d42744b3d06af51258d0e11ae56fafd"),
        
        ("T15", 0xfdf11a883b7b19fe'u64, fromHex("b0437abe0e06206f435b3ac3e9ddac62"),
            fmt_text, "Lorem ipsum dolor sit amet, ex sanctus appellant", "91d5886d97efa59b82fd20c3733ca114728a0a51f0edc81a3b7f45cea0b67898f9100bf7ae69b0edf624d2c7a90d9346"),
        
        ("T16", 0x435a310855d2fafb'u64, fromHex("91d5886d97efa59b82fd20c3733ca114"),
            fmt_text, "Sto bene, non ti preoccupare!\x00\x00\x00", "617fbb34591c8def389b202cadddfd9e57573471a39e43b515816037a319c9fb"),
        
        #3DES key suite
        
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
            desCrypter = newDesCipher(v.key)
            output = newSeq[byte](length)
            
    
        # ecrypt suite
        desCrypter.setIV(v.iv)

        if v.fmt == fmt_hex:
            desCrypter.encrypt(v.clear.fromHex(), output, mode)
        else:
            desCrypter.encrypt(v.clear, output, mode)

        doAssert(output == v.cipher.fromHex(), "\n$1: enc [$2] vs cipher [$3] " % [v.desc, output.toHex(false), v.cipher])

        # decrypt suite
        desCrypter.setIV(v.iv)

        desCrypter.decrypt(v.cipher.fromHex(), output, mode)

        if v.fmt == fmt_hex:
            doAssert(output == v.clear.fromHex(), "\n$1: dec [$2] vs clear [$3] " % [v.desc, output.toHex(false), v.clear])
        else:
            let clear = output.toString()
            doAssert(clear == v.clear, "\n$1: dec [$2] vs clear [$3] " % [v.desc, clear, v.clear])

    echo "=== passed ==="

    
    


    
    
    