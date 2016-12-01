import strutils, sequtils
import ../des_api


when isMainModule:
    type
        blockFormat = enum
            fmt_hex, fmt_text

        desVector = tuple[iv: uint64; key: seq[byte]; fmt: blockFormat; clear: string; cipher: string]

    # iv, key, clear, cipher,  
    var des_test: seq[desVector] = @[
        (0x00'u64, fromHex("0123456789abcdef"), fmt_hex, "1020304050607080_A0B0C0D0E0F07788", "output1")
        ]
    var
        mode = modeCBC

    #---------------    
    echo "=== DES encrypt ==="
    for v in des_test:
        var
            singleDes = newDesCipher(v.key)
            dataEnc = newSeq[byte]((v.clear.len div desBlockSize) * desBlockSize)
    
        singleDes.encrypt(v.clear, dataEnc, mode)

        echo "Enc data is:    ", $toHex(dataEnc, false)

    
    


    
    
    