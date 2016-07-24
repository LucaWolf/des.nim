import strutils, sequtils
import ../des_api


when isMainModule:
    var
        testKey = fromHex("0x10316E028C8F3B4A")
        dataClear = fromHex("1020-3040-5060-7080_A0:B0:C0:D0:E0:F0:77:88")
        dataEnc = newSeq[byte]((dataClear.len div desBlockSize) * desBlockSize)
        lastEnc = newSeq[byte](desBlockSize) # holder for last encrypted block
        
        mode = modeCBC
        padding = padPKCS5
        enforceFullBlockPadding = true

    echo "Clear data is:  ", toHex(dataClear, false)
    
    var des = newDesCipher(testKey)

    des.encrypt(dataClear, dataEnc, mode)

    var dataLast = dataClear.lastBlock(padding, enforceFullBlockPadding)
    if dataLast != nil:
        des.encrypt(dataLast, lastEnc, mode)
        dataEnc = dataEnc.concat(lastEnc)
    
    echo "Enc data is:    ", $toHex(dataEnc, false)

    # now test decryption
    echo "==============================="
    var dataRecovered = newSeq[byte](dataEnc.len)
    des.setIV(0'u64)
    des.decrypt(dataEnc, dataRecovered, mode)
    echo "Recovered data: ", $toHex(dataRecovered, false)


    
    
    