import strutils, sequtils
import ../des_api


when isMainModule:
    var
        testKey = fromHex("0123456789abcdef")
        testKey16 = fromHex("0x0123456789ABCDEFFEDCBA9876543210")
        testKey24 = fromHex("0x0123456789ABCDEFFEDCBA9876543210_8899AABBCCDDEEFF")
        dataClear = fromHex("1020-3040-5060-7080_A0:B0:C0:D0:E0:F0:77:88_FFFF")
        dataLast: desBlock
        
        lastEnc = newSeq[byte](desBlockSize) # holder for last encrypted block
        
        mode = modeCBC
        padding = padPKCS5
        enforceFullBlockPadding = false
        hasPadding = dataClear.lastBlock(dataLast, padding, enforceFullBlockPadding)

    echo "Clear data is:  ", toHex(dataClear, false)
    
    #---------------    
    echo "=== DES encrypt ==="
    var
        singleDes = newDesCipher(testKey)
        dataEnc = newSeq[byte]((dataClear.len div desBlockSize) * desBlockSize)
    
    singleDes.encrypt(dataClear, dataEnc, mode)

    if hasPadding:
        singleDes.encrypt(dataLast, lastEnc, mode)
        dataEnc = dataEnc.concat(lastEnc)
    
    echo "Enc data is:    ", $toHex(dataEnc, false)

    echo "=== DES decrypt ==="
    var dataRecovered = newSeq[byte](dataEnc.len)
    singleDes.setIV(0'u64)
    singleDes.decrypt(dataEnc, dataRecovered, mode)
    echo "Recovered data: ", $toHex(dataRecovered, false)
    
    #---------------    
    echo "=== DES2 encrypt ==="
    var
        doubleDes = newDesCipher(testKey16)
        dataEnc2 = newSeq[byte]((dataClear.len div desBlockSize) * desBlockSize)
    
    doubleDes.encrypt(dataClear, dataEnc2, mode)
    
    if hasPadding:
        doubleDes.encrypt(dataLast, lastEnc, mode)
        dataEnc2 = dataEnc2.concat(lastEnc)
    
    echo "Enc2 data is:   ", $toHex(dataEnc2, false)
    
    echo "=== DES2 decrypt ==="
    var dataRecovered2 = newSeq[byte](dataEnc2.len)
    doubleDes.setIV(0'u64)
    doubleDes.decrypt(dataEnc2, dataRecovered2, mode)
    echo "Recovered data: ", $toHex(dataRecovered2, false)
    
    #---------------    
    echo "=== DES3 encrypt ==="
    var
        tripleDes = newDesCipher(testKey24)
        dataEnc3 = newSeq[byte]((dataClear.len div desBlockSize) * desBlockSize)
    
    tripleDes.encrypt(dataClear, dataEnc3, mode)
    
    if hasPadding:
        tripleDes.encrypt(dataLast, lastEnc, mode)
        dataEnc3 = dataEnc3.concat(lastEnc)
    
    echo "Enc3 data is:   ", $toHex(dataEnc3, false)
    
    echo "=== DES3 decrypt ==="
    var dataRecovered3 = newSeq[byte](dataEnc3.len)
    tripleDes.setIV(0'u64)
    tripleDes.decrypt(dataEnc3, dataRecovered3, mode)
    echo "Recovered data: ", $toHex(dataRecovered3, false)
    
    


    
    
    