import times, strutils, sequtils
import ../des/des_api


proc main() =
    let
        numIter = 10_000_000
        startTime1 = epochTime()

    var
        testKey = fromHex("0123456789abcdef")
        dataClear = fromHex("1020-3040-5060-7080_A0:B0:C0:D0:E0:F0:77:88_FFFF")
        #dataClear = "Lorem ipsum dolor sit amet abcde"
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
    

    for i in 0 .. numIter.pred:
        singleDes.encrypt(dataClear, dataEnc, mode)

        if hasPadding:
            singleDes.encrypt(dataLast, lastEnc, mode)
            # not interested... dataEnc = dataEnc.concat(lastEnc)
        
    let endTime1 = epochTime()
    echo "Solution required ", endTime1 - startTime1, " seconds"
    echo "Enc data is:    ", $toHex(dataEnc, false)

main()
