import strutils, sequtils
import ../des_api
import ../dukpt_api

when isMainModule:

    var
        testBDK = fromHex("C1D0F8FB4958670DBA40AB1F3752EF0D")
        testKSN = fromHex("FFFF9876543210E10004")
        testData = fromHex("102030405060708090A0B0C0D0E0F0FF")
        testOut = newSeq[byte](testData.len)
        dukpt: dukptCipher

    dukpt = newDukptCipher(testBDK, testKSN)

    dukpt.encrypt(testData, testOut)
    echo "Output data: ", toHex(testOut, false)
    