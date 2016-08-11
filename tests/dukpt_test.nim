import strutils, sequtils
import ../des_api
import ../dukpt_api

when isMainModule:

    var
        testBDK = fromHex("C1D0F8FB4958670DBA40AB1F3752EF0D")
        testKSN = fromHex("FFFF9876543210E10004")
        dukpt: dukptCipher

    dukpt = newDukptCipher(testBDK, testKSN)
    echo $dukpt

