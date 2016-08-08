import strutils, sequtils
import ../des_api
# TODO unify into a dukpt API
import ../dukpt_const
import ../dukpt_ipek
import ../dukpt_pek


when isMainModule:
    var
        testBDK = fromHex("0x0123456789abcdeffedcba9876543210")
        testKSN = fromHex("0xFFFF9876543210E00047")

    var ipek = createIPEK(testBDK, testKSN)
    echo "iPEK is: ", toHex(ipek, true)

    var pek = createPEK(ipek, testKSN)
    echo "PEK is: ", toHex(pek, true)

