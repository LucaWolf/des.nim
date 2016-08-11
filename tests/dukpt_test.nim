import strutils, sequtils
import ../des_api
# TODO unify into a dukpt API
import ../dukpt_const
import ../dukpt_ipek
import ../dukpt_pek


when isMainModule:
    var
        testBDK = fromHex("C1D0F8FB4958670DBA40AB1F3752EF0D")
        testKSN = fromHex("FFFF9876543210E10004")

    var ipek = createIPEK(testBDK, testKSN)
    echo "iPEK is: ", toHex(ipek, true)

    var pek = createPEK(ipek, testKSN)
    echo "PEK is: ", toHex(pek, true)

