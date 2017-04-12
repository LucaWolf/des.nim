import strutils, sequtils
import ../des/des_api
import ../des/dukpt_api

when isMainModule:

    var
        testBDK = fromHex("C1D0F8FB4958670DBA40AB1F3752EF0D")
        testKSN = fromHex("FFFF9876543210E10004")
        testData = fromHex("102030405060708090A0B0C0D0E0F0FF")
        testOut = newSeq[byte](testData.len)
        macValue: desBlock
        dukpt: dukptCipher

    dukpt = newDukptCipher(testBDK, testKSN)

    dukpt.encrypt(testData, testOut)
    echo "Output data: ", toHex(testOut, false)

    dukpt.selectKey(kvMacReq)
    # key change will use a default IV, no need to reset it
    dukpt.mac(testData, macValue, macX9_19, padPKCS5, false)
    echo "Req X9.19 exact MAC: ", toHex(macValue, false) # 20535491B343C5DE

    dukpt.setIV(0'u64) # new MAC of the same key needs a fresh IV
    dukpt.mac(testData, macValue, macX9_19, padPKCS5, true)
    echo "Req X9.19 full pkcs5 MAC: ", toHex(macValue, false) # 28E707E2C0A21C4A


    testData.add(0xFF'u8)
    dukpt.setIV(0'u64) # new MAC of the same key needs a fresh IV
    dukpt.mac(testData, macValue, macX9_19, padPKCS5, false)
    echo "Req X9.19 pkcs5 MAC: ", toHex(macValue, false) # 86476EE921F82048

    dukpt.setIV(0'u64) # new MAC of the same key needs a fresh IV
    dukpt.mac(testData, macValue, macX9_19, padZero, false)
    echo "Req X9.19 zero MAC: ", toHex(macValue, false) # 590F2E876D3DA0F7

    dukpt.setIV(0'u64) # new MAC of the same key needs a fresh IV
    dukpt.mac(testData, macValue, macX9_19, padISO7816, false)
    echo "Req X9.19 iso7816 MAC: ", toHex(macValue, false) # E89712ED2CF8D465

    dukpt.setIV(0'u64) # new MAC of the same key needs a fresh IV
    dukpt.mac(testData, macValue, macX9_19, padX923, false)
    echo "Req X9.19 X923 MAC: ", toHex(macValue, false) # ADB9FB181F26CFF4
