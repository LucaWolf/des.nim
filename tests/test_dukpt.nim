import strutils, sequtils
import des

when isMainModule:

    var
        testBDK = des.fromHex("C1D0F8FB4958670DBA40AB1F3752EF0D")
        testKSN = des.fromHex("FFFF9876543210E10004")
        testData = des.fromHex("102030405060708090A0B0C0D0E0F0FF")
        testOut = newSeq[byte](testData.len)
        macValue: desBlock
        dukpt: dukptCipher
        output: string

    echo "=== DUKPT tests ==="

    dukpt = newDukptCipher(testBDK, testKSN)

    dukpt.encrypt(testData, testOut)
    output = toHex(testOut, false)
    #echo "Output data: ", output
    doAssert("4055689B2BDE84A1055AD91E59BF80A1" == output, "\n[$#] vs clear [$#] " % [output, "4055689B2BDE84A1055AD91E59BF80A1"])

    dukpt.selectKey(kvMacReq)
    # key change will use a default IV, no need to reset it
    dukpt.mac(testData, macValue, macX9_19, padPKCS5, false)
    output = toHex(macValue, false)
    #echo "Req X9.19 exact MAC: ", output
    doAssert("20535491B343C5DE" == output, "\n[$#] vs clear [$#] " % [output, "20535491B343C5DE"])

    dukpt.setIV(0'u64) # new MAC of the same key needs a fresh IV
    dukpt.mac(testData, macValue, macX9_19, padPKCS5, true)
    output = toHex(macValue, false)
    #echo "Req X9.19 full pkcs5 MAC: ", output
    doAssert("28E707E2C0A21C4A" == output, "\n[$#] vs clear [$#] " % [output, "28E707E2C0A21C4A"])

    testData.add(0xFF'u8)
    dukpt.setIV(0'u64) # new MAC of the same key needs a fresh IV
    dukpt.mac(testData, macValue, macX9_19, padPKCS5, false)
    output = toHex(macValue, false)
    #echo "Req X9.19 pkcs5 MAC: ", output
    doAssert("86476EE921F82048" == output, "\n[$#] vs clear [$#] " % [output, "86476EE921F82048"])

    dukpt.setIV(0'u64) # new MAC of the same key needs a fresh IV
    dukpt.mac(testData, macValue, macX9_19, padZero, false)
    output = toHex(macValue, false)
    #echo "Req X9.19 zero MAC: ", output
    doAssert("590F2E876D3DA0F7" == output, "\n[$#] vs clear [$#] " % [output, "590F2E876D3DA0F7"])

    dukpt.setIV(0'u64) # new MAC of the same key needs a fresh IV
    dukpt.mac(testData, macValue, macX9_19, padISO7816, false)
    output = toHex(macValue, false)
    #echo "Req X9.19 iso7816 MAC: ", output
    doAssert("E89712ED2CF8D465" == output, "\n[$#] vs clear [$#] " % [output, "E89712ED2CF8D465"])

    dukpt.setIV(0'u64) # new MAC of the same key needs a fresh IV
    dukpt.mac(testData, macValue, macX9_19, padX923, false)
    output = toHex(macValue, false)
    #echo "Req X9.19 X923 MAC: ", output
    doAssert("ADB9FB181F26CFF4" == output, "\n[$#] vs clear [$#] " % [output, "ADB9FB181F26CFF4"])


    var
        testData1 = "Lorem ipsum dolor sit amet ....."
        testOut1 = newSeq[byte](32)

    dukpt.selectKey(kvData)
    # key change will use a default IV, no need to reset it
    dukpt.encrypt(testData1, testOut1)
    output = toHex(testOut1, false)
    #echo "Output data: ", output
    doAssert("605F5B6426F786FF6407E89120AE812E807DB1546C2396A8784279B5FA596F10" == output, "\n[$#] vs clear [$#] " % [output, "605F5B6426F786FF6407E89120AE812E807DB1546C2396A8784279B5FA596F10"])

    dukpt.selectKey(kvMacReq)
    # key change will use a default IV, no need to reset it
    dukpt.mac(testData1, macValue, macX9_19, padPKCS5, false)
    output = toHex(macValue, false)
    #echo "Req X9.19 exact MAC: ", output
    doAssert("95B09FF19AB27E2F" == output, "\n[$#] vs clear [$#] " % [output, "95B09FF19AB27E2F"])

    dukpt.setIV(0'u64) # new MAC of the same key needs a fresh IV
    dukpt.mac(testData1, macValue, macX9_19, padPKCS5, true)
    output = toHex(macValue, false)
    #echo "Req X9.19 full pkcs5 MAC: ", output
    doAssert("08FF8748EAD7A6A0" == output, "\n[$#] vs clear [$#] " % [output, "08FF8748EAD7A6A0"])

    testData1 = testData1 & char(0xFF'u8)
    dukpt.setIV(0'u64) # new MAC of the same key needs a fresh IV
    dukpt.mac(testData1, macValue, macX9_19, padPKCS5, false)
    output = toHex(macValue, false)
    #echo "Req X9.19 pkcs5 MAC: ", output
    doAssert("860F886E08B63B64" == output, "\n[$#] vs clear [$#] " % [output, "860F886E08B63B64"])

    dukpt.setIV(0'u64) # new MAC of the same key needs a fresh IV
    dukpt.mac(testData1, macValue, macX9_19, padZero, false)
    output = toHex(macValue, false)
    #echo "Req X9.19 zero MAC: ", output
    doAssert("102FCC8FD2B0D2BE" == output, "\n[$#] vs clear [$#] " % [output, "102FCC8FD2B0D2BE"])

    dukpt.setIV(0'u64) # new MAC of the same key needs a fresh IV
    dukpt.mac(testData1, macValue, macX9_19, padISO7816, false)
    output = toHex(macValue, false)
    #echo "Req X9.19 iso7816 MAC: ", output
    doAssert("33F6814D923503E3" == output, "\n[$#] vs clear [$#] " % [output, "33F6814D923503E3"])

    dukpt.setIV(0'u64) # new MAC of the same key needs a fresh IV
    dukpt.mac(testData1, macValue, macX9_19, padX923, false)
    output = toHex(macValue, false)
    #echo "Req X9.19 X923 MAC: ", output
    doAssert("73DD4B6F4A3643A1" == output, "\n[$#] vs clear [$#] " % [output, "73DD4B6F4A3643A1"])
    
    echo "=== passed ==="
    