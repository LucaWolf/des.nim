import des_const 

type
    blockOp* = enum
        opEncrypt, opDecrypt
    blockMode* = enum
        modeCBC, modeECB
    blockPadding* = enum
        padX923, # ...00 00 NN
        padPKCS5, # ... NN NN NN
        padISO7816, # .. 80 00 00
        padZero # 00 00 00 00
        
    subkeys* = array[32, uint32]
    desBlock* = array[desBlockSize, byte]
    desKey* = array[desBlockSize, byte]

    
