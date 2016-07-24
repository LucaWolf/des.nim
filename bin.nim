import strutils, sequtils, endians

# rotate left with wrap-around
proc rol*(x: uint8, y: uint8): uint8 =
    result = (x shl (y and 7'u8)) or (x shr (8'u8 - (y and 7'u8)))

proc rol*(x: uint16, y: uint8): uint16 =
    result = (x shl (y and 15'u8)) or (x shr (16'u8 - (y and 15'u8)))

proc rol*(x: uint32, y: uint8): uint32 =
    result = (x shl (y and 31'u8)) or (x shr (32'u8 - (y and 31'u8)))

proc rol*(x: uint64, y: uint8): uint64 =
    result = (x shl (y and 63'u8)) or (x shr (64'u8 - (y and 63'u8)))

# rotate right with wrap-around
proc ror*(x: uint8, y: uint8): uint8 =
    result = (x shr (y and 7'u8)) or (x shl (8'u8 - (y and 7'u8)))

proc ror*(x: uint16, y: uint8): uint16 =
    result = (x shr (y and 15'u8)) or (x shl (16'u8 - (y and 15'u8)))

proc ror*(x: uint32, y: uint8): uint32 =
    result = (x shr (y and 31'u8)) or (x shl (32'u8 - (y and 31'u8)))

proc ror*(x: uint64, y: uint8): uint64 =
    result = (x shr (y and 63'u8)) or (x shl (64'u8 - (y and 63'u8)))

type
    binBufferObj = object
        data: cstring
        size: int
        view: Slice[int]
    binBuffer* = ref binBufferObj


proc len*(buff: binBuffer): int =
    result = buff.view.b - buff.view.a + 1


proc toBinBuffer*[T](data: openArray[T]): binBuffer = 
    new(result)
    result.data = cast[cstring](unsafeAddr data[0])
    result.size = data.len * T.sizeof
    result.view = 0 .. <result.size


proc `[]`*(buff: binBuffer, n: int): var byte =
    if n > <buff.len:
        raise newException(IndexError, "Invalid index: " & $n)

    result = cast[ptr byte](addr buff.data[buff.view.a + n])[]


proc `[]=`*(buff: binBuffer, n: int, val: byte) =
    if n  > <buff.len:
        raise newException(IndexError, "Invalid index: " & $n)

    cast[ptr byte](addr buff.data[buff.view.a + n])[] = val


proc `[]`*(buff: binBuffer, s: Slice[int]): binBuffer = 
    ## Slices `buff` to (and including) the desired limits. The underlying data array 
    ## is shared across slices. The 's' limits are limited to the
    ## original data size so is possible to grow back a slice up to
    ## the maximum size. 
    new(result)
    shallowCopy(result[], buff[])
    
    # allow expanding to original size
    result.view.b = (buff.view.a + s.b).clamp(0, <buff.size)
    result.view.a = (buff.view.a + s.a).clamp(0, <buff.size)

    if result.view.a > result.view.b:
        swap (result.view.a, result.view.b)

proc copy*(dst: binBuffer; src: binBuffer) = 
    var n = (src.len).clamp(0, dst.len)
    copyMem(addr dst.data[dst.view.a], addr src.data[src.view.a], n)

proc toHex*(buff: binBuffer, prefixed: bool = true): string =
    result = newStringOfCap(buff.len + 2)
    if prefixed:
        result.add("0x")
    for i in 0 .. <buff.len:
        result.add(toHex((int16)buff[i], 2))


#-----------------------
proc loadHigh*[T: SomeUnsignedInt](buff: binBuffer, value: var T, offset: int = 0): bool =
    ##  Reads an unsigned integer of type T from a sequence of bytes representing a big endian number.
    ## - value = var type pointer to the mutable integer (holder for the read value)
    ## - data = the byte array where to read from
    ## - offset = the element in the data array where to start. Defaults to zero if missing.
    ## Note: the routine will test if the offset position allows for the full T value to be read
    ## (i.e. there are enough bytes left to complete T size)

    var n = buff.view.a + offset  

    if (buff.view.b + 1 ) >= (n + sizeof(value)):
        result = true

        var i: pointer = addr buff.data[n]
        var o: pointer = addr value

        case sizeof(value)
        of 1:
            value = ord(buff.data[0])
        of 2:
            bigEndian16(o, i)
        of 4:
            bigEndian32(o, i)
        of 8:
            bigEndian64(o, i)
        else:
            result = false
    else:
        result = false
        assert(false, "Invalid load offset: " & $n & " in " & $buff.view)


proc storeHigh*[T: SomeUnsignedInt](buff: binBuffer, value: T, offset: int = 0): bool =
  
    var n = buff.view.a + offset  

    if (buff.view.b + 1 ) >= (n + sizeof(value)):
        result = true

        var o: pointer = addr buff.data[buff.view.a + offset]
        var i: pointer = unsafeAddr value
        
        case sizeof(value)
        of 1:
          buff.data[0] = char(value.byte)
        of 2:
          bigEndian16(o, i)
        of 4:
          bigEndian32(o, i)
        of 8:
          bigEndian64(o, i)
        else:
          result = false
    else:
      result = false
      assert(false, "Invalid store offset: " & $n & " in " & $buff.view)


#-----------------------
template seqOf*[T,N] (buff: openarray[T]): expr =
    ## Script to help with declaration of new sequences of type N based on an array of 
    ## values of type T. Internally, a conversion call *proc (x: T): N = x.N*
    ## is attempted, so the conversion function would better exists already.
    ## 
    ## For example, the following call preserves only the LSB from each input when defining 
    ## an aray of unsigned 8 bit integers:
    ##
    ##      data = seqOf[int,byte]([0x5C01, 0x0A] # is equivalent to 
    ##      data: seq[byte] = @[0x01'ui8, 0x0A'ui8]
    
    map[T, N](buff, proc (x: T): N = x.N)


proc toHex*[T](buff: openarray[T], prefixed: bool = true): string =
   result = foldl(buff, a & toHex((BiggestInt)b, T.sizeOf * 2), if prefixed: "0x" else: "")
   # note-1: cannot use foldl (buff, toHex() & toHex()) form  as the 1st param type does not match. Cannot change type inline of a?
   # note-2: needs extra parameter to change API signature otherwise it conflicts? with standard toHex[T](x: T): string


proc fromHex*(s: string): seq[byte] =
    ## Parses a hexadecimal sequence contained in `s`.
    ##
    ## If `s` is not a valid hex array, `ValueError` is raised. `s` can have one
    ## of the following optional prefixes: ``0x``, ``0X``, ``#``.  Underscores
    ## within `s` are ignored.
    var
        i = 0
        j = 0 # nibbles found
        startPot = false
        lsn, msn: byte # less/most significant nibble

    if s[i] == '0' and (s[i+1] == 'x' or s[i+1] == 'X'): inc(i, 2)
    elif s[i] == '#': inc(i)

    result = @[]

    while i < s.len:
        msn = lsn
        case s[i]
        of '_', ':', '-':
            inc(i)
            startPot = false
        of '0'..'9':
            lsn = (ord(s[i]) - ord('0')).byte
            inc(i)
            inc(j)
            startPot = true
        of 'a'..'f':
            lsn = (ord(s[i]) - ord('a') + 10).byte
            inc(i)
            inc(j)
            startPot = true
        of 'A'..'F':
            lsn = (ord(s[i]) - ord('A') + 10).byte
            inc(i)
            inc(j)
            startPot = true
        of '\0': break
        else: raise newException(ValueError, "invalid hex: " & s)

        if startPot and ((j and 1) == 0): 
            result.add(msn shl 4 or lsn)
    
    # leading zero if odd length of input
    if (j and 1) == 1:
        result.add(lsn shl 4)
        msn = 0'u8
        for i in 0 .. <result.len:
            lsn = result[i] and 0x0F'u8
            result[i] = (result[i] shr 4) or (msn shl 4)
            msn = lsn

