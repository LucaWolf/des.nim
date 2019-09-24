import strutils, sequtils, endians, typeinfo, bitops

#-----------------
# this allows mixing string and integers parameters for mapWith, applyWith
#-----------------
proc `xor`*[T: SomeInteger|byte](c: char, n: T): char =
    ## Allows 'xor' for char type (as bit pattern)
    result = char(ord(c).T xor n)

proc `or`*[T: SomeInteger|byte](c: char, n: T): char =
    ## Allows 'or' for char type (as bit pattern)
    result = char(ord(c).T or n)

proc `and`*[T: SomeInteger|byte](c: char, n: T): char =
    ## Allows 'and' for char type (as bit pattern)
    result = char(ord(c).T and n)

proc `shl`*[T: SomeInteger|byte](c: char, n: T): char =
    ## Allows 'shl' for char type (as bit pattern)
    result = char(ord(c).T shl n)

proc `shr`*[T: SomeInteger|byte](c: char, n: T): char =
    ## Allows 'shr' for char type (as bit pattern)
    result = char(ord(c).T shr n)

proc `div`*[T: SomeInteger|byte](c: char, n: T): char =
    ## Allows 'div' for char type (as bit pattern)
    result = char(ord(c).T div n)

proc `mod`*[T: SomeInteger|byte](c: char, n: T): char =
    ## Allows 'mod' for char type (as bit pattern)
    result = char(ord(c).T mod n)

#-----------------
proc testBit*[T: byte|int8](buff: openArray[T], idx: int): bool = 
    ## Tests if bit at position `idx` (bn..b1b0 order) is set in array.
    ##
    ## .. code-block:: Nim
    ##  let val = @[0b1100_1001'i8, 0b0001_0100'i8]
    ##  for n in {2,4,8,11,14,15}:
    ##      assert(testBit(val, n), "Bit $# is not set" % $n)
    ##  
    if idx > (buff.len * 8 - 1):
        result = false
    else:
        let n = succ(idx div 8)
        result = testBit(buff[^n], idx and 7)
        
proc setBit*[T: byte|int8](buff: var openArray[T], idx: int) =
    ## Sets bit at position `idx` (bn..b1b0 order) in array.
    if idx <= (buff.len * 8 - 1):
        let n = succ(idx div 8)
        setBit(buff[^n], idx and 7)

proc clearBit*[T: byte|int8](buff: var openArray[T], idx: int) =
    ## Clears bit at position `idx` (bn..b1b0 order) in array.
    if idx <= (buff.len * 8 - 1):
        let n = succ(idx div 8)
        clearBit(buff[^n], idx and 7)


#-----------------
template mapWith*(buff, mask: typed; action: untyped): untyped =
    ## Creates a new sequence of same type as `buff`,
    ## applying `action` to each pair of (`buff`,`mask`)
    ##
    ## Note: the `mask` can be shorter than `buff` input, in which case it wraps around,
    ## e.g. mask1, mask2, mask3, mask1, mask2, etc. gets apply to a long input array
    ##
    ## .. code-block:: Nim
    ##  let dataMasked = mapWith(@[0x0A, 0x0B, 0x0C, 0x0D], @[0x80, 0x40], `or`)
    ##  assert(dataMasked == @[0x8A, 0x4B, 0x8C, 0x4D])
    var
        result = newSeq[type(items(buff))](buff.len)
        n = mask.len
        i = 0
        j = 0

    for val in items(buff):
        result[i] = action(val, mask[j])
        inc(i)
        if j == n.pred: j = 0 else: inc(j) 
    result

# in-place operation
template applyWith*(buff, mask: typed, action: untyped) =
    ## Applies `action` with the circular `mask` to the `buff` input
    ##
    ## .. code-block:: Nim
    ##  var dataMasked = @[0x0A, 0x0B, 0x0C, 0x0D]
    ##  applyWith(dataMasked, @[0x88, 0x48], `xor`)
    ##  assert(dataMasked == @[0x82, 0x43, 0x84, 0x45])
    var
        n = mask.len
        j = 0

    for val in mitems(buff):
        val = action(val, mask[j])
        if j == n.pred: j = 0 else: inc(j) 

#-----------------------
template `..>`*[T, U](a: T, b: U): untyped =
    ## Binary slice operator constructing an interval based on offsset 'a' and length 'b'.
    ## 'b' can always be a BackwardsIndex. When combined with [] slicing, 'a' can also be a BackwardsIndex.
    ##
    ## When the length is BackwardsIndex then the resulting interval provides 'b' indeces before (excluding) 'a',
    ## otherwise the resulting interval provides 'b' indeces starting with (including) 'a'

    when b is BackwardsIndex:
        when a is BackwardsIndex:
            ^(a.int + b.int) .. ^(succ(a.int))
        else:
            (a - T(b)) .. pred(a)
    else:
        when a is BackwardsIndex:
            a .. ^(U(a) - pred(b))
        else:
            a .. pred(a + b)
    

iterator `..>`*[T, U](a: T, b: U): T =
    ## Iterates over a `..>` range as above. Unlike the slicing usage, `a` cannot be BackwardsIndex.
    when b is BackwardsIndex:
        var i = a - T(b)
        while i < a:
            yield i
            inc i
    else:
        var i = a
        while i < (a + b):
            yield i
            inc i

#-----------------------
proc `<--`*[D,S](d: var D, s: S) =
    ## Assigns (copy) a value of type 'S' to a value of type 'D'.
    ##
    ## D <-> S are usually char <-> byte/int; any other types will 
    ## use the plain '=' assignment (so it may fail to compile or raise exceptions).
    ##
    ## All this to avoid char <-> byte converters which may have global side effects.
    
    # prioritise clear cut cases
    when (S, D) is (char, byte):
        d = ord(s).byte
    elif (S, D) is (byte, char):
        d = char(s)
    # the rest of the integer scope
    elif (S, D) is (SomeInteger, char):
        d = char(s.uint) # should not be here: expect truncations or sign conversion errors
    elif (S, D) is (char, SomeInteger):
        d = ord(s).D
    # fallback to generic assignment
    else:
        d = s

template copyTo*(src: typed; frame: Slice[int]; dst: typed; at: int = 0) =
    ## copies elements from src[] into dst[at..]
    ##
    ## dst (var) is not protected from overflow
    var n = min(frame.b - frame.a, pred(dst.len - at))

    for i in 0 .. n:
        dst[at + i] <-- src[frame.a + i]


template copyTo*(src: typed; dst: typed; at: int = 0) =
    ## copies all elements from src into dst[at..]
    ##
    ## dst (var) is not protected from overflow
    copyTo(src, 0 ..> src.len, dst, at)
    

template copyLastTo*(src: typed; n: int; dst: typed; at: int = 0) =
    ## copies the last 'n' elements from src into dst[at..]
    ##
    ## dst (var) is not protected from overflow
    copyTo(src, src.len ..> ^n, dst, at)



#-----------------------
template storeHigh*[T: SomeInteger](data: var typed, value: T; offset: int = 0) =
    ## Saves the `value` in binary format (big-endian) at the `offset` position
    ## in the input `data` buffer
    ##
    ## .. code-block:: Nim
    ##  let value = 0xABCD.uint16
    ##  var binData = newSeq[byte](8)
    ##  storeHigh(binData, value, 3)
    ##  assert(binData == @[0x00, 0x00, 0x00, 0xAB, 0xCD, 0x00, 0x00, 0x00])

    # todo: version with test capacity

    var o: pointer = addr data[offset]
    var i: pointer = unsafeAddr value

    case sizeof(value)
    of 2:
        bigEndian16(o, i)
    of 4:
        bigEndian32(o, i)
    of 8:
        bigEndian64(o, i)
    else:
        assert(false, "Invalid input type: " & $sizeof(value))



template loadHigh*[T: SomeInteger](data: typed, value: var T, offset: int = 0) =
    ## Loads an integer `value` from a binary formated (big-endian) input `data` buffer
    ## starting at the `offset` position
    ##
    ## .. code-block:: Nim
    ##  var value: uint32
    ##  let binData = @[0x00, 0x00, 0x00, 0xCD, 0x00, 0xFF, 0x00, 0x00]
    ##  loadHigh(binData, value, 3)
    ##  assert(value == 0xCD00FF00)

    var i: pointer = unsafeAddr data[offset]
    var o: pointer = addr value

    case sizeof(value)
    of 2:
        bigEndian16(o, i)
    of 4:
        bigEndian32(o, i)
    of 8:
        bigEndian64(o, i)
    else:
        assert(false, "Invalid input type: " & $sizeof(value))



#-----------------------
proc toHex*[T](buff: openArray[T], prefixed: bool = true): string =
    ## Note: buff must implement items iterator 
    
    result = foldl(buff, a & strutils.toHex((BiggestInt)b, T.sizeof * 2), if prefixed: "0x" else: "")
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
        for i in 0 .. result.len.pred:
            lsn = result[i] and 0x0F'u8
            result[i] = (result[i] shr 4) or (msn shl 4)
            msn = lsn
