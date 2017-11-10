import strutils, sequtils, endians, typeinfo
include bin_utils

const maskbit* = [0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01]

#-----------------
proc rol*[T](x: T, y: int8): T =
    let n = 8 * sizeof(x).T # how many bits in x
    result = (x shl (y and <n)) or (x shr (n - (y and <n)))

#-----------------
proc ror*[T](x: T, y: int8): T =
    let n = 8 * sizeof(x).T # how many bits in x
    result = (x shr (y and <n)) or (x shl (n - (y and <n)))

proc `<--`*[D,S](d: var D, s: S) =
    ## Assigns a value of type 'S' to a value of type 'D'
    ## D <-> S are usually char <-> byte/int; any other types will 
    ## use the plain '=' assignment (so it may fail to compile or raise exceptions).
    ## All this to avoid char <-> byte converters which may have global side effects
    
    # prioritise clear cut cases
    when (S, D) is (char, byte):
        d = ord(s).byte
    elif (S, D) is (byte, char):
        d = char(s)
    # the rest of the integer scope
    elif (S, D) is (SomeInteger, char):
        d = char(toU8(s.int)) # expect truncations
    elif (S, D) is (char, SomeInteger):
        d = ord(s).D
    # fallback to generic assignment
    else:
        d = s

#-----------------
# this allows mixing string and integers parametrs for mapWith, applyWith
#-----------------
proc `xor`*[T: SomeInteger|byte](c: char, n: T): char =
    result = char(ord(c).T xor n)

proc `or`*[T: SomeInteger|byte](c: char, n: T): char =
    result = char(ord(c).T or n)

proc `and`*[T: SomeInteger|byte](c: char, n: T): char =
    result = char(ord(c).T and n)

proc `shl`*[T: SomeInteger|byte](c: char, n: T): char =
    result = char(ord(c).T shl n)

proc `shr`*[T: SomeInteger|byte](c: char, n: T): char =
    result = char(ord(c).T shr n)

proc `div`*[T: SomeInteger|byte](c: char, n: T): char =
    result = char(ord(c).T div n)

proc `mod`*[T: SomeInteger|byte](c: char, n: T): char =
    result = char(ord(c).T mod n)

#-----------------
template testBit*(buff: typed, idx: int): bool = 
    var result: bool = false
    if idx > (buff.len * 8 - 1):
        result = false
    else:
        var mask =  maskbit[idx and 7]
        result = (buff[idx div 8] and mask.byte) != 0
    result

template setBit*(buff: typed, idx: int) =
    if idx <= (buff.len * 8 - 1):
        var mask =  maskbit[idx and 7]
        buff[idx div 8] = buff[idx div 8] or mask.byte

template resetBit*(buff: typed, idx: int) =
    if idx <= (buff.len * 8 - 1):
        var mask =  maskbit[idx and 7]
        buff[idx div 8] = buff[idx div 8] and not(mask.byte)

#-----------------
template mapWith*(buff, mask: typed; action: untyped): untyped =
    var
        result = newSeq[type(items(buff))](buff.len)
        n = mask.len
        i = 0
        j = 0

    for val in items(buff):
        result[i] = action(val, mask[j])
        inc(i)
        if j == <n: j = 0 else: inc(j) 
    result

# in-place operation
template applyWith*(buff, mask: typed, action: untyped): typed =
    var
        n = mask.len
        j = 0

    for val in mitems(buff):
        val = action(val, mask[j])
        if j == <n: j = 0 else: inc(j) 

#-----------------------
# for easy of access, the slice holds the length (.b points to next element)
template copyTo*(src: typed; frame: Slice[int]; dst: typed; at:int = 0) =
    var n = (frame.b - frame.a).clamp(0, dst.len - at)

    for i in 0 .. <n:
        dst[at + i] <-- src[frame.a + i]


template copyTo*(src: typed; dst: typed; at:int = 0) =
    copyTo(src, 0 .. src.len(), dst, at)
    

template copyLastTo*(src: typed; last: int; dst: typed; at:int = 0) =
    copyTo(src, src.len() - last .. src.len(), dst, at)


#-----------------------
template storeHigh*[T: SomeInteger](data: var typed, value: T; offset: int = 0) =
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

