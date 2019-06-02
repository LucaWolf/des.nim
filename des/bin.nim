import strutils, sequtils, endians, typeinfo
include bin_utils

const maskbit* = [0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01]

#-----------------
proc rol*[T](x: T, y: int8): T =
    let n = T(8 * sizeof(x)) # how many bits in x
    result = (x shl (y.T and n.pred)) or (x shr (n - (y.T and n.pred)))

#-----------------
proc ror*[T](x: T, y: int8): T =
    let n = T(8 * sizeof(x)) # how many bits in x
    result = (x shr (y.T and n.pred)) or (x shl (n - (y.T and n.pred)))

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
proc testBit*[T](buff: T, idx: int): bool = 
    if idx > (buff.len * 8 - 1):
        result = false
    else:
        var mask =  maskbit[idx and 7]
        result = (buff[idx div 8] and mask.byte) != 0

proc setBit*[T](buff: var T, idx: int) =
    if idx <= (buff.len * 8 - 1):
        var mask =  maskbit[idx and 7]
        buff[idx div 8] = buff[idx div 8] or mask.byte

proc resetBit*[T](buff: var T, idx: int) =
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
        if j == n.pred: j = 0 else: inc(j) 
    result

# in-place operation
template applyWith*(buff, mask: typed, action: untyped): typed =
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
template copyTo*(src: typed; frame: Slice[int]; dst: typed; at:int = 0) =
    ## copies elements from src[] into dst[at..]
    ## dst (var) is not protected from overflow
    var n = min(frame.b - frame.a, pred(dst.len - at))
    var i = 0

    for i in 0 .. n:
        dst[at + i] <-- src[frame.a + i]


template copyTo*(src: typed; dst: typed; at:int = 0) =
    ## copies all elements from src into dst[at..]
    ## dst (var) is not protected from overflow
    copyTo(src, 0 ..> src.len, dst, at)
    

template copyLastTo*(src: typed; n: int; dst: typed; at:int = 0) =
    ## copies the last 'n' elements from src into dst[at..]
    ## dst (var) is not protected from overflow
    copyTo(src, src.len ..> ^n, dst, at)





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


template `:=`*(a, b): untyped {.dirty.}=
    let a = b;
    a
