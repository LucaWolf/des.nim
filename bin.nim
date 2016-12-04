import strutils, sequtils, endians, typeinfo
include bin_utils

#-----------------
proc rol*[T](x: T, y: int8): T =
    let n = 8 * sizeof(x).T # how many bits in x
    result = (x shl (y and <n)) or (x shr (n - (y and <n)))

#-----------------
proc ror*[T](x: T, y: int8): T =
    let n = 8 * sizeof(x).T # how many bits in x
    result = (x shr (y and <n)) or (x shl (n - (y and <n)))

#-----------------

type
    binBufferObj = object
        data: cstring
        size: int
        view: Slice[int]
    binBuffer* = ref binBufferObj


proc len*(buff: binBuffer): int =
    result = buff.view.b - buff.view.a + 1


proc setlen*(buff: var binBuffer, n: int) =
    if n > 0:
        buff.view.b = (buff.view.a + <n).clamp(0, <buff.size)

proc resetlen*(buff: var binBuffer) =
    buff.view = 0 .. <buff.size
        
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
        swap(result.view.a, result.view.b)

#-----------------------
const maskbit* = [0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01]

template testBit*[T: binBuffer|openArray[byte]](buff: T, idx: int): bool = 
    var result: bool = false
    if idx > (buff.len * 8 - 1):
        result = false
    else:
        var mask =  maskbit[idx and 7]
        result = (buff[idx div 8] and mask.byte) != 0
    result
#---
proc setBit*(buff: binBuffer, idx: int) =
    if idx <= (buff.len * 8 - 1):
        var mask =  maskbit[idx and 7]
        buff[idx div 8] = buff[idx div 8] or mask.byte

proc setBit*(buff: var openArray[byte], idx: int) =
    if idx <= (buff.len * 8 - 1):
        var mask =  maskbit[idx and 7]
        buff[idx div 8] = buff[idx div 8] or mask.byte
#---
proc resetBit*(buff: binBuffer, idx: int) =
    if idx <= (buff.len * 8 - 1):
        var mask =  maskbit[idx and 7]
        buff[idx div 8] = buff[idx div 8] and not(mask.byte)

proc resetBit*(buff: var openArray[byte], idx: int) =
    if idx <= (buff.len * 8 - 1):
        var mask =  maskbit[idx and 7]
        buff[idx div 8] = buff[idx div 8] and not(mask.byte)

#-----------------------
iterator items*(buff: binBuffer): byte =
  let noItems = (buff.view.b - buff.view.a)
  for n in 0..noItems:
    yield buff[n]

iterator pairs*(buff: binBuffer): tuple[key: int, val: byte] =
  var i = 0
  while i < len(buff):
    yield (i, buff[i])
    inc(i)

iterator mitems*(buff: binBuffer): var byte =
  let noItems = (buff.view.b - buff.view.a)
  for n in 0..noItems:
    yield buff[n]

#-----------------------
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
        dst[at + i] = src[frame.a + i]


template copyTo*(src: typed; dst: typed; at:int = 0) =
    copyTo(src, 0 .. src.len(), dst, at)
    

template copyLastTo*(src: typed; last: int; dst: typed; at:int = 0) =
    copyTo(src, src.len() - last .. src.len(), dst, at)
    
#-----------------------
proc load64BE*(data: openArray[byte]; pos: int = 0): int64 =
    result = (cast[int64](data[pos])   shl 56) or
             (cast[int64](data[pos+1]) shl 48) or
             (cast[int64](data[pos+2]) shl 40) or
             (cast[int64](data[pos+3]) shl 32) or
             (cast[int64](data[pos+4]) shl 24) or
             (cast[int64](data[pos+5]) shl 16) or
             (cast[int64](data[pos+6]) shl 8) or
             (cast[int64](data[pos+7]))

proc store64BE*(value: int64; data: var openArray[byte], pos: int = 0) =
    data[pos] = (value shr 56) and 0xFF
    data[pos+1] = (value shr 48) and 0xFF
    data[pos+2] = (value shr 40) and 0xFF
    data[pos+3] = (value shr 32) and 0xFF
    data[pos+4] = (value shr 24) and 0xFF
    data[pos+5] = (value shr 16) and 0xFF
    data[pos+6] = (value shr 8) and 0xFF
    data[pos+7] = value and 0xFF

# string data
proc load64BE*(data: string; pos: int = 0): int64 =
    result = (cast[int64](data[pos].ord())   shl 56) or
             (cast[int64](data[pos+1].ord()) shl 48) or
             (cast[int64](data[pos+2].ord()) shl 40) or
             (cast[int64](data[pos+3].ord()) shl 32) or
             (cast[int64](data[pos+4].ord()) shl 24) or
             (cast[int64](data[pos+5].ord()) shl 16) or
             (cast[int64](data[pos+6].ord()) shl 8) or
             (cast[int64](data[pos+7].ord()))



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
