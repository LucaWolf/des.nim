import strutils, sequtils, endians, typeinfo

# this i/face is useless... to become obsolete at some point.
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
    
 
proc `[]=`*[T](buff: binBuffer, n: int, val: T) =
    if n  > <buff.len:
        raise newException(IndexError, "Invalid index: " & $n)

    when T is char:
        buff.data[buff.view.a + n] = val
    else: # assume some sort of integer
        buff.data[buff.view.a + n] = char(val)


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

