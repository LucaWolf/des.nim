import strutils, sequtils

#--- add here required converters
converter i64ToU32*(x: int64): uint32 =
    result = x.uint32
converter iToU8(x: int): uint8 =
    result = x.uint8
#---

#-----------------------
template seqOf*[T,N] (buff: openarray[T]): seq[N] =
    ## Script to help with declaration of new sequences of type N based on an array of 
    ## values of type T. Internally, a conversion call *proc (x: T): N = x.N*
    ## is attempted, so the conversion function would better exists already.
    ## 
    map[T, N](buff, proc (x: T): N = x.N)


proc toHex*[T](buff: T, prefixed: bool = true): string =
    ## Note: buff must implement items iterator 
    type itemType = type(items(buff))
    result = foldl(buff, a & toHex((BiggestInt)b, itemType.sizeOf * 2), if prefixed: "0x" else: "")
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

