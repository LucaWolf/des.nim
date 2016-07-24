import strutils, bin

var
    data = seqOf[int,byte](@[0, 1, 2, 3, 4, 5, 6, 7, 8, 9])
    lastChunk = newSeq[byte](8)
    txt = "123456789"
    b1, b2: binBuffer


b1 = data.toBinBuffer()
echo b1.toHex()

while b1.len > 8:
    echo b1[0..7].toHex()
    b1 = b1[8..^1]

b2 = lastChunk.toBinBuffer()
b2.copy(b1)
echo b2.toHex()


b2 = txt.cstring.toBinBuffer()[2..^1]
echo "Txt $1 has len=$2, slice b2 has len=$3" % [txt, $txt.len, $b2.len]

b2[<b2.len] = ord('E')
echo "Modified b2=", txt



