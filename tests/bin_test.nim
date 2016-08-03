import strutils, sequtils
import ../des_api


var
    data = seqOf[int,byte](@[0, 1, 2, 3, 4, 5, 6, 7, 8, 9])
    mask = seqOf[int,byte](@[9, 8, 7, 7])
    lastChunk = newSeq[byte](8)
    txt = "123456789"
    b1, b2: binBuffer


b1 = data.toBinBuffer()
echo b1.toHex(true)

while b1.len > 8:
    echo b1[0..7].toHex(true)
    b1 = b1[8..^1]

b2 = lastChunk.toBinBuffer()
b2.copy(b1)
echo b2.toHex(true)


b2 = txt.toBinBuffer()[2..^1]
echo "Txt $1 has len=$2, slice b2 has len=$3" % [txt, $txt.len, $b2.len]

b2[<b2.len] = ord('E')
echo "Modified b2=", txt

var dataMasked = data.toBinBuffer() xor mask.toBinBuffer()
echo "dataMasked = ", $dataMasked

var dataMasked1 = data xor mask.toBinBuffer()
echo "dataMasked1 = ", $dataMasked1


