import strutils, sequtils
import ../des/bin
import ../des/bin_buffer


var
    data = [0xAA.byte, 1, 0x55, 3, 0xF0, 5, 6, 7, 8, 9]
    mask = [9.byte, 8, 7, 7]
    mask_odd = [0.byte, 0x55]
    lastChunk: array[8, byte]
    txt = "123456789"
    b1, b2: binBuffer
    dataMasked: seq[byte]


b1 = data.toBinBuffer()
echo b1.toHex(true)

while b1.len > 8:
    echo b1[0..7].toHex(true)
    b1 = b1[8..^1]

b2 = lastChunk.toBinBuffer()
copyTo(b2, b1)
echo b2.toHex(true)
echo b1.toHex(true)


b2 = txt.toBinBuffer()[2..^1]
echo "Txt $1 has len=$2, slice b2 has len=$3" % [txt, $txt.len, $b2.len]

b2[^1] = ord('E')
b2[0] = 'A'
b2[1] = 0x39
echo "Modified b2=", txt

var byte_AA_bits = [true, false, true, false, true, false, true, false]
var byte_55_bits = [false, true, false, true, false, true, false, true]

#test byte 0
echo "B0 testing ", $data[0]
for n in 0..7:
     assert(byte_AA_bits[n] == testBit(data, n), "B0-direct bit $1 not matching" % $n)
data[0] = data[0] xor 0xFF'u8

echo "B0 rev testing ", $data[0]
for n in 0..7:
     assert(byte_55_bits[n] == testBit(data, n), "B0-reversed bit $1 not matching" % $n)
data[0] = data[0] xor 0xFF'u8

#test byte 2
echo "B2 testing ", $data[2]
for n in 16..23:
     assert(byte_55_bits[n-16] == testBit(data, n), "B2-direct bit $1 not matching" % $n)
data[2] = data[2] xor 0xFF'u8

echo "B2 rev testing ", $data[2]
for n in 16..23:
     assert(byte_AA_bits[n-16] == testBit(data, n), "B2-reversed bit $1 not matching" % $n)
data[2] = data[2] xor 0xFF'u8

#test byte 2 via binBuffer i/face
echo "B2 iface testing ", $data[2]
for n in 0..7:
     assert(byte_55_bits[n] == testBit(data.toBinBuffer[2..2], n), "B2-direct-buff bit $1 not matching" % $n)
data[2] = data[2] xor 0xFF'u8

echo "B2 rev iface testing ", $data[2]
for n in 0..7:
     assert(byte_AA_bits[n] == testBit(data.toBinBuffer[2..2], n), "B2-reversed-buff bit $1 not matching" % $n)
data[2] = data[2] xor 0xFF'u8

#----
data.resetBit(8*2 + 1)
echo "B2 reset testing ", $data[2]
assert(false == testBit(data.toBinBuffer[2..^1], 1), "B2 bit 1 not reset")
assert(false == testBit(data, 8*2 + 1), "B2 bit 1 not reset")

#---
data.setBit(8*2 + 1)
echo "B2 set testing ", $data[2]
assert(true == testBit(data.toBinBuffer[2..^1], 1), "B2 bit 1 not set")
assert(true == testBit(data, 8*2 + 1), "B2 bit 1 not set")


# tests with new seq returned
dataMasked = mapWith(data, mask, `xor`)
echo "dataMasked(xor seq / seq) = ", $dataMasked

dataMasked = mapWith(data, mask, `or`)
echo "dataMasked(or  seq / seq) = ", $dataMasked

applyWith(data, mask_odd, `and`)
echo "dataTrimm (and seq / seq) = ", repr data

dataMasked = mapWith(data.toBinBuffer(), mask.toBinBuffer(), `xor`)
echo "dataMasked(xor buff/buff) = ", $dataMasked

dataMasked = mapWith(data, mask.toBinBuffer(), `xor`)
echo "dataMasked(xor seq /buff) = ", $dataMasked

dataMasked = mapWith(data.toBinBuffer() , mask, `xor`)
echo "dataMasked(xor buff/ seq) = ", $dataMasked


# tests with inplace masking

let a = ["a0","a1","a2","a3","a4","a5","a6","a7","a8","a9"]
echo a[5 ..> 3]
echo a[5 ..> ^3]

echo "ascending indeces:"
for i in 5 ..> 3: echo i

echo "descending indeces:"
for i in 5 ..> ^7: echo i