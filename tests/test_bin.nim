import strutils, sequtils, bin


var
    data = mapLiterals([0xAA, 1, 0x55, 3, 0xF0, 5, 6, 7, 8, 9], byte)
    mask = mapLiterals([9, 8, 7, 7], byte)
    mask_odd = mapLiterals([0x4E, 0x55, 0x27], byte)
    dataMasked: seq[byte]
    bitOffset = 0


var byte_AA_bits = [true, false, true, false, true, false, true, false]
var byte_55_bits = [false, true, false, true, false, true, false, true]

echo "=== BIN tests ==="

bitOffset = (data.len - 1) * 8 # point to bit start of 0xAA

# echo "B0 testing", $data[0]
for n in 0..7:
     assert(byte_AA_bits[7 - n] == testBit(data, n + bitOffset), "B0-direct bit $1 not matching" % $n)
data[0] = data[0] xor 0xFF'u8

# echo "B0 rev testing ", $data[0]
for n in 0..7:
     assert(byte_55_bits[7 - n] == testBit(data, n + bitOffset), "B0-reversed bit $1 not matching" % $n)
data[0] = data[0] xor 0xFF'u8


#echo "B2 testing ", $data[2]
bitOffset = (data.len - 3) * 8 # point to bit start of 0x55

for n in 0..7:
     assert(byte_55_bits[7 -  n] == testBit(data, n + bitOffset), "B2-direct bit $1 not matching" % $n)
data[2] = data[2] xor 0xFF'u8

#echo "B2 rev testing ", $data[2]
for n in 0..7:
     assert(byte_AA_bits[7 - n] == testBit(data, n + bitOffset), "B2-reversed bit $1 not matching" % $n)
data[2] = data[2] xor 0xFF'u8


#----
data.clearBit(8*2 + 1)
#echo "B2 reset testing ", $data[2]
assert(false == testBit(data, 8*2 + 1), "B2 bit 1 not reset")
#---
data.setBit(8*2 + 1)
#echo "B2 set testing ", $data[2]
assert(true == testBit(data, 8*2 + 1), "B2 bit 1 not set")


# mapWith XOR
let expectedResXOR = mapLiterals([
          data[0] xor mask[0], # loop 1
          data[1] xor mask[1],
          data[2] xor mask[2],
          data[3] xor mask[3],
          data[4] xor mask[0], # loop 2
          data[5] xor mask[1],
          data[6] xor mask[2],
          data[7] xor mask[3],
          data[8] xor mask[0], # loop 3
          data[9] xor mask[1]
    ], byte)
dataMasked = mapWith(data, mask, `xor`)
assert(dataMasked == expectedResXOR, "\nmapWith 'xor' failed:\n$# vs.\n$#" % [$dataMasked, $expectedResXOR])


# mapWith OR
let expectedResOR = mapLiterals([
          data[0] or mask[0], # loop 1
          data[1] or mask[1],
          data[2] or mask[2],
          data[3] or mask[3],
          data[4] or mask[0], # loop 2
          data[5] or mask[1],
          data[6] or mask[2],
          data[7] or mask[3],
          data[8] or mask[0], # loop 3
          data[9] or mask[1]
     ], byte)
dataMasked = mapWith(data, mask, `or`)
assert(dataMasked == expectedResOR, "\nmapWith 'or' failed:\n$# vs.\n$#" % [$dataMasked, $expectedResOR])

# applyWith AND
let expectedResAND = mapLiterals([
          data[0] and mask_odd[0], # loop 1
          data[1] and mask_odd[1],
          data[2] and mask_odd[2],
          data[3] and mask_odd[0], # loop 2
          data[4] and mask_odd[1],
          data[5] and mask_odd[2],
          data[6] and mask_odd[0], # loop 3
          data[7] and mask_odd[1],
          data[8] and mask_odd[2],
          data[9] and mask_odd[0] # loop 4
     ], byte)
applyWith(data, mask_odd, `and`)
assert(data == expectedResAND, "\napplyWith 'and' failed:\n$# vs.\n$#" % [$data, $expectedResAND])


# sized-range of 3 elements: 5,6,7
assert(5 ..> 3 == 5..7, "\npositive range 'b' elements including 'a' failed")
# sized-range of 7 elements: -2,-1,0,1,2,3,4
assert(5 ..> ^7 == -2..4, "\nnegative range 'b' elements before (but excluding) 'a' failed]")

# slices from sized-range
let a = ["a0","a1","a2","a3","a4","a5","a6","a7","a8","a9"]
assert(a[5 ..> 3] == ["a5", "a6", "a7"], "\npositive slice failed")
assert(a[5 ..> ^3] == ["a2", "a3", "a4"], "\nnegative slice failed")
assert(a[^4 ..> 3] == ["a6", "a7", "a8"], "\npositive slice end failed")
assert(a[^4 ..> ^6] == ["a0", "a1", "a2", "a3", "a4", "a5"], "\nnegative slice end failed")

let val = @[0b1100_1001'i8, 0b0001_0100'i8]
for n in {2,4,8,11,14,15}:
    assert(testBit(val, n), "Bit $# is not set" % $n)

let res1 = mapWith(@[0x0A, 0x0B, 0x0C, 0x0D], @[0x80, 0x40], `or`)
assert(res1 == @[0x8A, 0x4B, 0x8C, 0x4D], "mapWith short seq failed")

var res2 = @[0x0A, 0x0B, 0x0C, 0x0D]
applyWith(res2, @[0x88, 0x48], `xor`)
assert(res2 == @[0x82, 0x43, 0x84, 0x45], $res2.mapIt(toHex(it)))

echo "=== passed ==="


