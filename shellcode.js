#!/usr/bin/node

// Compile payload.c , extract .text section, hexdump and then turn into js array with correct order of bytes
// You should copy stdout from this program into the shellcode array in exploit.js

const { exec, spawn } = require("child_process");
exec(
  //gcc -nostdlib -O3 -o payload payload.c && objcopy -j.text -O binary payload payload.bin && hexdump -v -e '"\""x" 1/1 "%02x" ""' payload.bin
  'gcc -nostdlib -O3 -o payload payload.c && objcopy -j.text -O binary payload payload.bin && hexdump -v -e \'"\\\\""x" 1/1 "%02x" ""\' payload.bin',
  undefined,
  function (err, stdout, stderr) {
    let x = stdout.substr(2, stdout.length - 2);

    let res = "";
    let a = x.split("\\x");
    var i = 0;
    res +=
      "0x" +
      a[i + 3].padStart(2, "0") +
      a[i + 2].padStart(2, "0") +
      a[i + 1].padStart(2, "0") +
      a[i].padStart(2, "0");
    for (i = 4; i < a.length; ) {
      res += ", 0x";
      if (i + 3 < a.length) {
        res += a[i + 3].padStart(2, "0");
      } else {
        res += "00";
      }
      if (i + 2 < a.length) {
        res += a[i + 2].padStart(2, "0");
      } else {
        res += "00";
      }
      if (i + 1 < a.length) {
        res += a[i + 1].padStart(2, "0");
      } else {
        res += "00";
      }
      res += a[i].padStart(2, "0");
      i += 4;
    }
    console.log(res);
  }
);
