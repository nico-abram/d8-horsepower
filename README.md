# picoCTF v8 HorsePower challenge

Solution to the [v8 HorsePower challenge in picoCTF](https://play.picoctf.org/practice/challenge/135). Start reading in step1-readwrite-heap for an explanation, then step2, step3, shellcode.js and payload.c and then exploit.js . step1-readwrite-heap-orig.js is the first version of step1 I initially used, before realizing I could simplify it a bit (Which is step1-readwrite-heap.js)

NOTE: The files should (All except exploit.js) be run using d8 with the `--allow-natives-syntax` to enable `%DebugPrint`
Using `%DebugPrint` lets you check against the expect pointers easily, without having to muck around in gdb
Example:

`./d8 step1-readwrite-heap.js --allow-natives-syntax`

All the scripts end in an infinite loop, so that you can breakpoint if running in gdb

# Instructions

To send the exploit on windows:

`type .\exploit.js | python .\send.py`

On linux:

`cat ./exploit.js | python2 ./send.py`

Generate shellcode for payload.c (In linux/WSL):

`node shellcode.js`

(Copy stdout to the machine_code array in exploit.js)

Generate shellcode, put it in exploit.js, and send it(In linux/WSL):

`node ./setup_and_run.js`

# Further reading

[v8 blog on fast properties](https://v8.dev/blog/fast-properties)

[v8 docs on using d8](https://v8.dev/docs/d8)

[Exploiting v8: \*CTF 2019 oob-v8](https://faraz.faith/2019-12-13-starctf-oob-v8-indepth/)

[Comprehensive guide to browser exploitation](https://mgp25.com/browser-exploitation/)

[Assembly language files and Shellcode](https://github.com/reg1reg1/Shellcode)

[Stackoverflow answer on how to invoke syscalls with inline assembly](https://stackoverflow.com/a/9508738/8414238)

[getdents manpage example](https://man7.org/linux/man-pages/man2/getdents.2.html)

[strace examples](https://www.thegeekstuff.com/2011/11/strace-examples/)

## Helpful tools

[Godbolt Online Compiler Explorer](https://godbolt.org/)

[Online x86 assembler](https://defuse.ca/online-x86-assembler.htm)

[gdb gef](https://gef.readthedocs.io/en/master/)
