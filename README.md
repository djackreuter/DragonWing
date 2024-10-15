# DragonWing

Downloads and executes encrypted MimiKatz in memory.

MimiKatz PE file is manually loaded into memory and all section headers are encrypted in memory at rest. PE file is executed via Fiber. CPU intensive mathematical calculations are peppered in for delay.

### Usage:
0. [Rc4 encrypt](https://github.com/djackreuter/shellcode-encryption) mimikatz.exe and host on a web server.
1. Update `BYTE Rc4Key[KEY_SIZE]` on line 25 with the resulting Rc4 key, and update `char sURL[]` on line 732 ( both in `DragonWing.c` ) to your web server url where you are hosting mimikatz.exe.
2. compile.
3. profit.
