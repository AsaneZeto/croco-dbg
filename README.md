# Croco-dbg
Croco-dbg is a tiny debugger for x86-64 Linux based on ptrace and FreeBSD libraries 

# Build and Start
At first, get a clone of [linenoise](https://github.com/antirez/linenoise)
```
git submodule update --init
```
(Optional) Install FreeBSD library if you don't have them in your system
```
sudo apt-get install libelf-dev libdw-dev libdwarf-dev
```
Then just make it.
```
make
```
Launch Croco with you executable, enjoy it! 
```
./croco [executable]
```
# Commands
* help (h): Show command description
* break (b): Breakpoint-relative operations
    * [dump]: Show all existed breakpoints
    * [0xADDRESS]: Set a memory address as a breakpoint
    * [line_number]: Set a breakpoint at line [line_number] in the source file where main function resides
    * [source_file:line_number]: Set a breakpoint at line [line_number] in [source_file]
    * [function_name]: Set a breakpoint just before the start of function_name 
* continue (cont): Restart the stopped tracee process
* reg (r): Register oprations
    * dump: Dump all register information
    * read [REGISTER]: Read value from a register
    * write [REGISTER] [VALUE]: Write value to a register
* mem (m): Memory oprations
    * read [0xADDRESS]: Read value from an address
    * write [0xADDRESS] <VALUE>: Write value to an address
* vmmap: Show virtual memory layout
# References
1. [Writing a Linux Debugger](https://blog.tartanllama.xyz/writing-a-linux-debugger-setup/)
2. [基於 ptrace 在 Linux 上打造具體而微的 debugger](https://hackmd.io/@RinHizakura/BJH7zsU99#%E5%9F%BA%E6%96%BC-ptrace-%E5%9C%A8-Linux-%E4%B8%8A%E6%89%93%E9%80%A0%E5%85%B7%E9%AB%94%E8%80%8C%E5%BE%AE%E7%9A%84-debugger)
3. [raid-dbg](https://github.com/RinHizakura/raid-dbg/tree/main)
4. [minidbg](https://github.com/TartanLlama/minidbg/tree/master)
