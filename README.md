# Croco-dbg
Croco-dbg is a tiny debugger for x86-64 Linux based on ptrace and FreeBSD library for DWARF 

# Build
At first, get a clone of linenoise

git submodule update --init

(Optional) Install FreeBSD library if you don't have them in your system

sudo get-apt install libdw-dev libdwarf

Then just make it.

make

Launch Croco with you executable, enjoy it! 

./croco <executable>

# Command
* help (h): Show command description
* break (b)  <dump/0xADDRESS>: Set a memory address as a breakpoint
* continue (cont): Restart the stopped tracee process
* reg (r): Register oprations
    * dump: Dump all register information
    * read <REGISTER>: Read value from a register
    * write <REGISTER> <VALUE>: Write value to a register
* mem (m): Memory oprations
    * read <0xADDRESS>: Read value from an address
    * write <0xADDRESS> <VALUE>: Write value to an address
* vmmap: Show virtual memory layout
# Reference
1. [Writing a Linux Debugger](https://blog.tartanllama.xyz/writing-a-linux-debugger-setup/)
2. [基於 ptrace 在 Linux 上打造具體而微的 debugger](https://hackmd.io/@RinHizakura/BJH7zsU99#%E5%9F%BA%E6%96%BC-ptrace-%E5%9C%A8-Linux-%E4%B8%8A%E6%89%93%E9%80%A0%E5%85%B7%E9%AB%94%E8%80%8C%E5%BE%AE%E7%9A%84-debugger)
3. [raid-dbg](https://github.com/RinHizakura/raid-dbg/tree/main)
4. [minidbg](https://github.com/TartanLlama/minidbg/tree/master)
