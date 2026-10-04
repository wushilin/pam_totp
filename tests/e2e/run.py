#!/usr/bin/env python3
"""Drives real SSH logins against the pam-test container and saves transcripts."""
import io
import os
import re
import subprocess
import sys
import time

import pexpect

OUT = "/root/e2e"
BASE = (
    "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR "
    "-o NumberOfPasswordPrompts=1 "
)
KBD = BASE + "-o PubkeyAuthentication=no -o PreferredAuthentications=keyboard-interactive "
results = []


def codes(key):
    out = subprocess.run(["otputil", "--key", key], capture_output=True, text=True, check=True)
    return [line.split()[-1] for line in out.stdout.strip().splitlines()]


def session(name, cmd, steps):
    """steps: list of (pattern, reply). reply may be a callable taking the text so far."""
    log = io.StringIO()
    env = dict(os.environ, LANG="C.UTF-8", LC_ALL="C.UTF-8", TERM="xterm")
    child = pexpect.spawn(cmd, encoding="utf-8", env=env, timeout=30, dimensions=(80, 120))
    child.logfile_read = log
    try:
        for pattern, reply in steps:
            child.expect(pattern)
            child.sendline(reply(log.getvalue()) if callable(reply) else reply)
        child.expect(pexpect.EOF)
    except (pexpect.TIMEOUT, pexpect.EOF):
        pass
    child.close()
    text = log.getvalue().replace("\r\n", "\n")
    with open(f"{OUT}/{name}.txt", "w") as f:
        f.write(text)
    return text


def check(name, ok, detail=""):
    results.append((name, ok))
    print(f"{'PASS' if ok else 'FAIL'}  {name}  {detail}")


def kbd(user):
    return KBD + f"{user}@127.0.0.1 echo LOGIN-OK"


PW = r"[Pp]assword:"
TOTP = r"TOTP code:"
key = None

# 1. Wrong password must stop before the TOTP step.
t = session("01-wrong-password", kbd("jack"), [(PW, "not-the-password")])
check("wrong password never reaches TOTP", "TOTP" not in t and "LOGIN-OK" not in t)
check("no directory created by a failed password", not os.path.exists("/etc/pam_totp/jack"))


# 2. First login: self-enrollment.
def enroll_code(text):
    global key
    key = re.search(r"period\):\s*\n?\s*([A-Z2-7]{16,})", text).group(1)
    return codes(key)[0]


t = session("02-self-enroll", kbd("jack"), [(PW, "pw-jack-1"), (TOTP, enroll_code)])
check("self-enrollment logs in", "LOGIN-OK" in t and "Scan this QR code" in t)
listing = subprocess.run("ls -la /etc/pam_totp /etc/pam_totp/jack", shell=True, capture_output=True, text=True).stdout
open(f"{OUT}/02-files.txt", "w").write(listing)
check("enrollment wrote KEY, LAST_STEP, LOCK", all(n in listing for n in ("KEY", "LAST_STEP", "LOCK")))
used = codes(key)[0]

# 3. Reusing the accepted code is refused and does not show a QR again.
t = session("03-replay", kbd("jack"), [(PW, "pw-jack-1"), (TOTP, used)])
check("replayed code refused", "LOGIN-OK" not in t and "Scan this QR" not in t)

# 4. Normal login with a fresh code.
t = session("04-login", kbd("jack"), [(PW, "pw-jack-1"), (TOTP, lambda _: codes(key)[1])])
check("normal login with fresh code", "LOGIN-OK" in t)

# 5. Three wrong codes, then the throttle.
for i in range(3):
    t = session(f"05-wrong-code-{i + 1}", kbd("jack"), [(PW, "pw-jack-1"), (TOTP, "000000")])
    check(f"wrong code {i + 1} refused", "LOGIN-OK" not in t)
t = session("06-throttled", kbd("jack"), [(PW, "pw-jack-1"), (TOTP, lambda _: codes(key)[1])])
check("fourth attempt throttled without a prompt", "LOGIN-OK" not in t and "TOTP code" not in t, repr(t[-80:]))

# 6. After the penalty and a new time step, a correct code works again.
time.sleep(35)
t = session("07-after-penalty", kbd("jack"), [(PW, "pw-jack-1"), (TOTP, lambda _: codes(key)[1])])
check("login works after the penalty", "LOGIN-OK" in t)

# 7. Exempt group: password only.
t = session("08-exempt-group", kbd("opsadmin"), [(PW, "pw-opsadmin-1")])
check("exempt group skips TOTP", "LOGIN-OK" in t and "TOTP" not in t)

# 8. Public key alone: PAM auth is not involved.
cmd = BASE + "-i /root/e2e/id_test -o PreferredAuthentications=publickey kate@127.0.0.1 echo LOGIN-OK"
t = session("09-publickey-only", cmd, [])
check("public key only logs in", "LOGIN-OK" in t and "TOTP" not in t)

# 9. Public key then PAM: publickey_exempted skips the TOTP step.
cmd = BASE + "-i /root/e2e/id_test -o PreferredAuthentications=publickey,keyboard-interactive kim@127.0.0.1 echo LOGIN-OK"
t = session("10-publickey-then-password", cmd, [(PW, "pw-kim-1")])
check("public key + password skips TOTP", "LOGIN-OK" in t and "TOTP" not in t)

# 10. Unknown account: nothing is created.
t = session("11-unknown-user", kbd("nosuchuser"), [(PW, "whatever")])
check("unknown user creates nothing", not os.path.exists("/etc/pam_totp/nosuchuser"))

logs = subprocess.run(
    "journalctl --since '-10min' --no-pager -o cat | grep pam_totp", shell=True, capture_output=True, text=True
).stdout
open(f"{OUT}/12-syslog.txt", "w").write(logs)
check("module wrote syslog lines", "wrong code" in logs and "enrolled" in logs and "throttled" in logs)
check("syslog never contains the key", key not in logs)

failed = [n for n, ok in results if not ok]
print(f"\n{len(results) - len(failed)}/{len(results)} checks passed")
sys.exit(1 if failed else 0)
