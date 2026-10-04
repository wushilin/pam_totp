# pam-totp-rs

A Rust Linux-PAM authentication module that verifies a TOTP after an earlier PAM
module has checked the user's password. It supports a group exemption and
per-user replay state.

## Configuration

Pass these options on the `auth` line in `/etc/pam.d/<service>`:

```text
auth required pam_totp.so otp_required=true otp_exempted_group=wheel publickey_exempted=true pam_working_dir=/etc/pam_totp
```

`otp_required=false` skips the OTP check for all users. When it is true, members
of `otp_exempted_group` pass this module without an OTP. Every other user must
have a valid key and a valid, not previously accepted TOTP. Missing or unsafe
files and malformed state fail closed. Add `otp_enroll=true` to enroll users
without a key at their first successful password login:

```text
auth required pam_totp.so otp_required=true otp_exempted_group=wheel otp_enroll=true pam_working_dir=/etc/pam_totp
```

The module displays an ASCII QR code and a manual-entry secret in the terminal.
The user must enter a currently valid TOTP before the key is written. If the
code is wrong or the login is interrupted, no key is saved and enrollment can
be retried. Exempt users skip enrollment. Enrollment is disabled by default.
With `publickey_exempted=true`, the module skips its OTP step when an earlier
public-key step is reported by OpenSSH in `SSH_AUTH_INFO_0`. This is an
OpenSSH-specific signal. A public-key-only SSH authentication path normally
does not invoke PAM's `auth` stack at all, so the SSH method policy must also
allow public-key authentication as its own alternative if key-only logins
should skip OTP.

For the two-path SSH policy (key-only, or password plus OTP), OpenSSH can use:

```text
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication yes
AuthenticationMethods publickey keyboard-interactive:pam
```

Whitespace separates alternatives here: a user can authenticate with a key,
or use keyboard-interactive PAM, which runs the configured password and OTP
checks. If `publickey_exempted=false`, the module itself never skips OTP when
PAM auth runs; to require OTP on key logins too, sshd must require a
`keyboard-interactive:pam` step after the public key. With the example PAM
stack, that path also asks for the Unix password.

## Local test utility

Build `otputil` on the machine from which you test SSH:

```sh
cargo build --release --bin otputil
target/release/otputil --key BASE32_KEY
```

It prints codes for the current 30-second time step and the next two. Use
`--key-stdin` to avoid putting a key in process arguments, or `--key-file PATH`
to read one from a protected file. `--time UNIX_SECONDS` selects a fixed time
for repeatable tests. `otputil` is a test helper and is not installed with the
PAM module.

Create root-owned per-user directories and files, for example:

```text
/etc/pam_totp/jack/KEY
/etc/pam_totp/jack/LAST_STEP   # created and updated by the module
/etc/pam_totp/jack/LOCK        # created and retained by the module
```

The working directory and its user directories must be owned by root and not
writable by group or others. `KEY` must be root-owned with mode `0600`; it
contains the Base32 TOTP secret. The module accepts six-digit SHA-1 TOTP values
with a 30-second period and a one-step clock-skew window on either side.

## Setup guide (SSH)

These steps use Debian/Ubuntu paths. Keep a second root session open the whole
time; a mistake in PAM or sshd configuration can lock you out.

### Options

| Option | Default | Meaning |
|---|---|---|
| `otp_required=true\|false` | `true` | `false` makes the module succeed without asking for a code. |
| `otp_exempted_group=NAME` | none | Members of this group skip the OTP step. |
| `publickey_exempted=true\|false` | `false` | Skip the OTP step when sshd reports an earlier public-key step. |
| `otp_enroll=true\|false` | `false` | Let a user without a `KEY` enroll at login. |
| `pam_working_dir=/abs/path` | `/etc/pam_totp` | Where keys and state are stored. |

An unknown option or a bad value makes the module fail every login, so check
spelling before closing your spare root session.

### 1. Install the module

Download `pam_totp-<arch>-linux-gnu.so` from the release page (or build it, see
Build below) and install it into the PAM module directory:

```sh
sudo install -o root -g root -m 0755 pam_totp-x86_64-linux-gnu.so \
  /usr/lib/x86_64-linux-gnu/security/pam_totp.so
```

The directory is the one that already contains `pam_unix.so`. On RHEL-family
systems it is `/usr/lib64/security`.

### 2. Create the working directory and a user directory

```sh
sudo install -d -o root -g root -m 0700 /etc/pam_totp
sudo install -d -o root -g root -m 0700 /etc/pam_totp/jack
```

Every user who must pass OTP needs a directory named after their login, even
when `otp_enroll=true` is used. A user without one is rejected.

### 3. Give the user a key

Either create the key yourself:

```sh
sudo sh -c 'umask 077; head -c 20 /dev/urandom | base32 > /etc/pam_totp/jack/KEY'
sudo cat /etc/pam_totp/jack/KEY
```

and type the printed key into an authenticator app (time-based, SHA-1,
6 digits, 30 seconds), or skip this step and set `otp_enroll=true` so the user
is shown a QR code at their first password login.

Check the key before touching PAM:

```sh
sudo cat /etc/pam_totp/jack/KEY | otputil --key-stdin
```

The first line must match what the authenticator app shows.

### 4. Add the module to the sshd PAM stack

In `/etc/pam.d/sshd`, add the module directly after the password check:

```text
@include common-auth
auth required pam_totp.so
```

A wrong password must end authentication before this line is reached. The
stock Debian/Ubuntu `common-auth` does that. On other distributions, confirm
it by entering a wrong password and checking that no TOTP prompt appears; do
not enable `otp_enroll=true` until that holds, or someone without the password
could enroll their own key.

### 5. Configure sshd

In `/etc/ssh/sshd_config`:

```text
UsePAM yes
KbdInteractiveAuthentication yes
PasswordAuthentication no
```

`PasswordAuthentication` must be off because that method cannot display a
second prompt; password logins go through keyboard-interactive instead. Add
the `AuthenticationMethods` line from the Configuration section if key-only
logins should remain possible. Then validate and reload:

```sh
sudo sshd -t && sudo systemctl reload ssh
```

### 6. Test from a new connection

```sh
ssh -o PubkeyAuthentication=no jack@host
```

You should be asked for the password and then for `TOTP code:`. Also check
that a wrong code is refused and that reusing an accepted code is refused.

### Troubleshooting

- Every login fails: check option spelling, then ownership and modes. The
  working directory, user directory, `KEY`, `LAST_STEP`, `LOCK` and `THROTTLE`
  must all be owned by root and not accessible to group or others.
- Correct codes are refused: check the host clock, and see Failure throttling
  below; deleting `/etc/pam_totp/THROTTLE` clears all penalties.
- To re-enroll a user, delete their `KEY`.
- To back out, remove the `pam_totp.so` line from `/etc/pam.d/sshd`.
- On SELinux systems, sshd may be denied access to the working directory; look
  for denials in the audit log.

## Failure throttling

Wrong codes are counted per user and remote host (`PAM_RHOST`) in
`/etc/pam_totp/THROTTLE`, a root-owned `0600` file created by the module. It
holds at most 4096 fixed-size records (about 213 KB); when full, the record
with the oldest last failure is replaced. Each record keeps the total failure
count, the consecutive failure count and the last three failure times.

The first two consecutive failures carry no penalty. From the third, the
module rejects further attempts from that user and host for 5 seconds,
doubling with each additional failure up to one hour. Attempts made during a
penalty are rejected without being checked and are not counted. A successful
login resets the consecutive count, as does a gap of more than 24 hours since
the last failure. Deleting `THROTTLE` clears all penalties.

## PAM ordering

Put the module after the password check and make its result required. The
password check must stop the stack on failure (for a simple stack, use
`requisite pam_unix.so`); PAM's `required` control records failure but continues
to later modules, which could otherwise display enrollment after a bad
password. Do not add the OTP module as `sufficient`. For SSH, enable PAM and
keyboard-interactive authentication so the OTP prompt can be answered.

## Build

Build on the target Linux distribution (or with a matching Linux cross toolchain):

```sh
cargo build --release
sudo install -o root -g root -m 0755 target/release/libpam_totp.so \
  /usr/lib/security/pam_totp.so
```

The correct PAM module directory varies by distribution and architecture.
Test with a disposable system and keep an independent root session open while
editing PAM policy.

Building needs the PAM development files (`libpam0g-dev` on Debian/Ubuntu,
`pam-devel` on RHEL-family systems).

## Releases

Pushing a tag that starts with `v` runs `.github/workflows/release.yml`, which
tests and builds the module on Ubuntu 22.04 for x86_64 and aarch64 and attaches
`pam_totp-<arch>-linux-gnu.so`, `otputil-<arch>-linux-gnu` and checksums to a
GitHub Release:

```sh
git tag v0.1.0 && git push origin v0.1.0
```

The binaries need glibc 2.35 or newer. Build from source on older systems.

## Stress test

```sh
cargo test --release -- --ignored --nocapture
```

This runs several million operations across the TOTP, throttle, PAM
conversation and file paths and fails if peak memory or the number of open
file descriptors grows. It takes about a minute.

## Current scope

This is an initial implementation. It does not create accounts or configure
sudo authorization. The host clock must be synchronized. It uses `flock` on a
persistent per-user lock file and requires the filesystem to honor POSIX
advisory locks and atomic rename semantics.
