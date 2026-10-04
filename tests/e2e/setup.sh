#!/bin/sh
# Prepares the pam-test container for the end-to-end run. Safe to re-run.
set -eu
cd "$(dirname "$0")/../.."

install -o root -g root -m 0755 target/release/libpam_totp.so /usr/lib/x86_64-linux-gnu/security/pam_totp.so
install -o root -g root -m 0755 target/release/otputil /usr/local/bin/otputil

rm -rf /etc/pam_totp /root/e2e
install -d -o root -g root -m 0700 /etc/pam_totp
mkdir -p /root/e2e

getent group totpexempt >/dev/null || groupadd totpexempt
for u in jack kate kim opsadmin; do
    id "$u" >/dev/null 2>&1 || useradd -m -s /bin/bash "$u"
    echo "$u:pw-$u-1" | chpasswd
done
usermod -aG totpexempt opsadmin

ssh-keygen -q -t ed25519 -N "" -f /root/e2e/id_test
for u in kate kim; do
    install -d -o "$u" -g "$u" -m 0700 "/home/$u/.ssh"
    install -o "$u" -g "$u" -m 0600 /root/e2e/id_test.pub "/home/$u/.ssh/authorized_keys"
done

[ -f /etc/pam.d/sshd.pam_totp.bak ] || cp /etc/pam.d/sshd /etc/pam.d/sshd.pam_totp.bak
cp /etc/pam.d/sshd.pam_totp.bak /etc/pam.d/sshd
sed -i '/^@include common-auth/a auth required pam_totp.so otp_enroll=true otp_exempted_group=totpexempt publickey_exempted=true' /etc/pam.d/sshd
grep -n -A1 '^@include common-auth' /etc/pam.d/sshd

cat > /etc/ssh/sshd_config.d/00-pam-totp.conf <<'EOF'
UsePAM yes
KbdInteractiveAuthentication yes
PasswordAuthentication no
AuthenticationMethods publickey keyboard-interactive:pam
Match User kim
    AuthenticationMethods publickey,keyboard-interactive:pam
EOF
sshd -t
systemctl restart ssh
python3 -c "import pexpect" 2>/dev/null || apt-get install -y -q python3-pexpect >/dev/null
echo SETUP-OK
