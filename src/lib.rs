use hmac::{Hmac, Mac};
use qrcodegen::{QrCode, QrCodeEcc};
use sha1::Sha1;
use std::ffi::{CStr, CString};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};
use std::ptr;
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha1 = Hmac<Sha1>;

const PAM_SUCCESS: libc::c_int = 0;
const PAM_SERVICE_ERR: libc::c_int = 3;
const PAM_AUTH_ERR: libc::c_int = 7;
const PAM_PROMPT_ECHO_OFF: libc::c_int = 1;
const PAM_TEXT_INFO: libc::c_int = 4;
const PAM_CONV_ITEM: libc::c_int = 5;
const PAM_RHOST_ITEM: libc::c_int = 4;
const SSH_AUTH_INFO_ENV: &[u8] = b"SSH_AUTH_INFO_0\0";

const THROTTLE_SLOTS: usize = 4096;
const THROTTLE_RECORD: usize = 52;
const THROTTLE_THRESHOLD: u32 = 3;
const THROTTLE_BASE_SECS: u64 = 5;
const THROTTLE_MAX_SECS: u64 = 3600;
const THROTTLE_RESET_SECS: u64 = 86400;

#[repr(C)]
struct PamMessage {
    msg_style: libc::c_int,
    msg: *const libc::c_char,
}

#[repr(C)]
struct PamResponse {
    resp: *mut libc::c_char,
    resp_retcode: libc::c_int,
}

#[repr(C)]
struct PamConv {
    conv: Option<
        unsafe extern "C" fn(
            libc::c_int,
            *mut *const PamMessage,
            *mut *mut PamResponse,
            *mut libc::c_void,
        ) -> libc::c_int,
    >,
    appdata_ptr: *mut libc::c_void,
}

#[link(name = "pam")]
extern "C" {
    fn pam_get_user(
        pamh: *mut libc::c_void,
        user: *mut *const libc::c_char,
        prompt: *const libc::c_char,
    ) -> libc::c_int;
    fn pam_get_item(
        pamh: *mut libc::c_void,
        item_type: libc::c_int,
        item: *mut *const libc::c_void,
    ) -> libc::c_int;
    fn pam_getenv(pamh: *mut libc::c_void, name: *const libc::c_char) -> *const libc::c_char;
}

fn parse_args(
    argc: libc::c_int,
    argv: *const *const libc::c_char,
) -> Result<(bool, Option<String>, PathBuf, bool, bool), ()> {
    let mut required = true;
    let mut exempt_group = None;
    let mut working_dir = PathBuf::from("/etc/pam_totp");
    let mut enroll_missing = false;
    let mut publickey_exempted = false;
    if argc > 0 && argv.is_null() {
        return Err(());
    }
    for i in 0..argc.max(0) as isize {
        let raw = unsafe { *argv.offset(i) };
        if raw.is_null() {
            continue;
        }
        let arg = unsafe { CStr::from_ptr(raw) }.to_str().map_err(|_| ())?;
        if let Some(v) = arg.strip_prefix("otp_required=") {
            required = match v {
                "true" => true,
                "false" => false,
                _ => return Err(()),
            };
        } else if let Some(v) = arg.strip_prefix("otp_exempted_group=") {
            if v.is_empty() || v.contains('/') {
                return Err(());
            }
            exempt_group = Some(v.to_owned());
        } else if let Some(v) = arg.strip_prefix("pam_working_dir=") {
            if v.is_empty() {
                return Err(());
            }
            working_dir = PathBuf::from(v);
        } else if let Some(v) = arg.strip_prefix("otp_enroll=") {
            enroll_missing = match v {
                "true" => true,
                "false" => false,
                _ => return Err(()),
            };
        } else if let Some(v) = arg.strip_prefix("publickey_exempted=") {
            publickey_exempted = match v {
                "true" => true,
                "false" => false,
                _ => return Err(()),
            };
        } else {
            return Err(());
        }
    }
    if !working_dir.is_absolute()
        || working_dir
            .components()
            .any(|c| matches!(c, Component::ParentDir))
    {
        return Err(());
    }
    Ok((
        required,
        exempt_group,
        working_dir,
        enroll_missing,
        publickey_exempted,
    ))
}

fn ssh_publickey_was_used(pamh: *mut libc::c_void) -> bool {
    let raw = unsafe { pam_getenv(pamh, SSH_AUTH_INFO_ENV.as_ptr() as *const libc::c_char) };
    if raw.is_null() {
        return false;
    }
    auth_info_has_publickey(unsafe { CStr::from_ptr(raw) }.to_bytes())
}

fn auth_info_has_publickey(info: &[u8]) -> bool {
    info.split(|b| *b == b'\n')
        .any(|line| line == b"publickey" || line.starts_with(b"publickey "))
}

// The reentrant lookups keep the module from overwriting the static
// passwd/group buffers the host application may still be pointing into.
fn lookup_gid(group: &CStr) -> Option<libc::gid_t> {
    let mut buf = vec![0 as libc::c_char; 1024];
    loop {
        let mut gr: libc::group = unsafe { std::mem::zeroed() };
        let mut out: *mut libc::group = ptr::null_mut();
        let rc = unsafe {
            libc::getgrnam_r(
                group.as_ptr(),
                &mut gr,
                buf.as_mut_ptr(),
                buf.len(),
                &mut out,
            )
        };
        if rc == libc::ERANGE && buf.len() < (1 << 20) {
            buf.resize(buf.len() * 4, 0);
            continue;
        }
        if rc != 0 || out.is_null() {
            return None;
        }
        return Some(gr.gr_gid);
    }
}

fn lookup_primary_gid(user: &CStr) -> Option<libc::gid_t> {
    let mut buf = vec![0 as libc::c_char; 1024];
    loop {
        let mut pw: libc::passwd = unsafe { std::mem::zeroed() };
        let mut out: *mut libc::passwd = ptr::null_mut();
        let rc = unsafe {
            libc::getpwnam_r(
                user.as_ptr(),
                &mut pw,
                buf.as_mut_ptr(),
                buf.len(),
                &mut out,
            )
        };
        if rc == libc::ERANGE && buf.len() < (1 << 20) {
            buf.resize(buf.len() * 4, 0);
            continue;
        }
        if rc != 0 || out.is_null() {
            return None;
        }
        return Some(pw.pw_gid);
    }
}

fn group_contains(user: &str, group: &str) -> bool {
    let Ok(un) = CString::new(user) else {
        return false;
    };
    let Ok(gn) = CString::new(group) else {
        return false;
    };
    let Some(gid) = lookup_gid(&gn) else {
        return false;
    };
    let Some(pw_gid) = lookup_primary_gid(&un) else {
        return false;
    };
    unsafe {
        let mut count: libc::c_int = 0;
        #[cfg(target_os = "macos")]
        libc::getgrouplist(
            un.as_ptr(),
            pw_gid as libc::c_int,
            ptr::null_mut(),
            &mut count,
        );
        #[cfg(not(target_os = "macos"))]
        libc::getgrouplist(un.as_ptr(), pw_gid, ptr::null_mut(), &mut count);
        if count <= 0 || count > 65536 {
            return false;
        }
        #[cfg(target_os = "macos")]
        {
            let mut gids = vec![0 as libc::c_int; count as usize];
            if libc::getgrouplist(
                un.as_ptr(),
                pw_gid as libc::c_int,
                gids.as_mut_ptr(),
                &mut count,
            ) < 0
            {
                return false;
            }
            gids[..count as usize]
                .iter()
                .any(|g| *g as libc::gid_t == gid)
        }
        #[cfg(not(target_os = "macos"))]
        {
            let mut gids = vec![0 as libc::gid_t; count as usize];
            if libc::getgrouplist(un.as_ptr(), pw_gid, gids.as_mut_ptr(), &mut count) < 0 {
                return false;
            }
            gids[..count as usize].contains(&gid)
        }
    }
}

// Files and directories must belong to root. Unit tests run unprivileged, so
// test builds accept the current user instead.
fn trusted_owner(uid: u32) -> bool {
    #[cfg(test)]
    let owner = unsafe { libc::geteuid() };
    #[cfg(not(test))]
    let owner = 0;
    uid == owner
}

fn check_root_owned_dir(path: &Path, allow_group_write: bool) -> Result<(), ()> {
    let md = fs::symlink_metadata(path).map_err(|_| ())?;
    if !md.file_type().is_dir()
        || !trusted_owner(md.uid())
        || md.mode() & 0o002 != 0
        || (!allow_group_write && md.mode() & 0o020 != 0)
    {
        return Err(());
    }
    Ok(())
}

fn account_exists(user: &str) -> bool {
    CString::new(user).is_ok_and(|u| lookup_primary_gid(&u).is_some())
}

fn safe_user_dir(base: &Path, user: &str, create: bool) -> Result<PathBuf, ()> {
    if user.is_empty()
        || user == "."
        || user == ".."
        || !user
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
    {
        return Err(());
    }
    check_root_owned_dir(base, false)?;
    let dir = base.join(user);
    if create {
        match std::os::unix::fs::DirBuilderExt::mode(&mut fs::DirBuilder::new(), 0o700)
            .create(&dir)
        {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err(()),
        }
    }
    check_root_owned_dir(&dir, false)?;
    Ok(dir)
}

fn read_key(dir: &Path) -> Result<Vec<u8>, ()> {
    let path = dir.join("KEY");
    let md = fs::symlink_metadata(&path).map_err(|_| ())?;
    if !md.file_type().is_file() || !trusted_owner(md.uid()) || md.mode() & 0o077 != 0 || md.len() > 256 {
        return Err(());
    }
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| ())?;
    let mut s = String::new();
    f.read_to_string(&mut s).map_err(|_| ())?;
    decode_base32(s.trim())
}

pub fn decode_base32(s: &str) -> Result<Vec<u8>, ()> {
    let mut out = Vec::new();
    let mut acc: u32 = 0;
    let mut bits = 0;
    for b in s.bytes().filter(|b| *b != b'=' && !b.is_ascii_whitespace()) {
        let c = b.to_ascii_uppercase();
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'2'..=b'7' => c - b'2' + 26,
            _ => return Err(()),
        } as u32;
        acc = (acc << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    if out.len() < 10 {
        return Err(());
    }
    Ok(out)
}

fn encode_base32(data: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::new();
    let mut acc = 0u32;
    let mut bits = 0u8;
    for byte in data {
        acc = (acc << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((acc >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((acc << (5 - bits)) & 31) as usize] as char);
    }
    out
}

fn generate_secret() -> Result<Vec<u8>, ()> {
    let mut secret = vec![0u8; 20];
    File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut secret))
        .map_err(|_| ())?;
    Ok(secret)
}

fn enrollment_qr(user: &str, secret: &[u8]) -> Result<String, ()> {
    let encoded = encode_base32(secret);
    let uri = format!(
        "otpauth://totp/pam-totp:{user}?secret={encoded}&issuer=pam-totp&algorithm=SHA1&digits=6&period=30"
    );
    let qr = QrCode::encode_text(&uri, QrCodeEcc::Low).map_err(|_| ())?;
    let size = qr.size();
    let mut output = String::new();
    for y in (-4..size + 4).step_by(2) {
        for x in -4..size + 4 {
            let top = x >= 0 && x < size && y >= 0 && y < size && qr.get_module(x, y);
            let bottom_y = y + 1;
            let bottom = x >= 0
                && x < size
                && bottom_y >= 0
                && bottom_y < size
                && qr.get_module(x, bottom_y);
            output.push(match (top, bottom) {
                (true, true) => '█',
                (true, false) => '▀',
                (false, true) => '▄',
                (false, false) => ' ',
            });
        }
        output.push('\n');
    }
    Ok(format!(
        "First-time TOTP setup for {user}. Scan this QR code with your authenticator, then enter the displayed six-digit code to finish enrollment.\n\n{output}\nIf scanning does not work, add this key manually (SHA1, 6 digits, 30-second period):\n{encoded}"
    ))
}

pub fn totp_at(key: &[u8], step: u64) -> String {
    let mut mac = HmacSha1::new_from_slice(key).expect("HMAC accepts all key sizes");
    mac.update(&step.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let off = (digest[19] & 0x0f) as usize;
    let n = (u32::from(digest[off] & 0x7f) << 24)
        | (u32::from(digest[off + 1]) << 16)
        | (u32::from(digest[off + 2]) << 8)
        | u32::from(digest[off + 3]);
    format!("{:06}", n % 1_000_000)
}

fn pam_conv<'a>(pamh: *mut libc::c_void) -> Result<&'a PamConv, ()> {
    let mut item: *const libc::c_void = ptr::null();
    if unsafe { pam_get_item(pamh, PAM_CONV_ITEM, &mut item) } != PAM_SUCCESS || item.is_null() {
        return Err(());
    }
    Ok(unsafe { &*(item as *const PamConv) })
}

fn prompt_otp(pamh: *mut libc::c_void) -> Result<String, ()> {
    prompt_with(pam_conv(pamh)?)
}

fn show_text(pamh: *mut libc::c_void, text: &str) -> Result<(), ()> {
    show_with(pam_conv(pamh)?, text)
}

fn prompt_with(conv: &PamConv) -> Result<String, ()> {
    let callback = conv.conv.ok_or(())?;
    let prompt = CString::new("TOTP code: ").map_err(|_| ())?;
    let msg = PamMessage {
        msg_style: PAM_PROMPT_ECHO_OFF,
        msg: prompt.as_ptr(),
    };
    let mut msgp: *const PamMessage = &msg;
    let mut resp: *mut PamResponse = ptr::null_mut();
    let status = unsafe { callback(1, &mut msgp, &mut resp, conv.appdata_ptr) };
    if status != PAM_SUCCESS || resp.is_null() {
        return Err(());
    }
    let value = unsafe {
        let p = (*resp).resp;
        if p.is_null() {
            String::new()
        } else {
            CStr::from_ptr(p).to_string_lossy().into_owned()
        }
    };
    unsafe {
        if !(*resp).resp.is_null() {
            let p = (*resp).resp as *mut u8;
            let len = libc::strlen((*resp).resp);
            for i in 0..len {
                ptr::write_volatile(p.add(i), 0);
            }
            libc::free((*resp).resp as *mut libc::c_void);
        }
        libc::free(resp as *mut libc::c_void);
    }
    Ok(value)
}

fn show_with(conv: &PamConv, text: &str) -> Result<(), ()> {
    let callback = conv.conv.ok_or(())?;
    let message = CString::new(text).map_err(|_| ())?;
    let msg = PamMessage {
        msg_style: PAM_TEXT_INFO,
        msg: message.as_ptr(),
    };
    let mut msgp: *const PamMessage = &msg;
    let mut response: *mut PamResponse = ptr::null_mut();
    if unsafe { callback(1, &mut msgp, &mut response, conv.appdata_ptr) } != PAM_SUCCESS {
        return Err(());
    }
    if !response.is_null() {
        unsafe {
            libc::free((*response).resp as *mut libc::c_void);
            libc::free(response as *mut libc::c_void);
        }
    }
    Ok(())
}

fn lock_user_dir(dir: &Path) -> Result<File, ()> {
    let lock_path = dir.join("LOCK");
    let lmd = match fs::symlink_metadata(&lock_path) {
        Ok(m) => m,
        Err(_) => {
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&lock_path)
                .map_err(|_| ())?;
            fs::symlink_metadata(&lock_path).map_err(|_| ())?
        }
    };
    if !lmd.file_type().is_file() || !trusted_owner(lmd.uid()) || lmd.mode() & 0o077 != 0 {
        return Err(());
    }
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&lock_path)
        .map_err(|_| ())?;
    if unsafe { libc::flock(std::os::fd::AsRawFd::as_raw_fd(&lock), libc::LOCK_EX) } != 0 {
        return Err(());
    }
    Ok(lock)
}

fn read_last_step(dir: &Path) -> Result<u64, ()> {
    let state_path = dir.join("LAST_STEP");
    match fs::symlink_metadata(&state_path) {
        Ok(md) => {
            if !md.file_type().is_file() || !trusted_owner(md.uid()) || md.mode() & 0o077 != 0 || md.len() > 32
            {
                return Err(());
            }
            let s = fs::read_to_string(&state_path).map_err(|_| ())?;
            s.trim().parse::<u64>().map_err(|_| ())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(_) => return Err(()),
    }
}

fn write_atomic(dir: &Path, name: &str, data: &[u8]) -> Result<(), ()> {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ())?
        .as_nanos();
    let tmp = dir.join(format!(".{name}.{}.{}.tmp", std::process::id(), nonce));
    let mut out = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&tmp)
        .map_err(|_| ())?;
    if let Err(_) = out.write_all(data).and_then(|_| out.sync_all()) {
        let _ = fs::remove_file(&tmp);
        return Err(());
    }
    if let Err(_) = fs::rename(&tmp, dir.join(name)) {
        let _ = fs::remove_file(&tmp);
        return Err(());
    }
    File::open(dir).and_then(|d| d.sync_all()).map_err(|_| ())?;
    Ok(())
}

fn matching_step(key: &[u8], code: &str, now: u64, last: u64) -> Option<u64> {
    let current = now / 30;
    [
        current.saturating_sub(1),
        current,
        current.saturating_add(1),
    ]
    .into_iter()
    .find(|step| *step > last && constant_time_eq(totp_at(key, *step).as_bytes(), code.as_bytes()))
}

enum Failure {
    BadCode,
    Other,
}

impl From<()> for Failure {
    fn from(_: ()) -> Self {
        Failure::Other
    }
}

// Must be called with the user directory lock held.
fn commit_code(dir: &Path, key: &[u8], code: &str, enrolling: bool) -> Result<(), Failure> {
    let last = read_last_step(dir)?;
    // Another login may have finished enrollment while this one was prompting.
    if enrolling && fs::symlink_metadata(dir.join("KEY")).is_ok() {
        return Err(Failure::Other);
    }
    let step = matching_step(key, code, now_secs()?, last).ok_or(Failure::BadCode)?;
    write_atomic(dir, "LAST_STEP", format!("{step}\n").as_bytes())?;
    if enrolling {
        write_atomic(dir, "KEY", format!("{}\n", encode_base32(key)).as_bytes())?;
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
struct ThrottleEntry {
    key: [u8; 20],
    total: u32,
    consecutive: u32,
    times: [u64; 3],
}

impl ThrottleEntry {
    fn encode(&self) -> [u8; THROTTLE_RECORD] {
        let mut b = [0u8; THROTTLE_RECORD];
        b[..20].copy_from_slice(&self.key);
        b[20..24].copy_from_slice(&self.total.to_le_bytes());
        b[24..28].copy_from_slice(&self.consecutive.to_le_bytes());
        for (i, t) in self.times.iter().enumerate() {
            b[28 + i * 8..36 + i * 8].copy_from_slice(&t.to_le_bytes());
        }
        b
    }

    fn decode(b: &[u8]) -> Self {
        let u32_at = |i: usize| u32::from_le_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]]);
        let u64_at = |i: usize| {
            let mut a = [0u8; 8];
            a.copy_from_slice(&b[i..i + 8]);
            u64::from_le_bytes(a)
        };
        let mut key = [0u8; 20];
        key.copy_from_slice(&b[..20]);
        ThrottleEntry {
            key,
            total: u32_at(20),
            consecutive: u32_at(24),
            times: [u64_at(28), u64_at(36), u64_at(44)],
        }
    }
}

fn throttle_key(user: &str, rhost: &[u8]) -> [u8; 20] {
    let mut data = Vec::with_capacity(user.len() + 1 + rhost.len());
    data.extend_from_slice(user.as_bytes());
    data.push(0);
    data.extend_from_slice(rhost);
    <Sha1 as sha1::Digest>::digest(&data).into()
}

fn throttle_penalty(consecutive: u32) -> u64 {
    if consecutive < THROTTLE_THRESHOLD {
        return 0;
    }
    let shift = (consecutive - THROTTLE_THRESHOLD).min(32);
    (THROTTLE_BASE_SECS << shift).min(THROTTLE_MAX_SECS)
}

fn throttle_blocked(entries: &[ThrottleEntry], key: &[u8; 20], now: u64) -> bool {
    entries
        .iter()
        .find(|e| e.key == *key)
        .is_some_and(|e| now < e.times[0].saturating_add(throttle_penalty(e.consecutive)))
}

fn throttle_fail(entries: &mut Vec<ThrottleEntry>, key: &[u8; 20], now: u64) -> usize {
    let fresh = ThrottleEntry {
        key: *key,
        ..Default::default()
    };
    let idx = match entries.iter().position(|e| e.key == *key) {
        Some(i) => i,
        None if entries.len() < THROTTLE_SLOTS => {
            entries.push(fresh);
            entries.len() - 1
        }
        None => {
            let i = entries
                .iter()
                .enumerate()
                .min_by_key(|(_, e)| e.times[0])
                .map(|(i, _)| i)
                .unwrap_or(0);
            entries[i] = fresh;
            i
        }
    };
    let e = &mut entries[idx];
    if now.saturating_sub(e.times[0]) > THROTTLE_RESET_SECS {
        e.consecutive = 0;
    }
    e.total = e.total.saturating_add(1);
    e.consecutive = e.consecutive.saturating_add(1);
    e.times = [now, e.times[0], e.times[1]];
    idx
}

fn throttle_clear(entries: &mut [ThrottleEntry], key: &[u8; 20]) -> Option<usize> {
    let idx = entries
        .iter()
        .position(|e| e.key == *key && e.consecutive != 0)?;
    entries[idx].consecutive = 0;
    Some(idx)
}

fn open_throttle(base: &Path) -> Result<(File, Vec<ThrottleEntry>), ()> {
    let mut f = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(base.join("THROTTLE"))
        .map_err(|_| ())?;
    if unsafe { libc::flock(std::os::fd::AsRawFd::as_raw_fd(&f), libc::LOCK_EX) } != 0 {
        return Err(());
    }
    let md = f.metadata().map_err(|_| ())?;
    if !md.file_type().is_file() || !trusted_owner(md.uid()) || md.mode() & 0o077 != 0 {
        return Err(());
    }
    let mut data = Vec::new();
    if md.len() <= (THROTTLE_SLOTS * THROTTLE_RECORD) as u64 {
        f.read_to_end(&mut data).map_err(|_| ())?;
    }
    if data.len() as u64 != md.len() || data.len() % THROTTLE_RECORD != 0 {
        f.set_len(0).map_err(|_| ())?;
        data.clear();
    }
    Ok((
        f,
        data.chunks_exact(THROTTLE_RECORD)
            .map(ThrottleEntry::decode)
            .collect(),
    ))
}

fn store_throttle(f: &File, entries: &[ThrottleEntry], idx: usize) -> Result<(), ()> {
    std::os::unix::fs::FileExt::write_all_at(
        f,
        &entries[idx].encode(),
        (idx * THROTTLE_RECORD) as u64,
    )
    .map_err(|_| ())
}

fn throttled(base: &Path, key: &[u8; 20]) -> Result<bool, ()> {
    let (_f, entries) = open_throttle(base)?;
    Ok(throttle_blocked(&entries, key, now_secs()?))
}

fn remote_host(pamh: *mut libc::c_void) -> Vec<u8> {
    let mut item: *const libc::c_void = ptr::null();
    if unsafe { pam_get_item(pamh, PAM_RHOST_ITEM, &mut item) } != PAM_SUCCESS || item.is_null() {
        return Vec::new();
    }
    unsafe { CStr::from_ptr(item as *const libc::c_char) }
        .to_bytes()
        .to_vec()
}

fn now_secs() -> Result<u64, ()> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ())?
        .as_secs())
}

fn verify_or_enroll(
    pamh: *mut libc::c_void,
    user: &str,
    base: &Path,
    dir: &Path,
    enroll_missing: bool,
) -> Result<(), ()> {
    let tkey = throttle_key(user, &remote_host(pamh));
    if throttled(base, &tkey)? {
        let _ = show_text(pamh, "Too many failed TOTP attempts. Try again later.");
        return Err(());
    }
    let (key, enrolling) = match fs::symlink_metadata(dir.join("KEY")) {
        Ok(_) => (read_key(dir)?, false),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && enroll_missing => {
            let key = generate_secret()?;
            show_text(pamh, &enrollment_qr(user, &key)?)?;
            (key, true)
        }
        Err(_) => return Err(()),
    };
    let code = prompt_otp(pamh)?;

    // No lock is held while the user types; everything below is short file I/O.
    let _lock = lock_user_dir(dir)?;
    // Re-check under the user lock so parallel logins cannot each spend a guess.
    if throttled(base, &tkey)? {
        return Err(());
    }
    let result = commit_code(dir, &key, &code, enrolling);
    if matches!(result, Err(Failure::Other)) {
        return Err(());
    }
    let (f, mut entries) = open_throttle(base)?;
    let changed = match result {
        Ok(()) => throttle_clear(&mut entries, &tkey),
        Err(_) => Some(throttle_fail(&mut entries, &tkey, now_secs()?)),
    };
    if let Some(idx) = changed {
        store_throttle(&f, &entries, idx)?;
    }
    result.map_err(|_| ())
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |d, (x, y)| d | (x ^ y)) == 0
}

#[no_mangle]
pub unsafe extern "C" fn pam_sm_authenticate(
    pamh: *mut libc::c_void,
    _flags: libc::c_int,
    argc: libc::c_int,
    argv: *const *const libc::c_char,
) -> libc::c_int {
    let result = std::panic::catch_unwind(|| {
        let (required, group, base, enroll_missing, publickey_exempted) =
            parse_args(argc, argv).map_err(|_| PAM_SERVICE_ERR)?;
        if !required {
            return Ok(PAM_SUCCESS);
        }
        let mut user_ptr: *const libc::c_char = ptr::null();
        if pam_get_user(pamh, &mut user_ptr, ptr::null()) != PAM_SUCCESS || user_ptr.is_null() {
            return Err(PAM_AUTH_ERR);
        }
        let user = CStr::from_ptr(user_ptr)
            .to_str()
            .map_err(|_| PAM_AUTH_ERR)?;
        if publickey_exempted && ssh_publickey_was_used(pamh) {
            return Ok(PAM_SUCCESS);
        }
        if let Some(g) = group.as_deref() {
            if group_contains(user, g) {
                return Ok(PAM_SUCCESS);
            }
        }
        // Self-enrollment creates the user directory, but only for real
        // accounts so mistyped or made-up names cannot litter the store.
        let create = enroll_missing && account_exists(user);
        let dir = safe_user_dir(&base, user, create).map_err(|_| PAM_AUTH_ERR)?;
        verify_or_enroll(pamh, user, &base, &dir, enroll_missing).map_err(|_| PAM_AUTH_ERR)?;
        Ok(PAM_SUCCESS)
    });
    match result {
        Ok(Ok(status)) => status,
        Ok(Err(status)) => status,
        Err(_) => PAM_SERVICE_ERR,
    }
}

#[no_mangle]
pub unsafe extern "C" fn pam_sm_setcred(
    _pamh: *mut libc::c_void,
    _flags: libc::c_int,
    _argc: libc::c_int,
    _argv: *const *const libc::c_char,
) -> libc::c_int {
    PAM_SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc_4226_hotp_vectors_and_totp_step() {
        let key = b"12345678901234567890";
        assert_eq!(totp_at(key, 1), "287082");
        assert_eq!(totp_at(key, 0), "755224");
    }

    #[test]
    fn base32_decodes_known_secret() {
        assert_eq!(
            decode_base32("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ").unwrap(),
            b"12345678901234567890"
        );
        assert!(decode_base32("bad!").is_err());
        assert_eq!(
            encode_base32(b"12345678901234567890"),
            "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
        );
    }

    #[test]
    fn otp_comparison_is_exact() {
        assert!(constant_time_eq(b"123456", b"123456"));
        assert!(!constant_time_eq(b"123456", b"123457"));
    }

    #[test]
    fn enrollment_qr_contains_manual_key_instructions() {
        let text = enrollment_qr("alice", b"12345678901234567890").unwrap();
        assert!(text.contains("Scan this QR code"));
        assert!(text.contains("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"));
        assert!(text.contains('█') || text.contains('▀') || text.contains('▄'));
    }

    #[test]
    fn throttle_penalty_is_exponential_and_capped() {
        assert_eq!(throttle_penalty(0), 0);
        assert_eq!(throttle_penalty(2), 0);
        assert_eq!(throttle_penalty(3), 5);
        assert_eq!(throttle_penalty(4), 10);
        assert_eq!(throttle_penalty(6), 40);
        assert_eq!(throttle_penalty(13), 3600);
        assert_eq!(throttle_penalty(u32::MAX), 3600);
    }

    #[test]
    fn throttle_tracks_failures_per_user_and_host() {
        let alice = throttle_key("alice", b"10.0.0.1");
        let other = throttle_key("alice", b"10.0.0.2");
        let mut entries = Vec::new();
        throttle_fail(&mut entries, &alice, 1000);
        throttle_fail(&mut entries, &alice, 1001);
        assert!(!throttle_blocked(&entries, &alice, 1001));
        let idx = throttle_fail(&mut entries, &alice, 1002);
        assert_eq!(entries[idx].total, 3);
        assert_eq!(entries[idx].consecutive, 3);
        assert_eq!(entries[idx].times, [1002, 1001, 1000]);
        assert!(throttle_blocked(&entries, &alice, 1006));
        assert!(!throttle_blocked(&entries, &alice, 1007));
        assert!(!throttle_blocked(&entries, &other, 1003));

        assert_eq!(throttle_clear(&mut entries, &alice), Some(idx));
        assert_eq!(entries[idx].consecutive, 0);
        assert_eq!(entries[idx].total, 3);
        assert_eq!(throttle_clear(&mut entries, &alice), None);

        throttle_fail(&mut entries, &alice, 2000);
        throttle_fail(&mut entries, &alice, 2000 + THROTTLE_RESET_SECS + 1);
        assert_eq!(entries[idx].consecutive, 1);
        assert_eq!(entries[idx].total, 5);
    }

    #[test]
    fn throttle_evicts_least_recent_failure_when_full() {
        let mut entries = Vec::new();
        for i in 0..THROTTLE_SLOTS {
            let key = throttle_key("u", i.to_string().as_bytes());
            throttle_fail(&mut entries, &key, 1000 + i as u64);
        }
        let newcomer = throttle_key("u", b"new");
        let idx = throttle_fail(&mut entries, &newcomer, 9000);
        assert_eq!(entries.len(), THROTTLE_SLOTS);
        assert_eq!(idx, 0);
        assert_eq!(entries[0].key, newcomer);
        assert_eq!(entries[0].consecutive, 1);
    }

    #[test]
    fn throttle_record_round_trips() {
        let entry = ThrottleEntry {
            key: throttle_key("alice", b"host"),
            total: 7,
            consecutive: 4,
            times: [30, 20, 10],
        };
        assert_eq!(ThrottleEntry::decode(&entry.encode()), entry);
    }

    const STRESS_RSS_SLACK: u64 = 8 << 20;

    fn peak_rss_bytes() -> u64 {
        let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
        unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut ru) };
        let peak = ru.ru_maxrss as u64;
        if cfg!(target_os = "macos") {
            peak
        } else {
            peak * 1024
        }
    }

    fn open_fds() -> usize {
        fs::read_dir("/dev/fd").map(|d| d.count()).unwrap_or(0)
    }

    // Runs a warm-up, then checks that the real run neither raises peak RSS
    // beyond the slack nor leaves file descriptors open.
    fn steady(name: &str, iters: u64, mut op: impl FnMut(u64)) {
        for i in 0..(iters / 10).max(1) {
            op(i);
        }
        let (rss, fds) = (peak_rss_bytes(), open_fds());
        for i in 0..iters {
            op(i);
        }
        let grown = peak_rss_bytes().saturating_sub(rss);
        println!(
            "{name}: {iters} ops, peak RSS +{} KiB, fds {fds} -> {}",
            grown / 1024,
            open_fds()
        );
        assert!(grown < STRESS_RSS_SLACK, "{name}: peak RSS grew {grown} bytes");
        assert_eq!(open_fds(), fds, "{name}: file descriptors leaked");
    }

    unsafe extern "C" fn mock_conv(
        n: libc::c_int,
        msg: *mut *const PamMessage,
        resp: *mut *mut PamResponse,
        _data: *mut libc::c_void,
    ) -> libc::c_int {
        let r = libc::calloc(n as usize, std::mem::size_of::<PamResponse>()) as *mut PamResponse;
        let text: &[u8] = if (**msg).msg_style == PAM_PROMPT_ECHO_OFF {
            b"123456\0"
        } else {
            b"ok\0"
        };
        (*r).resp = libc::strdup(text.as_ptr() as *const libc::c_char);
        *resp = r;
        PAM_SUCCESS
    }

    // cargo test --release -- --ignored --nocapture
    #[test]
    #[ignore]
    fn stress_no_memory_or_fd_growth() {
        let secret = b"12345678901234567890";

        steady("totp/base32", 2_000_000, |i| {
            let code = totp_at(secret, i);
            let _ = matching_step(secret, &code, i * 30, 0);
            let encoded = encode_base32(secret);
            let _ = decode_base32(&encoded);
        });

        steady("enrollment qr", 50_000, |_| {
            let _ = enrollment_qr("alice", secret);
        });

        let mut table = Vec::new();
        steady("throttle table", 1_000_000, |i| {
            // More distinct keys than slots, so the table stays full and evicts.
            let key = throttle_key("alice", (i % 6000).to_string().as_bytes());
            let idx = throttle_fail(&mut table, &key, i);
            let _ = throttle_blocked(&table, &key, i);
            let _ = ThrottleEntry::decode(&table[idx].encode());
            if i % 3 == 0 {
                let _ = throttle_clear(&mut table, &key);
            }
        });
        assert_eq!(table.len(), THROTTLE_SLOTS);

        let conv = PamConv {
            conv: Some(mock_conv),
            appdata_ptr: ptr::null_mut(),
        };
        steady("pam conversation", 2_000_000, |_| {
            assert_eq!(prompt_with(&conv).unwrap(), "123456");
            show_with(&conv, "hello").unwrap();
        });

        let base = std::env::temp_dir().join(format!("pam_totp_stress_{}", std::process::id()));
        let dir = base.join("alice");
        let _ = fs::remove_dir_all(&base);
        fs::create_dir(&base).unwrap();
        fs::set_permissions(&base, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
        assert!(safe_user_dir(&base, "alice", false).is_err());
        assert!(safe_user_dir(&base, "../alice", true).is_err());
        assert_eq!(safe_user_dir(&base, "alice", true).unwrap(), dir);
        assert_eq!(fs::metadata(&dir).unwrap().mode() & 0o777, 0o700);
        assert_eq!(safe_user_dir(&base, "alice", false).unwrap(), dir);

        steady("throttle file", 100_000, |i| {
            let key = throttle_key("alice", (i % 6000).to_string().as_bytes());
            let (f, mut entries) = open_throttle(&base).unwrap();
            let idx = throttle_fail(&mut entries, &key, i);
            store_throttle(&f, &entries, idx).unwrap();
        });
        let (_f, entries) = open_throttle(&base).unwrap();
        assert_eq!(entries.len(), THROTTLE_SLOTS);

        write_atomic(&dir, "KEY", b"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ\n").unwrap();
        steady("user dir files", 2_000, |i| {
            let _lock = lock_user_dir(&dir).unwrap();
            write_atomic(&dir, "LAST_STEP", format!("{i}\n").as_bytes()).unwrap();
            assert_eq!(read_last_step(&dir).unwrap(), i);
            let key = read_key(&dir).unwrap();
            let _ = commit_code(&dir, &key, "000000", false);
        });
        fs::remove_dir_all(&base).unwrap();

        steady("group lookup", 20_000, |_| {
            let _ = group_contains("root", "wheel");
            let _ = group_contains("no-such-user", "no-such-group");
        });

        // Negative control: a deliberate 16-byte leak per op must be visible,
        // otherwise the checks above prove nothing.
        let before = peak_rss_bytes();
        for _ in 0..2_000_000 {
            std::mem::forget(std::hint::black_box(vec![1u8; 16]));
        }
        assert!(peak_rss_bytes() - before >= STRESS_RSS_SLACK);
    }

    #[test]
    fn ssh_auth_info_recognizes_publickey_lines() {
        assert!(auth_info_has_publickey(b"publickey ssh-ed25519 AAAA\n"));
        assert!(auth_info_has_publickey(
            b"keyboard-interactive/pam\npublickey key-data\n"
        ));
        assert!(!auth_info_has_publickey(
            b"password\nkeyboard-interactive/pam\n"
        ));
    }
}
