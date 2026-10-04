use pam_totp::{decode_base32, totp_at};
use std::env;
use std::fs;
use std::io::{self, Read};
use std::time::{SystemTime, UNIX_EPOCH};

fn usage() -> &'static str {
    "Usage: otputil (--key BASE32 | --key-file PATH | --key-stdin) [--time UNIX_SECONDS]\n\nPrints the TOTP for the current 30-second step and the following two steps.\n--time selects a fixed Unix timestamp for repeatable tests."
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut key_arg: Option<String> = None;
    let mut key_file: Option<String> = None;
    let mut key_stdin = false;
    let mut timestamp: Option<u64> = None;
    let mut args = env::args().skip(1);

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--key" => key_arg = Some(args.next().ok_or("--key needs a Base32 value")?),
            "--key-file" => key_file = Some(args.next().ok_or("--key-file needs a path")?),
            "--key-stdin" => key_stdin = true,
            "--time" => {
                timestamp = Some(args.next().ok_or("--time needs Unix seconds")?.parse()?);
            }
            "-h" | "--help" => {
                println!("{}", usage());
                return Ok(());
            }
            _ => return Err(format!("unknown argument: {arg}\n{}", usage()).into()),
        }
    }

    let selected = key_arg.is_some() as usize + key_file.is_some() as usize + key_stdin as usize;
    if selected != 1 {
        return Err(format!("choose exactly one key source\n{}", usage()).into());
    }
    let encoded = if let Some(value) = key_arg {
        value
    } else if let Some(path) = key_file {
        fs::read_to_string(path)?
    } else {
        let mut value = String::new();
        io::stdin().read_to_string(&mut value)?;
        value
    };
    let key = decode_base32(encoded.trim()).map_err(|_| "invalid Base32 TOTP key")?;
    let now = match timestamp {
        Some(value) => value,
        None => SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
    };
    let current_step = now / 30;

    println!("current: {}", totp_at(&key, current_step));
    println!("next:    {}", totp_at(&key, current_step + 1));
    println!("next:    {}", totp_at(&key, current_step + 2));
    Ok(())
}
