#![allow(non_camel_case_types)]
include!("pam_appl.rs");
use std::ffi::{CString, CStr};
use std::os::raw::{c_int, c_char};
use std::ptr;
use std::process::Command;
use regex::Regex;
use std::fs;
use std::os::linux::fs::MetadataExt;
use std::fs::File;
use std::io::{BufRead, BufReader};

#[no_mangle]
pub extern fn pam_sm_authenticate(pamh: *mut pam_handle_t, _flags: c_int, _argc: c_int, _argv: *const *const c_char) -> u32 {
    let mut username : *const c_char = ptr::null();
    let prompt = match CString::new("Username:") {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Unable to convert prompt to C-type string: {}", e);
            return PAM_AUTH_ERR;
        },
    };
    let get_user_result = unsafe { pam_get_user(pamh, &mut username, prompt.as_ptr()) };
    if get_user_result != (PAM_SUCCESS as i32) || username == ptr::null() {
        return PAM_AUTH_ERR;
    }
    let username_cstr = unsafe { CStr::from_ptr(username) };
    let username_str = match username_cstr.to_str() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Unable to convert username to Rust-type string: {}", e);
            return PAM_AUTH_ERR;
        },
    };
    let bdaddr = match get_device_id_from_users_file(username_str, "/etc/blox_users.conf") {
        Some(a) => a,
        None => {
            return PAM_AUTH_ERR;
        },
    };
    println!("Authenticating {:?} using device ID \"{}\"", username_str, bdaddr);
    let check_result = read_bluetooth_signal_strength_and_decide(&bdaddr, -5);
    if check_result {
        return PAM_SUCCESS; 
    }
    return PAM_AUTH_ERR;
}

fn get_device_id_from_users_file(username: &str, filename: &str) -> Option<String> {
    let meta = match fs::metadata(filename) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("Unable to fetch information for file {}: {}", filename, e);
            return None;
        },
    };
    if meta.st_uid() != 0 || meta.st_gid() != 0 {
        eprintln!("The file {} is not owned by root:root", filename);
        return None;
    }
    if (meta.st_mode() & 3967) != 256 {
        eprintln!("The file {} must be readable only by root", filename);
        return None;
    }
    let uname_re = match Regex::new("^\"?([a-zA-Z0-9].*?)\"?$") {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Unable to compile username regular expression: {}", e);
            return None;
        },
    };
    let mat = match uname_re.captures(username) {
        Some(m) => m,
        None => {
            eprintln!("Invalid username format supplied: {}", username);
            return None;
        },
    };
    let uname = match mat.get(1) {
        Some(u) => u.as_str(),
        None => {
            eprintln!("Empty username supplied: {}", username);
            return None;
        },
    };
    let f = match File::open(filename) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Unable to open file {}: {}", filename, e);
            return None;
        },
    };
    let reader = BufReader::new(f);
    let bdre = match Regex::new(r"^(?:[0-9A-F]{2})(?::[0-9A-F]{2}){5}$") {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Unable to create BT address regular expression: {}", e);
            return None;
        },
    };
    let mut user_found = false;
    for line in reader.lines() {
        let ln_text = match line {
            Ok(l) => l,
            Err(_e) => continue,
        };
        let items : Vec<&str> = ln_text.split('\t').collect();
        if items.len() < 2 {
            continue;
        }
        if items[0] == uname {
            user_found = true;
            if !bdre.is_match(items[1]) {
                eprintln!("User {} found, but the supplied BT address ({}) is not valid, skipping ...", items[0], items[1]);
                continue;
            }
            return Some(String::from(items[1]));
        }
    }
    if !user_found {
        eprintln!("User {} not found in {}", uname, filename);
    }
    return None;
}

fn read_bluetooth_signal_strength_and_decide(bdaddr: &str, threshold: i32) -> bool {
    let cmd = format!("hcitool rssi {}", bdaddr);
    let error_text = format!("Unable to read RSSI value for {}", bdaddr);
    let rssi_output = match Command::new("sh").arg("-c").arg(cmd).output() {
        Ok(o) => o.stdout,
        Err(e) => {
            eprintln!("{}: {}", &error_text, e);
            return false;
        },
    };
    let rssi_output_str = match std::str::from_utf8(&rssi_output) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Unable to convert output command to UTF-8: {}", e);
            return false;
        },
    };
    let re = match Regex::new(r"RSSI return value: (-?\d+)") {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Unable to create regular expression for parsing command output: {}", e);
            return false;
        },
    };
    let mut val_found = false;
    for mat in re.captures_iter(rssi_output_str) {
        let val = match mat.get(1) {
            Some(v) => v,
            None => continue,
        };
        let val_i32 = match val.as_str().parse::<i32>() {
            Ok(v) => v,
            Err(_e) => continue,
        };
        if val_i32 >= threshold {
            println!("Success: signal strength {} is above or equal to threshold {}", val_i32, threshold);
            return true;
        }
        val_found = true;
    }
    if val_found {
        println!("Device not close enough!");
    } else {
        println!("Device not connected!");
    }
    return false;
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
