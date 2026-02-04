use libc::{free, malloc};
use std::ptr;

const WORKER_API_VERSION: u32 = 1;

#[repr(u32)]
#[allow(dead_code)]
enum Status {
    Ok = 0,
    InvalidInput = 1,
    PointAtInfinity = 2,
    ZeroScalar = 3,
    InvalidPubkey = 4,
    TweakOutOfRange = 5,
    Internal = 255,
}

fn validate_case_header(input: *const u8, input_len: usize) -> bool {
    if input.is_null() {
        return false;
    }
    if input_len < 17 {
        return false;
    }

    let slice = unsafe { std::slice::from_raw_parts(input, input_len) };
    slice[0] == 1
}

#[no_mangle]
pub extern "C" fn sp_differ_worker_api_version() -> u32 {
    WORKER_API_VERSION
}

#[no_mangle]
pub extern "C" fn sp_differ_worker_run(
    input: *const u8,
    input_len: usize,
    output: *mut *mut u8,
    output_len: *mut usize,
) -> i32 {
    if output.is_null() || output_len.is_null() {
        return -1;
    }

    let status = if validate_case_header(input, input_len) {
        Status::Ok
    } else {
        Status::InvalidInput
    };

    let payload = [1u8, status as u8, 0, 0];
    let size = payload.len();

    unsafe {
        let ptr = malloc(size) as *mut u8;
        if ptr.is_null() {
            return -1;
        }
        ptr::copy_nonoverlapping(payload.as_ptr(), ptr, size);
        *output = ptr;
        *output_len = size;
    }

    0
}

#[no_mangle]
pub extern "C" fn sp_differ_worker_free(output: *mut u8) {
    if !output.is_null() {
        unsafe { free(output as *mut libc::c_void) };
    }
}
