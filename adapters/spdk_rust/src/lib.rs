#[allow(dead_code)]
#[path = "main.rs"]
mod executable;

use libc::{c_int, c_uchar, c_void, malloc, free, size_t};
use std::ptr;
use std::slice;
use std::str;

#[no_mangle]
pub extern "C" fn sp_differ_semantic_worker_api_version() -> u32 {
    executable::SEMANTIC_WORKER_API_VERSION
}

#[no_mangle]
pub unsafe extern "C" fn sp_differ_semantic_worker_run(
    input: *const c_uchar,
    input_len: size_t,
    output: *mut *mut c_uchar,
    output_len: *mut size_t,
) -> c_int {
    if output.is_null() || output_len.is_null() {
        return 1;
    }

    *output = ptr::null_mut();
    *output_len = 0;

    if input.is_null() && input_len != 0 {
        return 1;
    }

    let input_bytes = if input_len == 0 {
        &[]
    } else {
        slice::from_raw_parts(input, input_len)
    };
    let input_str = match str::from_utf8(input_bytes) {
        Ok(value) => value,
        Err(_) => return 1,
    };
    let response = match executable::run_request_json(input_str) {
        Ok(value) => value,
        Err(_) => return 1,
    };
    let response_bytes = response.into_bytes();
    let response_len = response_bytes.len();
    let allocated = malloc(response_len.max(1)) as *mut c_uchar;
    if allocated.is_null() {
        return 1;
    }
    ptr::copy_nonoverlapping(response_bytes.as_ptr(), allocated, response_len);
    *output = allocated;
    *output_len = response_len;
    0
}

#[no_mangle]
pub unsafe extern "C" fn sp_differ_semantic_worker_free(output: *mut c_uchar) {
    if !output.is_null() {
        free(output as *mut c_void);
    }
}
