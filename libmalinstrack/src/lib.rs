use std::{
    ffi::{CStr, CString},
    mem::transmute,
};

use libc::{self, c_char, c_int, dlsym, RTLD_NEXT};

// pub unsafe fn openat(dirfd: ::c_int, pathname: *const ::c_char, flags: ::c_int, ...) -> ::c_int
// pub unsafe fn open(path: *const c_char, oflag: ::c_int, ...) -> ::c_int

// Function pointer to open() libc
type OpenFn = fn(path: *const c_char, oflag: c_int) -> c_int;
// Function pointer to openat() libc
// type OpenAtFn = extern "C" fn(dirfd: c_int, pathname: *const c_char, flags: c_int, ...) -> c_int;

// Our own custom openat function
#[no_mangle]
pub unsafe extern "C" fn open(path: *const c_char, oflag: c_int) -> c_int {
    let path_c_str = CStr::from_ptr(path);
    println!("used open() function on filename: {:?}", path_c_str);

    let open_c_string = CString::new("open").expect("could not create C string");

    let original_open_fn_address = dlsym(RTLD_NEXT, open_c_string.as_ptr());
    let original_open_fn: OpenFn = unsafe { transmute(original_open_fn_address) };

    original_open_fn(path, oflag)
}
