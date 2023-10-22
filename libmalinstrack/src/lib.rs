use std::{
    ffi::{CStr, CString},
    mem::transmute,
    path::Path,
};

use libc::{self, c_char, c_int, dlsym, RTLD_NEXT};

// pub unsafe fn openat(dirfd: ::c_int, pathname: *const ::c_char, flags: ::c_int, ...) -> ::c_int
// pub unsafe fn open(path: *const c_char, oflag: ::c_int, ...) -> ::c_int

// Function pointer to open() libc
type OpenFn = fn(path: *const c_char, oflag: c_int) -> c_int;
// Function pointer to openat() libc
// type OpenAtFn = extern "C" fn(dirfd: c_int, pathname: *const c_char, flags: c_int, ...) -> c_int;

// TODO:
// - [] Do not return on failures in different places, instead always run open. Cause otherwise
// - [] By default do not push system files in filesystems like /proc
// host program just blocks in place :(
// - [] Identify different functions which could be added to tracking
// - [] Add hooks for all of them
// - [] Remove printlns from everywhere

// Our own custom openat function
#[no_mangle]
pub unsafe extern "C" fn open(path: *const c_char, oflag: c_int) -> c_int {
    // IMPORTANT RULE: Never panic in here

    let path_c_str = CStr::from_ptr(path);
    println!("used open() function on filename: {:?}", path_c_str);

    if let Ok(db_path_str) = std::env::var("MALINSTRACK_DB_PATH") {
        println!("db_path: {db_path_str}");
        match sqlite::open(db_path_str.clone()) {
            Ok(connection) => {
                let db_path = Path::new(&db_path_str);
                match db_path.file_stem() {
                    Some(db_file_name) => {
                        let db_name = db_file_name
                            .to_str()
                            .expect("could not convert os str to str")
                            .split(".")
                            .next()
                            .expect("could not fetch db name");

                        let path_insert_cmd =
                            format!("INSERT INTO {db_name} VALUES({path_c_str:?})");
                        println!("path_insert_cmd: {path_insert_cmd}");
                        if let Err(_) = connection.execute(path_insert_cmd) {
                            println!("could not run insert into table cmd");
                            // we do not want to return in this case, as it may be
                            // just a case of duplicate entry
                        }
                    }
                    None => {
                        println!("could not get file name from DB path");
                        return 0;
                    }
                }
            }
            Err(_) => {
                println!("could not open DB");
                return 0;
            }
        }
    } else {
        println!("could not get db path env var");
        return 0;
    }

    match CString::new("open") {
        Ok(open_c_string) => {
            let original_open_fn_address = dlsym(RTLD_NEXT, open_c_string.as_ptr());
            let original_open_fn: OpenFn = unsafe { transmute(original_open_fn_address) };

            original_open_fn(path, oflag)
        }
        Err(_) => {
            println!("could not create C string");
            return 0;
        }
    }
}
