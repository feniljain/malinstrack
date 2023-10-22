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
// - [] Identify different functions which could be added to tracking
//      - [] Add hooks for all of them

// Our own custom open function
#[no_mangle]
pub unsafe extern "C" fn open(path: *const c_char, oflag: c_int) -> c_int {
    // IMPORTANT RULE: Never panic in here

    let path_c_str = CStr::from_ptr(path);
    // println!("used open() function on filename: {:?}", path_c_str);

    if valid_path_to_insert(path_c_str) {
        add_path_to_db(path_c_str);
    }

    call_og_open_fn(path, oflag)
}

unsafe fn add_path_to_db(path_c_str: &CStr) {
    if let Ok(db_path_str) = std::env::var("MALINSTRACK_DB_PATH") {
        // println!("db_path: {db_path_str}");
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
                        // println!("path_insert_cmd: {path_insert_cmd}");
                        if let Err(_) = connection.execute(path_insert_cmd) {
                            // println!("could not run insert into table cmd");
                        }
                    }
                    None => {
                        println!("could not get file name from DB path");
                    }
                }
            }
            Err(_) => {
                println!("could not open DB");
            }
        }
    } else {
        println!("could not get db path env var");
    }
}

unsafe fn call_og_open_fn(path: *const c_char, oflag: c_int) -> i32 {
    let open_c_string = CString::new("open").expect("could not create C string for open");
    let original_open_fn_address = dlsym(RTLD_NEXT, open_c_string.as_ptr());
    let original_open_fn: OpenFn = unsafe { transmute(original_open_fn_address) };

    original_open_fn(path, oflag)
}

unsafe fn valid_path_to_insert(path_c_str: &CStr) -> bool {
    match path_c_str.to_str() {
        Ok(path_str) => {
            return !(path_str.starts_with("/proc/")
                || path_str.contains("/usr/bin/ldd")
                || path_str.contains("/dev/tty"));
        }
        Err(_) => {
            println!("could not convert path to path_c_str");
            return false;
        }
    }
}
