use rust_ffi::ffi_struct::struct_transfer::*;
use rust_ffi::ffi_alias::alias_set::*;

#[no_mangle]
pub extern "C" fn archive_read_support_format_rar5(mut _a:
                                        *mut archive)
                                        -> libc::c_int {
    return 0 as libc::c_int;
}
