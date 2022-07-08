use rust_ffi::ffi_alias::alias_set::*;
use rust_ffi::ffi_struct::struct_transfer::* ;

#[no_mangle]
pub extern "C" fn archive_read_support_format_cpio(mut _a: *mut archive) -> libc::c_int {
    return 0 as libc::c_int;
}
