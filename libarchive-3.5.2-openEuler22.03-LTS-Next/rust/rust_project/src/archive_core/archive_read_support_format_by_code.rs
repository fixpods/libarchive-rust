use rust_ffi::ffi_struct::struct_transfer::* ;
use rust_ffi::ffi_alias::alias_set::*;

#[no_mangle]
pub extern "C" fn archive_read_support_format_by_code(
    mut a: *mut archive,
    mut format_code: libc::c_int,
) -> libc::c_int {
    return 0 as libc::c_int;
}
