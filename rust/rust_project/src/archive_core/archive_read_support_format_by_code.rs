use archive_core::{
    archive_read_support_format_7zip::*, archive_read_support_format_ar::*,
    archive_read_support_format_cab::*, archive_read_support_format_cpio::*,
    archive_read_support_format_empty::*, archive_read_support_format_iso9660::*,
    archive_read_support_format_lha::*, archive_read_support_format_mtree::*,
    archive_read_support_format_rar::*, archive_read_support_format_rar5::*,
    archive_read_support_format_raw::*, archive_read_support_format_tar::*,
    archive_read_support_format_warc::*, archive_read_support_format_xar::*,
    archive_read_support_format_zip::*,
};
use rust_ffi::archive_set_error_safe;
use rust_ffi::ffi_alias::alias_set::*;
use rust_ffi::ffi_defined_param::defined_param_get::*;
use rust_ffi::ffi_method::method_call::*;
use rust_ffi::ffi_struct::struct_transfer::*;

#[no_mangle]
pub extern "C" fn archive_read_support_format_by_code(
    mut a: *mut archive,
    mut format_code: libc::c_int,
) -> libc::c_int {
    let mut magic_test: libc::c_int = __archive_check_magic_safe(
        a,
        0xdeb0c5 as libc::c_uint,
        1 as libc::c_uint,
        b"archive_read_support_format_by_code\x00" as *const u8 as *const libc::c_char,
    );
    if magic_test == -(30 as libc::c_int) {
        return -(30 as libc::c_int);
    }
    match format_code & 0xff0000 as libc::c_int {
        917504 => return archive_read_support_format_7zip(a),
        458752 => return archive_read_support_format_ar(a),
        786432 => return archive_read_support_format_cab(a),
        65536 => return archive_read_support_format_cpio(a),
        393216 => return archive_read_support_format_empty(a),
        262144 => return archive_read_support_format_iso9660(a),
        720896 => return archive_read_support_format_lha(a),
        524288 => return archive_read_support_format_mtree(a),
        851968 => return archive_read_support_format_rar(a),
        1048576 => return archive_read_support_format_rar5(a),
        589824 => return archive_read_support_format_raw(a),
        196608 => return archive_read_support_format_tar(a),
        983040 => return archive_read_support_format_warc(a),
        655360 => return archive_read_support_format_xar(a),
        327680 => return archive_read_support_format_zip(a),
        _ => {}
    }
    archive_set_error_safe!(
        a,
        ARCHIVE_BY_CODE_DEFINED_PARAM.archive_errno_programmer,
        b"Invalid format code specified\x00" as *const u8 as *const libc::c_char
    );
    return ARCHIVE_BY_CODE_DEFINED_PARAM.archive_fatal;
}
